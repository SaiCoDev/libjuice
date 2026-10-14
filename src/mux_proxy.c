/* SPDX-License-Identifier: MPL-2.0 */
#include "mux_proxy.h"
#include "juice.h"
#include "log.h"
#include "socket.h"
#include "stun.h"
#include "thread.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RANGES 4096
#define FLOW_BUCKET_BITS 14
#define FLOW_BUCKETS (1 << FLOW_BUCKET_BITS)
#define MAX_FLOWS FLOW_BUCKETS // at most one flow per bucket on average
#define FIBONACCI 0x9E3779B97F4A7C15ull // 2^64 divided by the golden ratio
#define FLOW_TIMEOUT 120000 // ms, well past ICE consent checks
#define HEADER_ABSENT -1
#define HEADER_INVALID -2

static const char signature[12] = {'\r', '\n', '\r', '\n', '\0', '\r',
                                   '\n', 'Q',  'U',  'I',  'T',  '\n'};

enum { RELAY, CLIENT };

typedef struct proxy_range {
	int family;
	unsigned char address[16];
	int prefix;
} proxy_range_t;

// One client behind a relay, which the relay reaches from its own source port. Indexed by both.
typedef struct proxy_flow {
	addr_record_t addr[2];
	struct proxy_flow *next[2];
	struct proxy_flow *older, *newer;
	timestamp_t last_seen;
} proxy_flow_t;

struct mux_proxy {
	mutex_t *lock;
	proxy_range_t *ranges;
	size_t range_count;
	proxy_flow_t *buckets[2][FLOW_BUCKETS];
	proxy_flow_t *oldest, *newest;
	size_t flow_count;
};

static int parse_range(const char *entry, proxy_range_t *range) {
	char host[ADDR_MAX_NUMERICHOST_LEN];
	const char *slash = strchr(entry, '/');
	size_t length = slash ? (size_t)(slash - entry) : strlen(entry);
	if (length == 0 || length >= sizeof(host))
		return -1;
	memcpy(host, entry, length);
	host[length] = '\0';

	if (inet_pton(AF_INET, host, range->address) == 1)
		range->family = AF_INET;
	else if (inet_pton(AF_INET6, host, range->address) == 1)
		range->family = AF_INET6;
	else
		return -1;

	int bits = range->family == AF_INET ? 32 : 128;
	range->prefix = bits;
	if (slash) {
		char *end;
		long prefix = strtol(slash + 1, &end, 10);
		if (end == slash + 1 || *end != '\0' || prefix < 0 || prefix > bits)
			return -1;
		range->prefix = (int)prefix;
	}
	return 0;
}

static bool range_contains(const proxy_range_t *range, const addr_record_t *record) {
	const unsigned char *address;
	const struct sockaddr *sa = (const struct sockaddr *)&record->addr;
	if (sa->sa_family != range->family)
		return false;
	if (sa->sa_family == AF_INET)
		address = (const unsigned char *)&((const struct sockaddr_in *)sa)->sin_addr;
	else
		address = (const unsigned char *)&((const struct sockaddr_in6 *)sa)->sin6_addr;

	int full = range->prefix / 8, rest = range->prefix % 8;
	if (memcmp(address, range->address, full) != 0)
		return false;
	if (rest == 0)
		return true;
	unsigned char mask = (unsigned char)(0xFF << (8 - rest));
	return (address[full] & mask) == (range->address[full] & mask);
}

static bool is_relay(const mux_proxy_t *proxy, const addr_record_t *src) {
	for (size_t i = 0; i < proxy->range_count; ++i)
		if (range_contains(proxy->ranges + i, src))
			return true;
	return false;
}

static bool is_stun_response(const char *data, size_t size) {
	return is_stun_datagram(data, size) &&
	       STUN_IS_RESPONSE(ntohs(((const struct stun_header *)data)->type) & STUN_CLASS_MASK);
}

// Returns the header length and the declared client, or HEADER_ABSENT or HEADER_INVALID
static int read_header(const char *data, size_t size, addr_record_t *client) {
	if (size < 16 || memcmp(data, signature, sizeof(signature)) != 0)
		return HEADER_ABSENT;

	const unsigned char *header = (const unsigned char *)data;
	size_t total = 16 + ((size_t)header[14] << 8 | header[15]);
	// A LOCAL command, such as a health check, declares no client
	if (total > size || header[12] != 0x21)
		return HEADER_INVALID;

	memset(client, 0, sizeof(*client));
	client->socktype = SOCK_DGRAM;
	if (header[13] == 0x12 && total >= 16 + 12) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&client->addr;
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, header + 16, 4);
		memcpy(&sin->sin_port, header + 24, 2);
		client->len = sizeof(*sin);
	} else if (header[13] == 0x22 && total >= 16 + 36) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&client->addr;
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, header + 16, 16);
		memcpy(&sin6->sin6_port, header + 48, 2);
		client->len = sizeof(*sin6);
		// As every receive path does, so a dual-stack relay's IPv4 clients stay IPv4
		addr_unmap_inet6_v4mapped((struct sockaddr *)&client->addr, &client->len);
	} else {
		return HEADER_INVALID;
	}
	return (int)total;
}

// The address and port packed into one key and mixed by a multiply. libjuice's djb2 address hash
// collides on sequential ports and addresses, which relays and clients often are.
static proxy_flow_t **bucket(mux_proxy_t *proxy, int key, const addr_record_t *addr) {
	const struct sockaddr *sa = (const struct sockaddr *)&addr->addr;
	uint64_t packed;
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
		packed = (uint64_t)sin->sin_addr.s_addr << 16 | sin->sin_port;
	} else {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
		uint64_t words[2];
		memcpy(words, &sin6->sin6_addr, sizeof(words));
		packed = (words[0] * FIBONACCI ^ words[1]) + sin6->sin6_port;
	}
	return &proxy->buckets[key][(packed * FIBONACCI) >> (64 - FLOW_BUCKET_BITS)];
}

static proxy_flow_t *find_flow(mux_proxy_t *proxy, int key, const addr_record_t *addr) {
	for (proxy_flow_t *flow = *bucket(proxy, key, addr); flow; flow = flow->next[key])
		if (addr_record_is_equal(&flow->addr[key], addr, true))
			return flow;
	return NULL;
}

static void append_age(mux_proxy_t *proxy, proxy_flow_t *flow) {
	flow->older = proxy->newest;
	flow->newer = NULL;
	if (proxy->newest)
		proxy->newest->newer = flow;
	else
		proxy->oldest = flow;
	proxy->newest = flow;
}

static void unlink_age(mux_proxy_t *proxy, proxy_flow_t *flow) {
	if (flow->older)
		flow->older->newer = flow->newer;
	else
		proxy->oldest = flow->newer;
	if (flow->newer)
		flow->newer->older = flow->older;
	else
		proxy->newest = flow->older;
}

// Sends only read the client chains, so the age list needs no lock
static void touch_flow(mux_proxy_t *proxy, proxy_flow_t *flow, timestamp_t now) {
	flow->last_seen = now;
	if (flow != proxy->newest) {
		unlink_age(proxy, flow);
		append_age(proxy, flow);
	}
}

// The caller holds the lock, unless no send can reach the flow anymore
static void remove_flow(mux_proxy_t *proxy, proxy_flow_t *flow) {
	for (int key = RELAY; key <= CLIENT; ++key) {
		proxy_flow_t **link = bucket(proxy, key, &flow->addr[key]);
		while (*link != flow)
			link = &(*link)->next[key];
		*link = flow->next[key];
	}
	unlink_age(proxy, flow);
	--proxy->flow_count;
	free(flow);
}

static bool expired(const mux_proxy_t *proxy, timestamp_t now) {
	return proxy->oldest && proxy->oldest->last_seen + FLOW_TIMEOUT < now;
}

static proxy_flow_t *new_flow(const addr_record_t *relay, const addr_record_t *client,
                              timestamp_t last_seen) {
	proxy_flow_t *flow = calloc(1, sizeof(*flow));
	if (!flow) {
		JLOG_ERROR("Memory allocation failed for proxy flow");
		return NULL;
	}
	flow->addr[RELAY] = *relay;
	flow->addr[CLIENT] = *client;
	flow->last_seen = last_seen;
	return flow;
}

// As the newest flow. The caller holds the lock, unless no send can reach the proxy yet.
static void insert_flow(mux_proxy_t *proxy, proxy_flow_t *flow) {
	for (int key = RELAY; key <= CLIENT; ++key) {
		proxy_flow_t **head = bucket(proxy, key, &flow->addr[key]);
		flow->next[key] = *head;
		*head = flow;
	}
	append_age(proxy, flow);
	++proxy->flow_count;
}

// Maps the relay to the client in place of stale, the relay's previous flow if any. A relay speaks
// for one client, and a client has one relay.
static int replace_flow(mux_proxy_t *proxy, proxy_flow_t *stale, const addr_record_t *relay,
                        const addr_record_t *client, timestamp_t now) {
	proxy_flow_t *flow = new_flow(relay, client, now);
	if (!flow)
		return -1;

	mutex_lock(proxy->lock);
	if (stale)
		remove_flow(proxy, stale);
	if ((stale = find_flow(proxy, CLIENT, client)))
		remove_flow(proxy, stale);
	if (proxy->flow_count >= MAX_FLOWS)
		remove_flow(proxy, proxy->oldest);
	insert_flow(proxy, flow);
	mutex_unlock(proxy->lock);
	return 0;
}

int mux_proxy_create(const char *const *relays, size_t count, mutex_t *lock,
                     const mux_proxy_t *previous, mux_proxy_t **proxy) {
	if (count > MAX_RANGES)
		return JUICE_ERR_INVALID;
	mux_proxy_t *created = calloc(1, sizeof(*created));
	proxy_range_t *ranges = calloc(count, sizeof(*ranges));
	if (!created || !ranges) {
		free(created);
		free(ranges);
		return JUICE_ERR_FAILED;
	}
	for (size_t i = 0; i < count; ++i) {
		if (!relays[i] || parse_range(relays[i], ranges + i) != 0) {
			JLOG_ERROR("Invalid PROXY protocol relay: %s", relays[i] ? relays[i] : "(null)");
			free(created);
			free(ranges);
			return JUICE_ERR_INVALID;
		}
	}
	created->lock = lock;
	created->ranges = ranges;
	created->range_count = count;
	// Oldest first, so the age order carries over. Sends may still read previous, never write it.
	for (const proxy_flow_t *flow = previous ? previous->oldest : NULL; flow; flow = flow->newer) {
		if (!is_relay(created, &flow->addr[RELAY]))
			continue;
		proxy_flow_t *copy = new_flow(&flow->addr[RELAY], &flow->addr[CLIENT], flow->last_seen);
		if (!copy) {
			mux_proxy_destroy(created);
			return JUICE_ERR_FAILED;
		}
		insert_flow(created, copy);
	}
	*proxy = created;
	return 0;
}

void mux_proxy_destroy(mux_proxy_t *proxy) {
	if (!proxy)
		return;
	while (proxy->oldest)
		remove_flow(proxy, proxy->oldest);
	free(proxy->ranges);
	free(proxy);
}

int mux_proxy_receive(mux_proxy_t *proxy, char **data, size_t *size, addr_record_t *src,
                      timestamp_t now) {
	if (expired(proxy, now)) {
		mutex_lock(proxy->lock);
		while (expired(proxy, now))
			remove_flow(proxy, proxy->oldest);
		mutex_unlock(proxy->lock);
	}

	addr_record_t client;
	int header = read_header(*data, *size, &client);
	if (header == HEADER_INVALID)
		return -1;
	proxy_flow_t *flow = find_flow(proxy, RELAY, src);
	if (header == HEADER_ABSENT) {
		// Some relays only prefix the first datagram of a flow
		if (flow) {
			touch_flow(proxy, flow, now);
			*src = flow->addr[CLIENT];
			return 0;
		}
		// Behind relays no peer comes straight here. A STUN response stays, as it only matches a
		// request this endpoint sent, such as one to a STUN server.
		return is_stun_response(*data, *size) ? 0 : -1;
	}

	if (flow && addr_record_is_equal(&flow->addr[CLIENT], &client, true)) {
		touch_flow(proxy, flow, now);
	} else if (!flow && !is_relay(proxy, src)) {
		// A header from anywhere else is spoofed. A flow implies a listed relay, since a new list
		// keeps only the flows of relays it lists.
		return -1;
	} else if (replace_flow(proxy, flow, src, &client, now) != 0) {
		return -1;
	}
	*data += header;
	*size -= (size_t)header;
	*src = client;
	return *size > 0 ? 0 : -1;
}

const addr_record_t *mux_proxy_route(mux_proxy_t *proxy, const addr_record_t *dst) {
	proxy_flow_t *flow = find_flow(proxy, CLIENT, dst);
	return flow ? &flow->addr[RELAY] : dst;
}

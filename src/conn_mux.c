/**
 * Copyright (c) 2022 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "conn_mux.h"
#include "agent.h"
#include "base64.h"
#include "log.h"
#include "mux_proxy.h"
#include "socket.h"
#include "stun.h"
#include "thread.h"
#include "udp.h"

#include <assert.h>
#include <string.h>

#define BUFFER_SIZE 4096
#define INITIAL_MAP_SIZE 16
#define MAX_PENDING_PACKET_SIZE 2048
#define MAX_NOTIFICATIONS_PER_TICK 64
#define ICE_CHARACTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#define MAX_ADMISSION_CONTEXT 1024
#define MAX_ADMISSION_KEYS 8
#define MAX_ADMISSION_PREFIX 16
#define MAX_ADMISSION_SECRET 64
#define ADMISSION_DIGEST_SIZE 24

typedef struct admission_key {
	char prefix[MAX_ADMISSION_PREFIX + 1];
	size_t secret_size;
	uint8_t secret[MAX_ADMISSION_SECRET];
} admission_key_t;

typedef struct admission {
	size_t context_size;
	uint8_t context[MAX_ADMISSION_CONTEXT];
	int keys_count;
	admission_key_t keys[MAX_ADMISSION_KEYS];
} admission_t;

typedef struct pending_request {
	struct pending_request *next;
	struct pending_request *previous;
	struct pending_request *hash_next;
	struct pending_request *id_next;
	struct pending_request *expiry_next, *expiry_previous;
	struct pending_request *work_next, *work_previous;
	uint64_t id;
	timestamp_t deadline;
	addr_record_t src;
	char local_ufrag[257];
	char remote_ufrag[257];
	char password[257];
	bool notified;
	bool verified;
	juice_agent_t *agent;
	size_t size;
	char data[MAX_PENDING_PACKET_SIZE];
} pending_request_t;

static mutex_t request_id_mutex = MUTEX_INITIALIZER;
static uint64_t next_request_id = 1;

typedef enum map_entry_type {
	MAP_ENTRY_TYPE_EMPTY = 0,
	MAP_ENTRY_TYPE_DELETED,
	MAP_ENTRY_TYPE_FULL
} map_entry_type_t;

typedef struct map_entry {
	map_entry_type_t type;
	juice_agent_t *agent;
	addr_record_t record;
} map_entry_t;

typedef struct registry_impl {
	int conn_mux_registries_index;
	uint16_t port;
	char bind_address[ADDR_MAX_NUMERICHOST_LEN];
	thread_t thread;
	socket_t sock;
	mutex_t send_mutex;
	int send_ds;
	map_entry_t *map;
	int map_size;
	int map_count;
	juice_cb_mux_incoming_t cb_mux_incoming;
	juice_cb_mux_pending_t cb_mux_pending;
	void *mux_pending_user_ptr;
	bool pending_required;
	bool pending_closing;
	mutex_t callback_mutex;
	unsigned int max_pending;
	unsigned int pending_timeout_ms;
	unsigned int pending_count;
	unsigned int pending_bucket_count;
	pending_request_t **pending_buckets;
	pending_request_t **pending_ids;
	pending_request_t *pending_head;
	pending_request_t *pending_tail;
	pending_request_t *expiry_head, *expiry_tail;
	pending_request_t *notify_head, *notify_tail;
	pending_request_t *ready_head, *ready_tail;
	admission_t *admission;
	uint64_t received;
	uint64_t rejected;
	uint64_t notifications;
	uint64_t duplicates;
	void *mux_incoming_user_ptr;
	// Swapped under both the registry lock and send_mutex. Sends route through it under send_mutex
	mux_proxy_t *proxy;
} registry_impl_t;

typedef struct conn_impl {
	conn_registry_t *registry;
	timestamp_t next_timestamp;
	bool finished;
} conn_impl_t;

static conn_registry_t **conn_mux_registries;
static int conn_mux_registries_size;
static int conn_mux_registries_count;

conn_registry_t *conn_mux_get_registry(udp_socket_config_t *config) {
	for (int i = 0; i < conn_mux_registries_size; i++) {
		if (!conn_mux_registries[i]) {
			continue;
		}

		conn_registry_t *registry = conn_mux_registries[i];
		registry_impl_t *impl = registry->impl;

		if (strcmp(impl->bind_address, config->bind_address ? config->bind_address : "") == 0 &&
            impl->port >= config->port_begin && (config->port_end == 0 || impl->port <= config->port_end)) {
			return registry;
		}
	}

	return NULL;
}

static int conn_mux_add_registry(conn_registry_t *registry) {
	int i = 0;
		while (i < conn_mux_registries_size && conn_mux_registries[i])
			++i;

	if (i == conn_mux_registries_size) {
		int new_size = conn_mux_registries_size * 2;

		if (new_size == 0) {
			new_size = 1;
		}

		JLOG_DEBUG("Reallocating registries array, new_size=%d", new_size);
		assert(new_size > 0);

		conn_registry_t **new_registries =
				realloc(conn_mux_registries, new_size * sizeof(conn_registry_t *));
		if (!new_registries) {
			JLOG_FATAL("Memory reallocation failed for registries array");
			return -1;
		}

		conn_mux_registries = new_registries;
		conn_mux_registries_size = new_size;
		memset(conn_mux_registries + i, 0, (new_size - i) * sizeof(conn_registry_t *));
	}

	conn_mux_registries[i] = registry;
	++conn_mux_registries_count;

	registry_impl_t *impl = registry->impl;
	impl->conn_mux_registries_index = i;

	return 0;
}

static bool is_ready(const juice_agent_t *agent) {
	if (!agent)
		return false;

	conn_impl_t *conn_impl = agent->conn_impl;
	if (!conn_impl || conn_impl->finished)
		return false;

	return true;
}

static map_entry_t *find_map_entry(registry_impl_t *impl, const addr_record_t *record,
                                   bool allow_deleted);
static int insert_map_entry(registry_impl_t *impl, const addr_record_t *record,
                            juice_agent_t *agent);
static int remove_map_entries(registry_impl_t *impl, juice_agent_t *agent);
static int grow_map(registry_impl_t *impl, int new_size);

static map_entry_t *find_map_entry(registry_impl_t *impl, const addr_record_t *record,
                                   bool allow_deleted) {
	unsigned long key = addr_record_hash(record, false) % impl->map_size;
	unsigned long pos = key;
	while (true) {
		map_entry_t *entry = impl->map + pos;
		if (entry->type == MAP_ENTRY_TYPE_EMPTY ||
		    addr_record_is_equal(&entry->record, record, true)) // compare ports
			break;

		if (entry->type == MAP_ENTRY_TYPE_DELETED && allow_deleted)
			break;

		pos = (pos + 1) % impl->map_size;
		if (pos == key)
			return NULL;
	}
	return impl->map + pos;
}

static int insert_map_entry(registry_impl_t *impl, const addr_record_t *record,
                            juice_agent_t *agent) {

	map_entry_t *entry = find_map_entry(impl, record, true); // allow deleted
	if (!entry || (entry->type != MAP_ENTRY_TYPE_FULL && impl->map_count * 2 >= impl->map_size)) {
		if (grow_map(impl, impl->map_size * 2) != 0)
			return -1;
		return insert_map_entry(impl, record, agent);
	}

	if (entry->type != MAP_ENTRY_TYPE_FULL)
		++impl->map_count;

	entry->type = MAP_ENTRY_TYPE_FULL;
	entry->agent = agent;
	entry->record = *record;

	JLOG_VERBOSE("Added map entry, count=%d", impl->map_count);
	return 0;
}

static int remove_map_entries(registry_impl_t *impl, juice_agent_t *agent) {
	int count = 0;
	for (int i = 0; i < impl->map_size; ++i) {
		map_entry_t *entry = impl->map + i;
		if (entry->type == MAP_ENTRY_TYPE_FULL && entry->agent == agent) {
			entry->type = MAP_ENTRY_TYPE_DELETED;
			entry->agent = NULL;
			++count;
		}
	}

	assert(impl->map_count >= count);
	impl->map_count -= count;

	JLOG_VERBOSE("Removed %d map entries, count=%d", count, impl->map_count);
	return 0;
}

static int grow_map(registry_impl_t *impl, int new_size) {
	if (new_size <= impl->map_size)
		return 0;

	JLOG_DEBUG("Growing map, new_size=%d", new_size);

	map_entry_t *new_map = calloc(1, new_size * sizeof(map_entry_t));
	if (!new_map) {
		JLOG_FATAL("Memory allocation failed for map");
		return -1;
	}

	map_entry_t *old_map = impl->map;
	int old_size = impl->map_size;
	impl->map = new_map;
	impl->map_size = new_size;
	impl->map_count = 0;

	for (int i = 0; i < old_size; ++i) {
		map_entry_t *old_entry = old_map + i;
		if (old_entry->type == MAP_ENTRY_TYPE_FULL)
			insert_map_entry(impl, &old_entry->record, old_entry->agent);
	}

	free(old_map);
	return 0;
}

int conn_mux_prepare(conn_registry_t *registry, struct pollfd *pfd, timestamp_t *next_timestamp);
int conn_mux_process(conn_registry_t *registry, struct pollfd *pfd);
int conn_mux_recv(conn_registry_t *registry, char *buffer, size_t size, addr_record_t *src);
void conn_mux_fail(conn_registry_t *registry);
int conn_mux_run(conn_registry_t *registry);

static thread_return_t THREAD_CALL conn_mux_thread_entry(void *arg) {
	thread_set_name_self("juice mux");
	conn_registry_t *registry = (conn_registry_t *)arg;
	conn_mux_run(registry);
	return (thread_return_t)0;
}

int conn_mux_registry_init(conn_registry_t *registry, udp_socket_config_t *config) {
    if (config->bind_address && strlen(config->bind_address) >= ADDR_MAX_NUMERICHOST_LEN) return -1;
	registry_impl_t *registry_impl = calloc(1, sizeof(registry_impl_t));
	if (!registry_impl) {
		JLOG_FATAL("Memory allocation failed for connections registry impl");
		return -1;
	}

    if (config->bind_address) strcpy(registry_impl->bind_address, config->bind_address);
	registry_impl->map = calloc(INITIAL_MAP_SIZE, sizeof(map_entry_t));
	if (!registry_impl->map) {
		JLOG_FATAL("Memory allocation failed for map");
		free(registry_impl);
		return -1;
	}
	registry_impl->map_size = INITIAL_MAP_SIZE;
	registry_impl->map_count = 0;

	registry_impl->sock = udp_create_socket(config);
	if (registry_impl->sock == INVALID_SOCKET) {
		JLOG_FATAL("UDP socket creation failed");
		free(registry_impl->map);
		free(registry_impl);
		return -1;
	}

	registry_impl->port = udp_get_port(registry_impl->sock);

	mutex_init(&registry_impl->send_mutex, 0);
	mutex_init(&registry_impl->callback_mutex, 0);
	registry->impl = registry_impl;

	if (conn_mux_add_registry(registry)) {
		JLOG_FATAL("Could not add registry");
		goto error;
	}
	JLOG_DEBUG("Starting connections thread");
	int ret = thread_init(&registry_impl->thread, conn_mux_thread_entry, registry);
	if (ret) {
		JLOG_FATAL("Thread creation failed, error=%d", ret);
		conn_mux_registries[registry_impl->conn_mux_registries_index] = NULL;
		--conn_mux_registries_count;
		goto error;
	}

	return 0;

error:
	mutex_destroy(&registry_impl->callback_mutex);
	mutex_destroy(&registry_impl->send_mutex);
	closesocket(registry_impl->sock);
	free(registry_impl->map);
	free(registry_impl);
	registry->impl = NULL;
	return -1;
}

static unsigned long pending_hash(const addr_record_t *src, const char *local,
                                  const char *remote) {
	unsigned long hash = addr_record_hash(src, true);
	for (const unsigned char *p = (const unsigned char *)local; *p; ++p)
		hash = hash * 33 + *p;
	hash = hash * 33 + ':';
	for (const unsigned char *p = (const unsigned char *)remote; *p; ++p)
		hash = hash * 33 + *p;
	return hash;
}

static void remove_expiry(registry_impl_t *impl, pending_request_t *request) {
	if (request->expiry_previous) request->expiry_previous->expiry_next = request->expiry_next;
	else impl->expiry_head = request->expiry_next;
	if (request->expiry_next) request->expiry_next->expiry_previous = request->expiry_previous;
	else impl->expiry_tail = request->expiry_previous;
	request->expiry_next = request->expiry_previous = NULL;
}

static void remove_work(pending_request_t **head, pending_request_t **tail,
                        pending_request_t *request) {
	if (request->work_previous) request->work_previous->work_next = request->work_next;
	else *head = request->work_next;
	if (request->work_next) request->work_next->work_previous = request->work_previous;
	else *tail = request->work_previous;
	request->work_next = request->work_previous = NULL;
}

static void append_work(pending_request_t **head, pending_request_t **tail,
                        pending_request_t *request) {
	request->work_previous = *tail;
	if (*tail) (*tail)->work_next = request;
	else *head = request;
	*tail = request;
}

static void remove_pending(registry_impl_t *impl, pending_request_t *request) {
	unsigned long bucket = pending_hash(&request->src, request->local_ufrag,
	                                   request->remote_ufrag) % impl->pending_bucket_count;
	pending_request_t **link = &impl->pending_buckets[bucket];
	while (*link != request) link = &(*link)->hash_next;
	*link = request->hash_next;
	link = &impl->pending_ids[request->id % impl->pending_bucket_count];
	while (*link != request) link = &(*link)->id_next;
	*link = request->id_next;
	if (request->agent) remove_work(&impl->ready_head, &impl->ready_tail, request);
	else {
		remove_expiry(impl, request);
		if (!request->notified) remove_work(&impl->notify_head, &impl->notify_tail, request);
	}
	if (request->previous) request->previous->next = request->next;
	else impl->pending_head = request->next;
	if (request->next) request->next->previous = request->previous;
	else impl->pending_tail = request->previous;
	--impl->pending_count;
	memset(request->password, 0, sizeof(request->password));
	memset(request->data, 0, request->size);
	free(request);
}

static void clear_pending(registry_impl_t *impl) {
	while (impl->pending_head) remove_pending(impl, impl->pending_head);
}

static void expire_pending(registry_impl_t *impl, timestamp_t now) {
	// All unaccepted requests use the same timeout and duplicates never extend it.
	while (impl->expiry_head && impl->expiry_head->deadline <= now) {
		++impl->rejected;
		remove_pending(impl, impl->expiry_head);
	}
}

static pending_request_t *pending_by_id(registry_impl_t *impl, uint64_t id) {
	if (!impl->pending_ids) return NULL;
	for (pending_request_t *request = impl->pending_ids[id % impl->pending_bucket_count];
	     request; request = request->id_next)
		if (request->id == id) return request;
	return NULL;
}

static void wipe(void *data, size_t size) {
	volatile uint8_t *bytes = data;
	while (size--) *bytes++ = 0;
}

static void destroy_admission(registry_impl_t *impl) {
	if (!impl->admission) return;
	wipe(impl->admission, sizeof(*impl->admission));
	free(impl->admission);
	impl->admission = NULL;
}

static bool admission_verifies(conn_registry_t *registry, char *data, size_t size,
                               const stun_message_t *msg, const char *local) {
	const admission_t *admission = ((registry_impl_t *)registry->impl)->admission;
	if (!admission) return true;
	for (int i = 0; i < registry->agents_size; ++i) {
		juice_agent_t *agent = registry->agents[i];
		if (is_ready(agent) && *agent->local.ice_pwd != '\0' &&
		    strcmp(local, agent->local.ice_ufrag) == 0 &&
		    stun_check_integrity(data, size, msg, agent->local.ice_pwd))
			return true;
	}
	size_t local_size = strlen(local);
	for (int i = 0; i < admission->keys_count; ++i) {
		const admission_key_t *key = &admission->keys[i];
		if (strncmp(local, key->prefix, strlen(key->prefix)) != 0) continue;
		uint8_t input[MAX_ADMISSION_CONTEXT + 256];
		memcpy(input, admission->context, admission->context_size);
		memcpy(input + admission->context_size, local, local_size);
		uint8_t digest[HMAC_SHA256_SIZE];
		hmac_sha256(input, admission->context_size + local_size, key->secret, key->secret_size,
		            digest);
		char password[ADMISSION_DIGEST_SIZE / 3 * 4 + 1];
		bool verified = BASE64_ENCODE(digest, ADMISSION_DIGEST_SIZE, password, sizeof(password)) > 0 &&
		                stun_check_integrity(data, size, msg, password);
		wipe(digest, sizeof(digest));
		wipe(password, sizeof(password));
		if (verified) return true;
	}
	return false;
}

static void defer_request(conn_registry_t *registry, const addr_record_t *src, const char *local,
                          const char *remote, char *data, size_t size, const stun_message_t *msg) {
	registry_impl_t *impl = registry->impl;
	if (!impl->cb_mux_pending || size > MAX_PENDING_PACKET_SIZE) {
		++impl->rejected;
		return;
	}
	unsigned long bucket = pending_hash(src, local, remote) % impl->pending_bucket_count;
	for (pending_request_t *request = impl->pending_buckets[bucket]; request;
	     request = request->hash_next) {
		if (addr_record_is_equal(src, &request->src, true) &&
		    strcmp(local, request->local_ufrag) == 0 &&
		    strcmp(remote, request->remote_ufrag) == 0) {
			++impl->duplicates;
			return; // Duplicates neither replace the first packet nor extend its deadline.
		}
	}
	if (impl->pending_count >= impl->max_pending ||
	    !admission_verifies(registry, data, size, msg, local)) {
		++impl->rejected;
		return;
	}
	pending_request_t *request = calloc(1, sizeof(*request));
	if (!request) { ++impl->rejected; return; }
	mutex_lock(&request_id_mutex);
	request->id = next_request_id;
	if (next_request_id != 0) ++next_request_id;
	mutex_unlock(&request_id_mutex);
	if (!request->id) { free(request); ++impl->rejected; return; }
	request->src = *src;
	request->deadline = current_timestamp() + impl->pending_timeout_ms;
	strcpy(request->local_ufrag, local);
	strcpy(request->remote_ufrag, remote);
	request->size = size;
	memcpy(request->data, data, size);
	request->hash_next = impl->pending_buckets[bucket];
	impl->pending_buckets[bucket] = request;
	request->previous = impl->pending_tail;
	if (impl->pending_tail) impl->pending_tail->next = request;
	else impl->pending_head = request;
	impl->pending_tail = request;
	request->id_next = impl->pending_ids[request->id % impl->pending_bucket_count];
	impl->pending_ids[request->id % impl->pending_bucket_count] = request;
	request->expiry_previous = impl->expiry_tail;
	if (impl->expiry_tail) impl->expiry_tail->expiry_next = request;
	else impl->expiry_head = request;
	impl->expiry_tail = request;
	append_work(&impl->notify_head, &impl->notify_tail, request);
	++impl->pending_count;
}

// Callback serialization is separate from the registry lock. Stop first detaches
// the callback, then waits here without holding the global registry-entry lock.
static void dispatch_pending(conn_registry_t *registry) {
	registry_impl_t *impl = registry->impl;
	for (unsigned int i = 0; i < MAX_NOTIFICATIONS_PER_TICK; ++i) {
		mutex_lock(&impl->callback_mutex);
		mutex_lock(&registry->mutex);
		expire_pending(impl, current_timestamp());
		pending_request_t *request = impl->notify_head;
		juice_cb_mux_pending_t cb = impl->cb_mux_pending;
		if (!cb || !request) {
			mutex_unlock(&registry->mutex);
			mutex_unlock(&impl->callback_mutex);
			break;
		}
		char local[257], remote[257], host[ADDR_MAX_NUMERICHOST_LEN];
		if (getnameinfo((const struct sockaddr *)&request->src.addr, request->src.len,
		                host, sizeof(host), NULL, 0, NI_NUMERICHOST) != 0) {
			++impl->rejected;
			remove_pending(impl, request);
			mutex_unlock(&registry->mutex);
			mutex_unlock(&impl->callback_mutex);
			continue;
		}
		strcpy(local, request->local_ufrag);
		strcpy(remote, request->remote_ufrag);
		juice_mux_pending_request_t info = {request->id,
			{local, remote, host, addr_get_port((const struct sockaddr *)&request->src.addr)}};
		void *user_ptr = impl->mux_pending_user_ptr;
		remove_work(&impl->notify_head, &impl->notify_tail, request);
		request->notified = true;
		++impl->notifications;
		mutex_unlock(&registry->mutex);
		cb(&info, user_ptr);
		mutex_unlock(&impl->callback_mutex);
	}
}

void conn_mux_registry_cleanup(conn_registry_t *registry) {
	registry_impl_t *registry_impl = registry->impl;

	JLOG_VERBOSE("Waiting for connections thread");
	thread_join(registry_impl->thread, NULL);
	clear_pending(registry_impl);
	destroy_admission(registry_impl);
	free(registry_impl->pending_buckets);
	free(registry_impl->pending_ids);
	mux_proxy_destroy(registry_impl->proxy);

	if (registry_impl->conn_mux_registries_index > -1) {
		int i = registry_impl->conn_mux_registries_index;
		assert(conn_mux_registries[i] == registry);
		conn_mux_registries[i] = NULL;
		registry_impl->conn_mux_registries_index = -1;
	}

	assert(conn_mux_registries_count > 0);
	--conn_mux_registries_count;
	if (conn_mux_registries_count == 0) {
		free(conn_mux_registries);
		conn_mux_registries = NULL;
		conn_mux_registries_size = 0;
	}

	mutex_destroy(&registry_impl->callback_mutex);
	mutex_destroy(&registry_impl->send_mutex);
	closesocket(registry_impl->sock);
	free(registry_impl->map);
	free(registry->impl);
	registry->impl = NULL;
}

int conn_mux_prepare(conn_registry_t *registry, struct pollfd *pfd, timestamp_t *next_timestamp) {
	timestamp_t now = current_timestamp();
	*next_timestamp = now + 60000;

	mutex_lock(&registry->mutex);
	registry_impl_t *registry_impl = registry->impl;
	pfd->fd = registry_impl->sock;
	pfd->events = POLLIN;

	for (int i = 0; i < registry->agents_size; ++i) {
		juice_agent_t *agent = registry->agents[i];
		if (is_ready(agent)) {
			conn_impl_t *conn_impl = agent->conn_impl;
			if (*next_timestamp > conn_impl->next_timestamp)
				*next_timestamp = conn_impl->next_timestamp;
		}
	}

	int count = registry->agents_count;
	registry_impl_t *impl = registry->impl;
	// Whatever keeps the registry also keeps its thread, as agents may join later
	if (impl->cb_mux_incoming || impl->cb_mux_pending || impl->pending_closing || impl->proxy)
		++count;
	if (impl->notify_head || impl->ready_head) *next_timestamp = now;
	else if (impl->expiry_head && *next_timestamp > impl->expiry_head->deadline)
		*next_timestamp = impl->expiry_head->deadline;
	mutex_unlock(&registry->mutex);
	return count;
}

static juice_agent_t *lookup_agent(conn_registry_t *registry, char *buf, size_t len,
                                   const addr_record_t *src) {
	JLOG_VERBOSE("Looking up agent from address");

	registry_impl_t *registry_impl = registry->impl;
	map_entry_t *entry = find_map_entry(registry_impl, src, false);
	juice_agent_t *agent = entry && entry->type == MAP_ENTRY_TYPE_FULL ? entry->agent : NULL;
	if (agent) {
		JLOG_DEBUG("Found agent from address");
		return agent;
	}

	if (!is_stun_datagram(buf, len)) {
		++registry_impl->rejected;
		JLOG_DEBUG("Got non-STUN message from unknown source address");
		return NULL;
	}

	JLOG_VERBOSE("Looking up agent from STUN message content");

	stun_message_t msg;
	if (stun_read(buf, len, &msg) < 0) {
		++registry_impl->rejected;
		JLOG_DEBUG("STUN message reading failed");
		return NULL;
	}

	if (msg.msg_class == STUN_CLASS_REQUEST && msg.msg_method == STUN_METHOD_BINDING &&
	    msg.has_integrity) {
		// Binding request from peer
		char username[STUN_MAX_USERNAME_LEN];
		strcpy(username, msg.credentials.username);
		char *separator = strchr(username, ':');
		if (!separator) {
			++registry_impl->rejected;
			JLOG_DEBUG("Invalid STUN username");
			return NULL;
		}
		*separator = '\0';
		const char *local_ufrag = username;
		const char *remote_ufrag = separator + 1;
		if (strlen(local_ufrag) < 4 || strlen(local_ufrag) > 256 ||
		    strlen(remote_ufrag) < 4 || strlen(remote_ufrag) > 256 ||
		    strspn(local_ufrag, ICE_CHARACTERS) != strlen(local_ufrag) ||
		    strspn(remote_ufrag, ICE_CHARACTERS) != strlen(remote_ufrag)) {
			++registry_impl->rejected;
			return NULL;
		}
		bool ufrag_matched = false;
		for (int i = 0; i < registry->agents_size; ++i) {
			agent = registry->agents[i];
			// Behind a pending listener only direct agents skip admission.
			if (is_ready(agent) && (!registry_impl->pending_required || agent->config.mux_direct) &&
			    strcmp(local_ufrag, agent->local.ice_ufrag) == 0) {
				JLOG_DEBUG("Found agent from ICE ufrag");
				ufrag_matched = true;
				// A username match alone must never authorize the source address. Generated ufrags
				// are short, so another agent may share this one: only the password tells them apart.
				if (agent_verify_stun_binding(agent, buf, len, &msg) != 0)
					continue;
				if (insert_map_entry(registry_impl, src, agent) != 0) return NULL;
				return agent;
			}
		}
		if (ufrag_matched) {
			++registry_impl->rejected;
			return NULL;
		}
		if (registry_impl->pending_required) {
			defer_request(registry, src, local_ufrag, remote_ufrag, buf, len, &msg);
			return NULL;
		}

		registry_impl_t *impl = registry->impl;

		if (impl->cb_mux_incoming) {
			JLOG_DEBUG("Found STUN request with unknown ICE ufrag");
			char host[ADDR_MAX_NUMERICHOST_LEN];
			if (getnameinfo((const struct sockaddr *)&src->addr, src->len, host, ADDR_MAX_NUMERICHOST_LEN, NULL, 0, NI_NUMERICHOST)) {
				JLOG_ERROR("getnameinfo failed, errno=%d", sockerrno);
				return NULL;
			}

			juice_mux_binding_request_t incoming_info;

			incoming_info.local_ufrag = local_ufrag;
			incoming_info.remote_ufrag = separator + 1;
			incoming_info.address = host;
			incoming_info.port = addr_get_port((struct sockaddr *)src);

			impl->cb_mux_incoming(&incoming_info, impl->mux_incoming_user_ptr);

			return NULL;
		}
	} else {
		if (!STUN_IS_RESPONSE(msg.msg_class)) {
			++registry_impl->rejected;
			JLOG_DEBUG("Got unexpected STUN message from unknown source address");
			return NULL;
		}

		for (int i = 0; i < registry->agents_size; ++i) {
			agent = registry->agents[i];
			if (is_ready(agent)) {
				if (agent_find_entry_from_transaction_id(agent, msg.transaction_id)) {
					JLOG_DEBUG("Found agent from transaction ID");
					return agent;
				}
			}
		}
	}

	return NULL;
}

static void process_datagram(conn_registry_t *registry, char *data, size_t size,
                              const addr_record_t *src) {
    juice_agent_t *agent = lookup_agent(registry, data, size, src);
    if (!agent || !is_ready(agent)) {
        JLOG_DEBUG("Agent not found for incoming datagram, dropping");
        return;
    }
    conn_impl_t *conn_impl = agent->conn_impl;
    if (agent_conn_recv(agent, data, size, src) != 0) {
        JLOG_WARN("Agent receive failed");
        conn_impl->finished = true;
        return;
    }
    conn_impl->next_timestamp = current_timestamp();
}

int conn_mux_process(conn_registry_t *registry, struct pollfd *pfd) {
	mutex_lock(&registry->mutex);

	if (pfd->revents & POLLNVAL || pfd->revents & POLLERR) {
		JLOG_ERROR("Error when polling socket");
		conn_mux_fail(registry);
		mutex_unlock(&registry->mutex);
		return -1;
	}

    registry_impl_t *impl = registry->impl;
	timestamp_t now = current_timestamp();
	expire_pending(impl, now);
	while (impl->ready_head) {
		pending_request_t *request = impl->ready_head;
		juice_agent_t *agent = request->agent;
		if (is_ready(agent) && insert_map_entry(impl, &request->src, agent) == 0) {
			conn_impl_t *connection = agent->conn_impl;
			if (agent_conn_recv(agent, request->data, request->size, &request->src) != 0)
				connection->finished = true;
			connection->next_timestamp = current_timestamp();
		}
		remove_pending(impl, request);
	}

	if (pfd->revents & POLLIN) {
		char buffer[BUFFER_SIZE];
		addr_record_t src;
		int left = 1000; // limit to ensure update is run and new agents are processed
		int ret;
		while (left--) {
			if ((ret = conn_mux_recv(registry, buffer, BUFFER_SIZE, &src)) <= 0) {
				break;
			}

			if (JLOG_DEBUG_ENABLED) {
				char src_str[ADDR_MAX_STRING_LEN];
				addr_record_to_string(&src, src_str, ADDR_MAX_STRING_LEN);
				JLOG_DEBUG("Demultiplexing incoming datagram from %s", src_str);
			}

			++impl->received;
			char *data = buffer;
			size_t size = (size_t)ret;
			if (impl->proxy && mux_proxy_receive(impl->proxy, &data, &size, &src, now) != 0) {
				++impl->rejected;
				continue;
			}
			process_datagram(registry, data, size, &src);
		}

		if (ret < 0) {
			conn_mux_fail(registry);
			mutex_unlock(&registry->mutex);
			return -1;
		}
	}

	for (int i = 0; i < registry->agents_size; ++i) {
		juice_agent_t *agent = registry->agents[i];
		if (is_ready(agent)) {
			conn_impl_t *conn_impl = agent->conn_impl;
			if (conn_impl->next_timestamp <= current_timestamp()) {
				if (agent_conn_update(agent, &conn_impl->next_timestamp) != 0) {
					JLOG_WARN("Agent update failed");
					conn_impl->finished = true;
					continue;
				}
			}
		}
	}

	mutex_unlock(&registry->mutex);
	dispatch_pending(registry);
	return 0;
}

int conn_mux_recv(conn_registry_t *registry, char *buffer, size_t size, addr_record_t *src) {
	JLOG_VERBOSE("Receiving datagram");
	registry_impl_t *registry_impl = registry->impl;
	int len;
	while ((len = udp_recvfrom(registry_impl->sock, buffer, size, src)) == 0) {
		// Empty datagram (used to interrupt)
	}

	if (len < 0) {
		if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK) {
			JLOG_VERBOSE("No more datagrams to receive");
			return 0;
		}
		JLOG_ERROR("recvfrom failed, errno=%d", sockerrno);
		return -1;
	}

	addr_unmap_inet6_v4mapped((struct sockaddr *)&src->addr, &src->len);
	return len; // len > 0
}

void conn_mux_fail(conn_registry_t *registry) {
	for (int i = 0; i < registry->agents_size; ++i) {
		juice_agent_t *agent = registry->agents[i];
		if (is_ready(agent)) {
			conn_impl_t *conn_impl = agent->conn_impl;
			agent_conn_fail(agent);
			conn_impl->finished = true;
		}
	}
}

int conn_mux_run(conn_registry_t *registry) {
	struct pollfd pfd[1];
	timestamp_t next_timestamp;
	while (conn_mux_prepare(registry, pfd, &next_timestamp) > 0) {
		timediff_t timediff = next_timestamp - current_timestamp();
		if (timediff < 0)
			timediff = 0;

		JLOG_VERBOSE("Entering poll for %d ms", (int)timediff);
		int ret = poll(pfd, 1, (int)timediff);
		JLOG_VERBOSE("Leaving poll");
		if (ret < 0) {
			if (sockerrno == SEINTR || sockerrno == SEAGAIN) {
				JLOG_VERBOSE("poll interrupted");
				continue;
			} else {
				JLOG_FATAL("poll failed, errno=%d", sockerrno);
				break;
			}
		}

		if (conn_mux_process(registry, pfd) < 0)
			break;
	}

	JLOG_DEBUG("Leaving connections thread");
	return 0;
}

int conn_mux_init(juice_agent_t *agent, conn_registry_t *registry, udp_socket_config_t *config) {
	(void)config; // ignored, only the config from the first connection is used

	conn_impl_t *conn_impl = calloc(1, sizeof(conn_impl_t));
	if (!conn_impl) {
		JLOG_FATAL("Memory allocation failed for connection impl");
		return -1;
	}

	conn_impl->registry = registry;
	agent->conn_impl = conn_impl;
	return 0;
}

void conn_mux_cleanup(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	conn_registry_t *registry = conn_impl->registry;

	mutex_lock(&registry->mutex);
	registry_impl_t *registry_impl = registry->impl;
	remove_map_entries(registry_impl, agent);
	pending_request_t *request = registry_impl->pending_head;
	while (request) {
		pending_request_t *next = request->next;
		if (request->agent == agent) remove_pending(registry_impl, request);
		request = next;
	}
	mutex_unlock(&registry->mutex);

	conn_mux_interrupt(agent);

	free(agent->conn_impl);
	agent->conn_impl = NULL;
}

void conn_mux_lock(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	conn_registry_t *registry = conn_impl->registry;
	mutex_lock(&registry->mutex);
}

void conn_mux_unlock(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	conn_registry_t *registry = conn_impl->registry;
	mutex_unlock(&registry->mutex);
}

int conn_mux_interrupt_registry(conn_registry_t *registry) {
	JLOG_VERBOSE("Interrupting connections thread");

	registry_impl_t *registry_impl = registry->impl;
	mutex_lock(&registry_impl->send_mutex);
	char dummy = 0; // Some C libraries might error out on NULL pointers
	if (udp_sendto_self(registry_impl->sock, &dummy, 0) < 0) {
		if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK) {
			JLOG_WARN("Failed to interrupt poll by triggering socket, errno=%d", sockerrno);
		}
		mutex_unlock(&registry_impl->send_mutex);
		return -1;
	}
	mutex_unlock(&registry_impl->send_mutex);
	return 0;
}

int conn_mux_interrupt(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	conn_registry_t *registry = conn_impl->registry;

	mutex_lock(&registry->mutex);
	conn_impl->next_timestamp = current_timestamp();
	mutex_unlock(&registry->mutex);

	return conn_mux_interrupt_registry(registry);
}

int conn_mux_send(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size,
                  int ds) {
	conn_impl_t *conn_impl = agent->conn_impl;
	registry_impl_t *registry_impl = conn_impl->registry->impl;

	mutex_lock(&registry_impl->send_mutex);

	if (registry_impl->send_ds >= 0 && registry_impl->send_ds != ds) {
		JLOG_VERBOSE("Setting Differentiated Services field to 0x%X", ds);
		if (udp_set_diffserv(registry_impl->sock, ds) == 0)
			registry_impl->send_ds = ds;
		else
			registry_impl->send_ds = -1; // disable for next time
	}

	JLOG_VERBOSE("Sending datagram, size=%d", size);

	// A client behind a relay is reached through it
	const addr_record_t *to =
	    registry_impl->proxy ? mux_proxy_route(registry_impl->proxy, dst) : dst;
	int ret = udp_sendto(registry_impl->sock, data, size, to);
	if (ret < 0) {
		ret = -sockerrno;
		if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
			JLOG_INFO("Send failed, buffer is full");
		else if (sockerrno == SEMSGSIZE)
			JLOG_WARN("Send failed, datagram is too large");
		else
			JLOG_WARN("Send failed, errno=%d", sockerrno);
	}

	mutex_unlock(&registry_impl->send_mutex);
	return ret;
}

int conn_mux_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size) {
	conn_impl_t *conn_impl = agent->conn_impl;
	registry_impl_t *registry_impl = conn_impl->registry->impl;

	return udp_get_addrs(registry_impl->sock, records, size);
}

int conn_mux_stop_listen(conn_registry_t *registry) {
	registry_impl_t *registry_impl = registry->impl;
	if (!registry_impl) {
		JLOG_VERBOSE("conn_mux_stop_listen No registry impl found");
		return -1;
	}

	JLOG_VERBOSE("conn_mux_stop_listen Removing mux handler callback");
	registry_impl->cb_mux_incoming = NULL;
	registry_impl->mux_incoming_user_ptr = NULL;

	return conn_mux_interrupt_registry(registry);
}

int conn_mux_listen(conn_registry_t *registry, juice_cb_mux_incoming_t cb, void *user_ptr) {
	if (!cb) {
		return conn_mux_stop_listen(registry);
	}

	registry_impl_t *registry_impl = registry->impl;
	if (!registry_impl) {
		JLOG_VERBOSE("conn_mux_listen No registry impl found");
		return -1;
	}

	if (registry_impl->cb_mux_incoming || registry_impl->pending_required) {
		JLOG_VERBOSE("conn_mux_listen Callback already registered\n");
		return -1;
	}

	registry_impl->cb_mux_incoming = cb;
	registry_impl->mux_incoming_user_ptr = user_ptr;

	return 0;
}

bool conn_mux_can_release_registry(conn_registry_t *registry) {
	registry_impl_t *registry_impl = registry->impl;

	if (!registry_impl) {
		JLOG_VERBOSE("conn_mux_can_release_registry No registry impl found");
		return true;
	}

	return registry_impl->cb_mux_incoming == NULL && registry_impl->cb_mux_pending == NULL &&
	       !registry_impl->pending_closing && !registry_impl->proxy;
}

int conn_mux_listen_pending(conn_registry_t *registry, const juice_mux_pending_config_t *config,
                           juice_cb_mux_pending_t cb, void *user_ptr) {
	registry_impl_t *impl = registry->impl;
	if (!cb || impl->cb_mux_incoming || impl->cb_mux_pending || impl->pending_closing)
		return JUICE_ERR_NOT_AVAIL;
	unsigned int limit = config && config->max_pending ? config->max_pending : 256;
	unsigned int timeout = config && config->timeout_ms ? config->timeout_ms : 5000;
	if (limit > 4096 || timeout > 30000) return JUICE_ERR_INVALID;
	unsigned int buckets = 1;
	while (buckets < limit * 2) buckets *= 2;
	pending_request_t **table = calloc(buckets, sizeof(*table));
	pending_request_t **ids = calloc(buckets, sizeof(*ids));
	if (!table || !ids) { free(table); free(ids); return JUICE_ERR_FAILED; }
	free(impl->pending_buckets);
	free(impl->pending_ids);
	impl->pending_buckets = table;
	impl->pending_ids = ids;
	impl->pending_bucket_count = buckets;
	// Already-attached requests belong to their agents, even across listener stop.
	for (pending_request_t *request = impl->pending_head; request; request = request->next) {
		unsigned long bucket = pending_hash(&request->src, request->local_ufrag,
		                                   request->remote_ufrag) % buckets;
		request->hash_next = table[bucket];
		table[bucket] = request;
		request->id_next = ids[request->id % buckets];
		ids[request->id % buckets] = request;
	}
	impl->max_pending = limit;
	impl->pending_timeout_ms = timeout;
	impl->pending_required = true;
	impl->cb_mux_pending = cb;
	impl->mux_pending_user_ptr = user_ptr;
	return 0;
}

int conn_mux_begin_stop_pending(conn_registry_t *registry) {
	registry_impl_t *impl = registry->impl;
#ifdef _WIN32
	if (GetCurrentThreadId() == GetThreadId(impl->thread)) return JUICE_ERR_INVALID;
#else
	if (pthread_equal(pthread_self(), impl->thread)) return JUICE_ERR_INVALID;
#endif
	if (!impl->cb_mux_pending || impl->pending_closing) return JUICE_ERR_NOT_AVAIL;
	impl->pending_closing = true; // Keeps the registry alive until callback completion.
	impl->cb_mux_pending = NULL;
	impl->mux_pending_user_ptr = NULL;
	destroy_admission(impl);
	pending_request_t *request = impl->pending_head;
	while (request) {
		pending_request_t *next = request->next;
		if (!request->agent) remove_pending(impl, request);
		request = next;
	}
	return 0;
}

void conn_mux_wait_pending_callbacks(conn_registry_t *registry) {
	registry_impl_t *impl = registry->impl;
	mutex_lock(&impl->callback_mutex);
	mutex_unlock(&impl->callback_mutex);
}

void conn_mux_finish_stop_pending(conn_registry_t *registry) {
	registry_impl_t *impl = registry->impl;
	impl->pending_closing = false;
	conn_mux_interrupt_registry(registry);
}

int conn_mux_verify_request(conn_registry_t *registry, uint64_t id, const char *password) {
	registry_impl_t *impl = registry->impl;
	expire_pending(impl, current_timestamp());
	pending_request_t *request = pending_by_id(impl, id);
	if (!request || request->verified || !request->notified) return JUICE_ERR_NOT_AVAIL;
	map_entry_t *entry = find_map_entry(impl, &request->src, false);
	stun_message_t message;
	if ((entry && entry->type == MAP_ENTRY_TYPE_FULL) ||
	    stun_read(request->data, request->size, &message) < 0 ||
	    !stun_check_integrity(request->data, request->size, &message, password)) {
		++impl->rejected;
		remove_pending(impl, request);
		return JUICE_ERR_FAILED;
	}
	strcpy(request->password, password);
	request->verified = true;
	return 0;
}

int conn_mux_attach_request(conn_registry_t *registry, uint64_t id, juice_agent_t *agent) {
	registry_impl_t *impl = registry->impl;
	expire_pending(impl, current_timestamp());
	pending_request_t *request = pending_by_id(impl, id);
	if (!request || !request->verified || request->agent) return JUICE_ERR_NOT_AVAIL;
	if (agent->registry != registry || agent->config.mux_direct || !is_ready(agent) ||
	    strcmp(agent->local.ice_ufrag, request->local_ufrag) != 0 ||
	    strcmp(agent->remote.ice_ufrag, request->remote_ufrag) != 0 ||
	    strcmp(agent->local.ice_pwd, request->password) != 0) return JUICE_ERR_INVALID;
	map_entry_t *entry = find_map_entry(impl, &request->src, false);
	if (entry && entry->type == MAP_ENTRY_TYPE_FULL) return JUICE_ERR_NOT_AVAIL;
	for (pending_request_t *other = impl->ready_head; other; other = other->work_next)
		if (addr_record_is_equal(&request->src, &other->src, true))
			return JUICE_ERR_NOT_AVAIL;
	if (conn_mux_interrupt_registry(registry) != 0) return JUICE_ERR_FAILED;
	remove_expiry(impl, request);
	request->agent = agent;
	append_work(&impl->ready_head, &impl->ready_tail, request);
	return 0;
}

int conn_mux_reject_request(conn_registry_t *registry, uint64_t id) {
	registry_impl_t *impl = registry->impl;
	pending_request_t *request = pending_by_id(impl, id);
	if (!request || request->agent) return JUICE_ERR_NOT_AVAIL;
	++impl->rejected;
	remove_pending(impl, request);
	return 0;
}

void conn_mux_get_stats(conn_registry_t *registry, juice_mux_stats_t *stats) {
	registry_impl_t *impl = registry->impl;
	*stats = (juice_mux_stats_t){impl->received, impl->rejected, registry->agents_count,
		impl->map_count, impl->pending_count, impl->notifications, impl->duplicates};
}

int conn_mux_set_admission(conn_registry_t *registry, const juice_mux_admission_t *config) {
	registry_impl_t *impl = registry->impl;
	if (!impl->cb_mux_pending || impl->pending_closing) return JUICE_ERR_NOT_AVAIL;
	if (!config) {
		destroy_admission(impl);
		return 0;
	}
	if (config->context_size > MAX_ADMISSION_CONTEXT || (config->context_size && !config->context) ||
	    config->keys_count < 0 || config->keys_count > MAX_ADMISSION_KEYS ||
	    (config->keys_count && !config->keys))
		return JUICE_ERR_INVALID;
	for (int i = 0; i < config->keys_count; ++i) {
		const juice_mux_admission_key_t *key = &config->keys[i];
		size_t prefix = key->ufrag_prefix ? strlen(key->ufrag_prefix) : 0;
		if (prefix < 1 || prefix > MAX_ADMISSION_PREFIX || !key->secret || key->secret_size < 1 ||
		    key->secret_size > MAX_ADMISSION_SECRET)
			return JUICE_ERR_INVALID;
	}
	admission_t *admission = calloc(1, sizeof(*admission));
	if (!admission) return JUICE_ERR_FAILED;
	admission->context_size = config->context_size;
	if (config->context_size) memcpy(admission->context, config->context, config->context_size);
	admission->keys_count = config->keys_count;
	for (int i = 0; i < config->keys_count; ++i) {
		strcpy(admission->keys[i].prefix, config->keys[i].ufrag_prefix);
		admission->keys[i].secret_size = config->keys[i].secret_size;
		memcpy(admission->keys[i].secret, config->keys[i].secret, config->keys[i].secret_size);
	}
	destroy_admission(impl);
	impl->admission = admission;
	return 0;
}

int conn_mux_set_proxy_protocol(conn_registry_t *registry, const char *const *proxies,
                                size_t count) {
	// The caller holds the registry lock, so nothing receives meanwhile
	registry_impl_t *impl = registry->impl;
	mux_proxy_t *proxy = NULL;
	if (count) {
		int ret = mux_proxy_create(proxies, count, &impl->send_mutex, impl->proxy, &proxy);
		if (ret != 0)
			return ret;
	}
	mutex_lock(&impl->send_mutex);
	mux_proxy_t *previous = impl->proxy;
	impl->proxy = proxy;
	mutex_unlock(&impl->send_mutex);
	mux_proxy_destroy(previous);
	// So the thread sees whether it is still needed. A failure logs, and its poll times out anyway.
	conn_mux_interrupt_registry(registry);
	return 0;
}

/* SPDX-License-Identifier: MPL-2.0 */
#include "mux_test_helpers.h"
#include <time.h>

typedef struct observed {
	atomic_uint calls;
	atomic_uint_fast64_t id;
	char address[64];
	uint16_t port;
} observed_t;

static void incoming(const juice_mux_pending_request_t *request, void *ptr) {
	observed_t *observed = ptr;
	snprintf(observed->address, sizeof(observed->address), "%s", request->binding.address);
	observed->port = request->binding.port;
	atomic_store(&observed->id, request->request_id);
	atomic_fetch_add(&observed->calls, 1);
}

static uint64_t await_callback(observed_t *observed, unsigned int count) {
	for (int i = 0; i < 400 && atomic_load(&observed->calls) < count; ++i) usleep(5000);
	assert(atomic_load(&observed->calls) == count);
	return atomic_load(&observed->id);
}

#define CLIENT "203.0.113.7"

// A relay's header for a datagram from the given client, IPv6 if it has a colon
static size_t proxy_header(unsigned char *out, const char *client, uint16_t client_port,
                           uint16_t port) {
	static const unsigned char signature[12] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
	                                            0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};
	bool v6 = strchr(client, ':') != NULL;
	int family = v6 ? AF_INET6 : AF_INET;
	size_t length = v6 ? 16 : 4;
	memcpy(out, signature, sizeof(signature));
	out[12] = 0x21;            // v2, PROXY
	out[13] = v6 ? 0x22 : 0x12; // datagram
	out[14] = 0;
	out[15] = (unsigned char)(2 * length + 4);
	assert(inet_pton(family, client, out + 16) == 1);
	assert(inet_pton(family, v6 ? "::1" : "127.0.0.1", out + 16 + length) == 1);
	unsigned char *ports = out + 16 + 2 * length;
	ports[0] = client_port >> 8;
	ports[1] = client_port & 0xFF;
	ports[2] = port >> 8;
	ports[3] = port & 0xFF;
	return 16 + 2 * length + 4;
}

// A binding request, behind a header declaring client unless it is NULL
static void send_binding(int fd, uint16_t port, const char *client) {
	stun_message_t request = {0};
	request.msg_class = STUN_CLASS_REQUEST;
	request.msg_method = STUN_METHOD_BINDING;
	request.priority = 123456;
	request.ice_controlling = 123456789;
	memcpy(request.transaction_id, "firstrequest", STUN_TRANSACTION_ID_SIZE);
	snprintf(request.credentials.username, sizeof(request.credentials.username), "host:peer");
	unsigned char datagram[2048];
	size_t offset = client ? proxy_header(datagram, client, 5555, port) : 0;
	int size =
	    _juice_stun_write(datagram + offset, sizeof(datagram) - offset, &request, test_password);
	assert(size > 0);
	struct sockaddr_in destination = {.sin_family = AF_INET, .sin_port = htons(port)};
	assert(inet_pton(AF_INET, "127.0.0.1", &destination.sin_addr) == 1);
	size += (int)offset;
	struct sockaddr *to = (struct sockaddr *)&destination;
	assert(sendto(fd, datagram, size, 0, to, sizeof(destination)) == size);
}

static void attributes_a_relayed_client(void) {
	uint16_t port = test_port(), relay;
	int fd = test_socket(&relay);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	observed_t observed = {0};
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, incoming, &observed) == 0);

	send_binding(fd, port, CLIENT);
	uint64_t id = await_callback(&observed, 1);
	assert(strcmp(observed.address, CLIENT) == 0 && observed.port == 5555);
	assert(juice_mux_verify_request("127.0.0.1", port, id, test_password) == 0);
	juice_agent_t *agent = test_agent(port);
	assert(juice_mux_attach_request("127.0.0.1", port, id, agent) == 0);
	// Sent to the client, so it only arrives here if it went back through the relay
	test_response(fd);

	juice_mux_stats_t stats = test_received(port, 1);
	assert(stats.mapped_tuples == 1);
	// A relay that only prefixes the first datagram keeps its client
	send_binding(fd, port, NULL);
	stats = test_received(port, 2);
	test_response(fd);
	assert(stats.notifications == 1 && atomic_load(&observed.calls) == 1);

	// So does a new list that still has the relay, while one without it forgets the client
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	send_binding(fd, port, NULL);
	test_response(fd);
	const char *others[] = {"10.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, others, 1) == 0);
	send_binding(fd, port, NULL);
	assert(!test_answered(fd));

	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, NULL, NULL) == 0);
	juice_destroy(agent);
	// The setting alone holds the endpoint open
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == 0);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == JUICE_ERR_NOT_AVAIL);
	close(fd);
}

// A dual-stack relay declares an IPv4 client as v4-mapped IPv6, which arrives as the IPv4 client
static void unmaps_a_v4_mapped_client(void) {
	uint16_t port = test_port(), relay;
	int fd = test_socket(&relay);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	observed_t observed = {0};
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, incoming, &observed) == 0);

	send_binding(fd, port, "::ffff:" CLIENT);
	await_callback(&observed, 1);
	assert(strcmp(observed.address, CLIENT) == 0 && observed.port == 5555);

	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, NULL, NULL) == 0);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(fd);
}

// Peers only come through relays, so the rest is dropped whether it carries a header or not
static void drops_what_no_relay_brings(void) {
	uint16_t port = test_port(), source, relay;
	int fd = test_socket(&source), relay_fd = test_socket(&relay);
	const char *relays[] = {"10.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	observed_t observed = {0};
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, incoming, &observed) == 0);

	send_binding(fd, port, CLIENT);
	send_binding(fd, port, NULL);
	juice_mux_stats_t stats = test_received(port, 2);
	usleep(30000);
	assert(atomic_load(&observed.calls) == 0);
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == 0 && stats.rejected == 2);

	// Nor does a relay's datagram without a header, before any flow says whose it is
	const char *local[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, local, 1) == 0);
	send_binding(relay_fd, port, NULL);
	stats = test_received(port, 3);
	usleep(30000);
	assert(atomic_load(&observed.calls) == 0);
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == 0 && stats.rejected == 3);

	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, NULL, NULL) == 0);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(fd);
	close(relay_fd);
}

// Responses to the endpoint's own requests still come straight from their server
static void keeps_responses_to_its_own_requests(void) {
	uint16_t port = test_port(), server;
	int fd = test_socket(&server);
	const char *relays[] = {"10.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	juice_config_t config = {0};
	config.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	config.bind_address = "127.0.0.1";
	config.local_port_range_begin = config.local_port_range_end = port;
	config.stun_server_host = "127.0.0.1";
	config.stun_server_port = server;
	juice_agent_t *agent = juice_create(&config);
	assert(agent && juice_gather_candidates(agent) == 0);

	unsigned char datagram[2048];
	struct sockaddr_storage from;
	socklen_t from_size = sizeof(from);
	struct pollfd pfd = {.fd = fd, .events = POLLIN};
	assert(poll(&pfd, 1, 2000) == 1);
	ssize_t size = recvfrom(fd, datagram, sizeof(datagram), 0, (struct sockaddr *)&from, &from_size);
	stun_message_t request = {0};
	assert(size > 0 && _juice_stun_read(datagram, size, &request) > 0);
	stun_message_t response = {0};
	response.msg_class = STUN_CLASS_RESP_SUCCESS;
	response.msg_method = STUN_METHOD_BINDING;
	memcpy(response.transaction_id, request.transaction_id, STUN_TRANSACTION_ID_SIZE);
	struct sockaddr_in *mapped = (struct sockaddr_in *)&response.mapped.addr;
	mapped->sin_family = AF_INET;
	mapped->sin_port = htons(4000);
	assert(inet_pton(AF_INET, "198.51.100.4", &mapped->sin_addr) == 1);
	response.mapped.len = sizeof(struct sockaddr_in);
	int written = _juice_stun_write(datagram, sizeof(datagram), &response, NULL);
	assert(written > 0);
	assert(sendto(fd, datagram, written, 0, (struct sockaddr *)&from, from_size) == written);

	char description[JUICE_MAX_SDP_STRING_LEN];
	bool reflexive = false;
	for (int i = 0; i < 200 && !reflexive; ++i) {
		usleep(10000);
		assert(juice_get_local_description(agent, description, sizeof(description)) == 0);
		reflexive = strstr(description, "typ srflx") != NULL;
	}
	assert(reflexive);
	juice_destroy(agent);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(fd);
}

// Direct agents with no listener, as built-in signaling runs: the setting alone keeps it served
static void serves_agents_without_a_listener(void) {
	uint16_t port = test_port(), relay;
	int fd = test_socket(&relay);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	// The endpoint idles before its first agent, as between a bind and the first join
	usleep(50000);
	juice_agent_t *agent = test_mux_agent(port, true);
	send_binding(fd, port, CLIENT);
	test_response(fd);
	juice_destroy(agent);

	// Clearing wakes the endpoint rather than waiting out its idle poll
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	clock_gettime(CLOCK_MONOTONIC, &end);
	assert(end.tv_sec - start.tv_sec < 2);
	close(fd);
}

static void refuses_an_invalid_range(void) {
	uint16_t port = test_port();
	const char *word[] = {"relay"};
	const char *prefix[] = {"10.0.0.0/33"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, word, 1) == JUICE_ERR_INVALID);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, prefix, 1) == JUICE_ERR_INVALID);
	juice_mux_stats_t stats;
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == JUICE_ERR_NOT_AVAIL);
}

int main(void) {
	juice_set_log_level(JUICE_LOG_LEVEL_FATAL);
	attributes_a_relayed_client();
	unmaps_a_v4_mapped_client();
	drops_what_no_relay_brings();
	keeps_responses_to_its_own_requests();
	serves_agents_without_a_listener();
	refuses_an_invalid_range();
	puts("mux PROXY protocol: relayed clients, kept across lists, the rest dropped except STUN "
	     "responses, served without a listener PASS");
}

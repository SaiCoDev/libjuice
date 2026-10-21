/* SPDX-License-Identifier: MPL-2.0 */
#ifndef JUICE_MUX_TEST_HELPERS_H
#define JUICE_MUX_TEST_HELPERS_H
#include <juice/juice.h>
#include "stun.h"
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char test_password[] = "012345678901234567890123456789";

static int test_socket(uint16_t *port) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd >= 0);
	struct sockaddr_in address = {.sin_family = AF_INET};
	assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
	assert(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
	socklen_t size = sizeof(address);
	assert(getsockname(fd, (struct sockaddr *)&address, &size) == 0);
	*port = ntohs(address.sin_port);
	return fd;
}

static uint16_t test_port(void) {
	uint16_t port;
	int fd = test_socket(&port);
	close(fd);
	return port;
}

static void test_send(int fd, uint16_t port, const char *local, const char *remote,
                      const char *password) {
	stun_message_t request = {0};
	request.msg_class = STUN_CLASS_REQUEST;
	request.msg_method = STUN_METHOD_BINDING;
	request.priority = 123456;
	request.ice_controlling = 123456789;
	memcpy(request.transaction_id, "firstrequest", STUN_TRANSACTION_ID_SIZE);
	snprintf(request.credentials.username, sizeof(request.credentials.username), "%s:%s", local, remote);
	unsigned char datagram[2048];
	int size = _juice_stun_write(datagram, sizeof(datagram), &request, password);
	assert(size > 0);
	struct sockaddr_in destination = {.sin_family = AF_INET, .sin_port = htons(port)};
	assert(inet_pton(AF_INET, "127.0.0.1", &destination.sin_addr) == 1);
	assert(sendto(fd, datagram, size, 0, (struct sockaddr *)&destination, sizeof(destination)) == size);
}

static juice_mux_stats_t test_received(uint16_t port, uint64_t count) {
	juice_mux_stats_t stats;
	for (int i = 0; i < 400; ++i) {
		assert(juice_mux_get_stats("127.0.0.1", port, &stats) == 0);
		if (stats.received >= count) return stats;
		usleep(5000);
	}
	assert(!"timed out waiting for datagrams");
	return stats;
}

static void test_response(int fd) {
	for (int i = 0; i < 40; ++i) {
		struct pollfd pfd = {.fd = fd, .events = POLLIN};
		assert(poll(&pfd, 1, 50) >= 0);
		if (!(pfd.revents & POLLIN)) continue;
		unsigned char response[2048];
		ssize_t size = recv(fd, response, sizeof(response), 0);
		assert(size > 0);
		stun_message_t message = {0};
		assert(_juice_stun_read(response, size, &message) > 0);
		if (message.msg_class == STUN_CLASS_RESP_SUCCESS &&
		    memcmp(message.transaction_id, "firstrequest", STUN_TRANSACTION_ID_SIZE) == 0) {
			assert(_juice_stun_check_integrity(response, size, &message, test_password));
			return;
		}
	}
	assert(!"the retained first request did not receive its authenticated response");
}

static juice_agent_t *test_mux_agent(uint16_t port, bool direct) {
	juice_config_t config = {0};
	config.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	config.mux_direct = direct;
	config.bind_address = "127.0.0.1";
	config.local_port_range_begin = config.local_port_range_end = port;
	juice_agent_t *agent = juice_create(&config);
	assert(agent);
	assert(juice_set_local_ice_attributes(agent, "host", test_password) == 0);
	assert(juice_set_remote_description(agent,
	    "a=ice-ufrag:peer\r\na=ice-pwd:012345678901234567890123456789\r\n") == 0);
	assert(juice_gather_candidates(agent) == 0);
	return agent;
}

static juice_agent_t *test_agent(uint16_t port) { return test_mux_agent(port, false); }
#endif

/* SPDX-License-Identifier: MPL-2.0 */
#include "mux_test_helpers.h"

static atomic_uint calls, unexpected;
static atomic_uint_fast64_t last_id;
static const char *expected_ufrag;

static void incoming(const juice_mux_pending_request_t *request, void *ptr) {
	(void)ptr;
	if (strcmp(request->binding.local_ufrag, expected_ufrag) != 0)
		atomic_fetch_add(&unexpected, 1);
	atomic_store(&last_id, request->request_id);
	atomic_fetch_add(&calls, 1);
}

static uint64_t await_calls(unsigned int count) {
	for (int i = 0; i < 400 && atomic_load(&calls) < count; ++i) usleep(5000);
	assert(atomic_load(&calls) == count && atomic_load(&unexpected) == 0);
	return atomic_load(&last_id);
}

static bool established(juice_agent_t *agent) {
	juice_state_t state = juice_get_state(agent);
	return state == JUICE_STATE_CONNECTED || state == JUICE_STATE_COMPLETED;
}

// A direct agent completes ICE next to a pending listener; unknown ufrags still reach admission.
static void connectivity(void) {
	atomic_store(&calls, 0);
	expected_ufrag = "unknown";
	uint16_t port = test_port(), source;
	int fd = test_socket(&source);
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, incoming, NULL) == 0);
	juice_agent_t *direct = test_mux_agent(port, true);
	juice_config_t config = {0};
	config.bind_address = "127.0.0.1";
	juice_agent_t *remote = juice_create(&config);
	assert(remote);
	assert(juice_set_local_ice_attributes(remote, "peer", test_password) == 0);
	char sdp[JUICE_MAX_SDP_STRING_LEN];
	// The remote offers first and controls, like a joining client.
	assert(juice_get_local_description(remote, sdp, sizeof(sdp)) == 0);
	assert(juice_get_local_description(direct, sdp, sizeof(sdp)) == 0);
	assert(juice_set_remote_description(remote, sdp) == 0);
	assert(juice_gather_candidates(remote) == 0);
	for (int i = 0; i < 1000 && !(established(remote) && established(direct)); ++i) usleep(5000);
	assert(established(remote) && established(direct));
	assert(atomic_load(&calls) == 0);
	test_send(fd, port, "unknown", "peer", test_password);
	uint64_t id = await_calls(1);
	juice_mux_stats_t stats;
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == 0);
	assert(stats.pending == 1 && stats.notifications == 1 && stats.mapped_tuples >= 1);
	assert(juice_mux_reject_request("127.0.0.1", port, id) == 0);
	juice_destroy(remote);
	juice_destroy(direct);
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, NULL, NULL) == 0);
	close(fd);
}

// Checks that arrive before the direct agent is gathered are held for admission. A retransmission
// then reaches the agent by ufrag; the held requests can neither map that source again nor attach.
static void deferred_before_ready(void) {
	atomic_store(&calls, 0);
	expected_ufrag = "host";
	uint16_t port = test_port(), source, other_source;
	int fd = test_socket(&source), other = test_socket(&other_source);
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, incoming, NULL) == 0);
	test_send(fd, port, "host", "peer", test_password);
	uint64_t retransmitted = await_calls(1);
	test_send(other, port, "host", "peer", test_password);
	uint64_t held = await_calls(2);
	juice_agent_t *direct = test_mux_agent(port, true);
	test_send(fd, port, "host", "peer", test_password);
	test_response(fd);
	juice_mux_stats_t stats = test_received(port, 3);
	assert(stats.mapped_tuples == 1 && stats.pending == 2 && stats.duplicates == 0);
	assert(juice_mux_verify_request("127.0.0.1", port, retransmitted, test_password) == JUICE_ERR_FAILED);
	assert(juice_mux_verify_request("127.0.0.1", port, held, test_password) == 0);
	assert(juice_mux_attach_request("127.0.0.1", port, held, direct) == JUICE_ERR_INVALID);
	assert(juice_mux_reject_request("127.0.0.1", port, held) == 0);
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == 0);
	assert(stats.pending == 0 && stats.mapped_tuples == 1 && stats.notifications == 2);
	juice_destroy(direct);
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, NULL, NULL) == 0);
	close(other);
	close(fd);
}

// Generated ufrags are four characters, so live agents can share one. The password decides which
// agent a request is for, behind a pending listener and in plain mux mode alike.
static void shared_ufrag(bool pending) {
	static const char other_password[] = "abcdefghijabcdefghijabcdefghij";
	atomic_store(&calls, 0);
	uint16_t port = test_port(), source, wrong_source;
	int fd = test_socket(&source), wrong = test_socket(&wrong_source);
	if (pending) assert(juice_mux_listen_pending("127.0.0.1", port, NULL, incoming, NULL) == 0);
	juice_agent_t *first = test_mux_agent_with(port, pending, test_password);
	juice_agent_t *second = test_mux_agent_with(port, pending, other_password);
	test_send(fd, port, "host", "peer", other_password);
	test_response_for(fd, other_password);
	test_send(wrong, port, "host", "peer", "wrongwrongwrongwrongwrongwrong");
	assert(!test_answered(wrong));
	juice_mux_stats_t stats = test_received(port, 2);
	assert(stats.mapped_tuples == 1 && stats.rejected == 1 && atomic_load(&calls) == 0);
	juice_destroy(second);
	juice_destroy(first);
	if (pending) assert(juice_mux_listen_pending("127.0.0.1", port, NULL, NULL, NULL) == 0);
	close(wrong);
	close(fd);
}

int main(void) {
	juice_set_log_level(JUICE_LOG_LEVEL_FATAL);
	connectivity();
	deferred_before_ready();
	shared_ufrag(true);
	shared_ufrag(false);
	puts("direct mux agents: ufrag routing beside a pending listener, held requests stay admission-only, shared ufrags PASS");
}

/* SPDX-License-Identifier: MPL-2.0 */
#include "mux_test_helpers.h"

// Vector from network's stateless-admission-v1 fixture.
static const char secret[] = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
static const char context[] =
    "nxs-stateless-ice-v1\0nxs-stateless-host-v1/0123456789abcdef0123456789abcdef";
static const char token[] =
    "NXS1K001AAECAwQFBgcICQoLdmyMSn5L1qmXVDtK+5OT1q+/lC0AucGZUHG2cae56GTDJoOujCkB1Q1fdh64sjRS+2Mm1"
    "GyEIg5bq9AU9kZ3G14af9B1x9yYizUKhfOODUMu2UdOouEac4USNI/Zf/k+OnhQnQ4Om9k12BdA";
static const char token_password[] = "hIrH0fD9ha/MbJHvMD4+Q0poQHaRc4+Y";
static const char wrong_password[] = "wrongwrongwrongwrongwrongwrong";

static atomic_uint calls;
static atomic_uint_fast64_t last_id;

static void incoming(const juice_mux_pending_request_t *request, void *ptr) {
	(void)ptr;
	atomic_store(&last_id, request->request_id);
	atomic_fetch_add(&calls, 1);
}

static uint64_t await_calls(unsigned int count) {
	for (int i = 0; i < 400 && atomic_load(&calls) < count; ++i) usleep(5000);
	assert(atomic_load(&calls) == count);
	return atomic_load(&last_id);
}

static int admit(uint16_t port, const char *prefix) {
	juice_mux_admission_key_t key = {prefix, secret, strlen(secret)};
	// The context ends with the NUL separating it from the ufrag.
	juice_mux_admission_t admission = {context, sizeof(context), &key, prefix ? 1 : 0};
	return juice_mux_set_admission("127.0.0.1", port, &admission);
}

static uint16_t listen_pending(void) {
	atomic_store(&calls, 0);
	uint16_t port = test_port();
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, incoming, NULL) == 0);
	return port;
}

static void stop(uint16_t port) {
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, NULL, NULL) == 0);
}

// Only a request signed with its key's derived password is held, and the application derives
// the same password.
static void keyed(void) {
	uint16_t port = listen_pending(), a, b, c, d;
	int forged = test_socket(&a), unknown_key = test_socket(&b), unknown = test_socket(&c),
	    valid = test_socket(&d);
	assert(admit(port, "NXS1K001") == 0);
	char other_key[sizeof(token)];
	strcpy(other_key, token);
	other_key[7] = '2';
	test_send(forged, port, token, "clientFixtureUf", wrong_password);
	test_send(unknown_key, port, other_key, "clientFixtureUf", token_password);
	test_send(unknown, port, "unknown", "peer", test_password);
	juice_mux_stats_t stats = test_received(port, 3);
	assert(stats.rejected == 3 && stats.pending == 0 && atomic_load(&calls) == 0);
	assert(!test_answered(forged) && !test_answered(unknown));
	test_send(valid, port, token, "clientFixtureUf", token_password);
	uint64_t id = await_calls(1);
	assert(juice_mux_verify_request("127.0.0.1", port, id, token_password) == 0);
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == 0);
	assert(stats.pending == 1 && stats.rejected == 3);
	assert(juice_mux_reject_request("127.0.0.1", port, id) == 0);
	stop(port);
	close(valid);
	close(unknown);
	close(unknown_key);
	close(forged);
}

// A replaced key set drops the old key, and no admission holds everything again.
static void replaced(void) {
	uint16_t port = listen_pending(), a, b;
	int retired = test_socket(&a), open_again = test_socket(&b);
	assert(admit(port, "NXS1K001") == 0);
	assert(admit(port, "NXS1K002") == 0);
	test_send(retired, port, token, "clientFixtureUf", token_password);
	juice_mux_stats_t stats = test_received(port, 1);
	assert(stats.rejected == 1 && atomic_load(&calls) == 0);
	assert(juice_mux_set_admission("127.0.0.1", port, NULL) == 0);
	test_send(open_again, port, "unknown", "peer", wrong_password);
	await_calls(1);
	stop(port);
	close(open_again);
	close(retired);
}

// Requests for an agent the application already owns pass with that agent's password.
static void existing_agent(void) {
	uint16_t port = listen_pending(), a, b;
	int wrong = test_socket(&a), right = test_socket(&b);
	assert(admit(port, NULL) == 0);
	juice_agent_t *agent = test_agent(port);
	test_send(wrong, port, "host", "peer", wrong_password);
	juice_mux_stats_t stats = test_received(port, 1);
	assert(stats.rejected == 1 && atomic_load(&calls) == 0);
	test_send(right, port, "host", "peer", test_password);
	uint64_t id = await_calls(1);
	assert(juice_mux_verify_request("127.0.0.1", port, id, test_password) == 0);
	assert(juice_mux_attach_request("127.0.0.1", port, id, agent) == 0);
	test_response(right);
	juice_destroy(agent);
	stop(port);
	close(right);
	close(wrong);
}

// Stopping the listener clears the admission, and invalid settings change nothing.
static void lifecycle(void) {
	uint16_t port = listen_pending(), a;
	int fd = test_socket(&a);
	juice_mux_admission_key_t keys[9];
	for (int i = 0; i < 9; ++i) keys[i] = (juice_mux_admission_key_t){"NXS1", secret, strlen(secret)};
	juice_mux_admission_t too_many = {context, sizeof(context), keys, 9};
	assert(juice_mux_set_admission("127.0.0.1", port, &too_many) == JUICE_ERR_INVALID);
	keys[0].secret_size = 65;
	juice_mux_admission_t long_secret = {context, sizeof(context), keys, 1};
	assert(juice_mux_set_admission("127.0.0.1", port, &long_secret) == JUICE_ERR_INVALID);
	assert(admit(port, "NXS1K001") == 0);
	stop(port);
	assert(admit(port, "NXS1K001") == JUICE_ERR_NOT_AVAIL);
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, incoming, NULL) == 0);
	test_send(fd, port, "unknown", "peer", wrong_password);
	await_calls(1);
	stop(port);
	close(fd);
}

int main(void) {
	juice_set_log_level(JUICE_LOG_LEVEL_FATAL);
	keyed();
	replaced();
	existing_agent();
	lifecycle();
	puts("mux admission: keyed and agent passwords held, forged and unknown requests dropped, "
	     "keys replaced and cleared PASS");
}

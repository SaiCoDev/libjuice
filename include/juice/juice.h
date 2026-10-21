/**
 * Copyright (c) 2020-2022 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_H
#define JUICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef JUICE_STATIC // dynamic library
#  ifdef _WIN32
#    ifdef JUICE_EXPORTS
#      define JUICE_EXPORT __declspec(dllexport) // building the library
#    else
#      define JUICE_EXPORT __declspec(dllimport) // using the library
#    endif
#  else // not WIN32
#    if defined(__has_attribute)
#      if __has_attribute(visibility)
#        define JUICE_EXPORT __attribute__((visibility("default")))
#      endif
#    endif
#  endif
#endif
#ifndef JUICE_EXPORT
#  define JUICE_EXPORT
#endif

#define JUICE_ERR_SUCCESS 0
#define JUICE_ERR_INVALID -1   // invalid argument
#define JUICE_ERR_FAILED -2    // runtime error
#define JUICE_ERR_NOT_AVAIL -3 // element not available
#define JUICE_ERR_IGNORED -4   // ignored
#define JUICE_ERR_AGAIN -5     // buffer full
#define JUICE_ERR_TOO_LARGE -6 // datagram too large

// ICE Agent

#define JUICE_MAX_ADDRESS_STRING_LEN 64
#define JUICE_MAX_CANDIDATE_SDP_STRING_LEN 256
#define JUICE_MAX_SDP_STRING_LEN 4096

typedef struct juice_agent juice_agent_t;

typedef enum juice_stun_binding_state {
	JUICE_STUN_BINDING_PENDING = 0,
	JUICE_STUN_BINDING_SUCCEEDED,
	JUICE_STUN_BINDING_FAILED
} juice_stun_binding_state_t;

/** Latest observation from one resolved STUN server, independent of ICE peers.
 * Addresses are numeric, without a port. An empty mapped address and UINT64_MAX
 * age mean no successful observation. Ages use the library's monotonic clock.
 * A mapping is an observation, not proof of reachability or a NAT lease: callers
 * decide how old an observation may be. Reading never refreshes its age.
 */
typedef struct juice_stun_binding {
	char server_address[JUICE_MAX_ADDRESS_STRING_LEN];
	uint16_t server_port;
	char mapped_address[JUICE_MAX_ADDRESS_STRING_LEN];
	uint16_t mapped_port;
	juice_stun_binding_state_t state;
	uint64_t successful_responses;
	uint64_t failed_transactions;
	uint64_t mapping_revision;
	uint64_t last_success_age_ms;
} juice_stun_binding_t;

typedef enum juice_state {
	JUICE_STATE_DISCONNECTED = 0,
	JUICE_STATE_GATHERING,
	JUICE_STATE_CONNECTING,
	JUICE_STATE_CONNECTED,
	JUICE_STATE_COMPLETED,
	JUICE_STATE_FAILED
} juice_state_t;

typedef void (*juice_cb_state_changed_t)(juice_agent_t *agent, juice_state_t state, void *user_ptr);
typedef void (*juice_cb_candidate_t)(juice_agent_t *agent, const char *sdp, void *user_ptr);
typedef void (*juice_cb_gathering_done_t)(juice_agent_t *agent, void *user_ptr);
typedef void (*juice_cb_recv_t)(juice_agent_t *agent, const char *data, size_t size,
                                void *user_ptr);

typedef struct juice_mux_binding_request {
	const char *local_ufrag;
	const char *remote_ufrag;

	const char *address;
	uint16_t port;
} juice_mux_binding_request_t;

typedef void (*juice_cb_mux_incoming_t)(const juice_mux_binding_request_t *info, void *user_ptr);

typedef struct juice_mux_pending_request {
	uint64_t request_id;
	juice_mux_binding_request_t binding;
} juice_mux_pending_request_t;

typedef struct juice_mux_pending_config {
	unsigned int max_pending; // 0 selects 256; maximum 4096
	unsigned int timeout_ms;  // 0 selects 5000; maximum 30000
} juice_mux_pending_config_t;

/** Called once for a pending attempt, outside the UDP registry lock.
 * Metadata is borrowed until the callback returns. Copy it to defer a decision.
 * Keep callbacks short: enqueue application work and return. Request operations
 * may be called here, but stopping this listener from its callback is invalid.
 * Packet bytes remain native. Duplicate requests do not repeat the callback.
 */
typedef void (*juice_cb_mux_pending_t)(const juice_mux_pending_request_t *request,
	                                  void *user_ptr);

typedef struct juice_mux_stats {
	uint64_t received; // Datagrams received from the socket
	uint64_t rejected;
	int agents;        // Currently registered agents
	int mapped_tuples; // Currently authenticated source tuples
	unsigned int pending;
	uint64_t notifications;
	uint64_t duplicates;
} juice_mux_stats_t;


typedef struct juice_turn_server {
	const char *host;
	const char *username;
	const char *password;
	uint16_t port;
} juice_turn_server_t;

typedef enum juice_concurrency_mode {
	JUICE_CONCURRENCY_MODE_POLL = 0, // Connections share a single thread
	JUICE_CONCURRENCY_MODE_MUX,      // Connections are multiplexed on a single UDP socket
	JUICE_CONCURRENCY_MODE_THREAD,   // Each connection runs in its own thread
} juice_concurrency_mode_t;

typedef enum juice_ice_tcp_mode {
	JUICE_ICE_TCP_MODE_NONE = 0, // ICE-TCP is disabled
	JUICE_ICE_TCP_MODE_ACTIVE,   // ICE-TCP will operate as a client
} juice_ice_tcp_mode_t;

typedef struct juice_config {
	juice_concurrency_mode_t concurrency_mode;

	const char *stun_server_host;
	uint16_t stun_server_port;

	juice_turn_server_t *turn_servers;
	int turn_servers_count;

	const char *bind_address;

	uint16_t local_port_range_begin;
	uint16_t local_port_range_end;

	juice_cb_state_changed_t cb_state_changed;
	juice_cb_candidate_t cb_candidate;
	juice_cb_gathering_done_t cb_gathering_done;
	juice_cb_recv_t cb_recv;

	void *user_ptr;

	/** Mux mode only. Behind a pending listener, new sources are admitted through
	 * the listener by default. A direct agent is found by its local ICE ufrag
	 * instead and can never be the target of juice_mux_attach_request.
	 */
	bool mux_direct;

} juice_config_t;

JUICE_EXPORT juice_agent_t *juice_create(const juice_config_t *config);
JUICE_EXPORT void juice_destroy(juice_agent_t *agent);

JUICE_EXPORT int juice_gather_candidates(juice_agent_t *agent);

/** Opt in before gathering to persistent STUN-server monitoring. The default is
 * false. Monitoring retries failed transactions and keeps server bindings warm
 * even after ICE nomination. It uses the agent's actual UDP connection, including
 * its shared MUX socket, and works without a remote description or ICE peer.
 * Normal ICE candidate SDP remains a gathering history; use get_stun_binding for
 * the current mapping. No refresh is performed by get_stun_binding itself.
 */
JUICE_EXPORT int juice_set_stun_monitoring(juice_agent_t *agent, bool enabled);

/** Copy the observation for a zero-based resolved STUN-server index.
 * Returns JUICE_ERR_NOT_AVAIL if the index has no resolved server (including
 * before/during resolution or after resolution failure). Index ordering is
 * stable for the lifetime of the agent; each IPv4/IPv6 server has its own entry.
 */
JUICE_EXPORT int juice_get_stun_binding(juice_agent_t *agent, unsigned int index,
                                       juice_stun_binding_t *binding);
JUICE_EXPORT int juice_get_local_description(juice_agent_t *agent, char *buffer, size_t size);
JUICE_EXPORT int juice_set_remote_description(juice_agent_t *agent, const char *sdp);
JUICE_EXPORT int juice_add_remote_candidate(juice_agent_t *agent, const char *sdp);
JUICE_EXPORT int juice_add_turn_server(juice_agent_t *agent, const juice_turn_server_t *turn_server);
JUICE_EXPORT int juice_set_remote_gathering_done(juice_agent_t *agent);
JUICE_EXPORT int juice_send(juice_agent_t *agent, const char *data, size_t size);
JUICE_EXPORT int juice_send_diffserv(juice_agent_t *agent, const char *data, size_t size, int ds);
JUICE_EXPORT juice_state_t juice_get_state(juice_agent_t *agent);
JUICE_EXPORT int juice_get_selected_candidates(juice_agent_t *agent, char *local, size_t local_size,
                                               char *remote, size_t remote_size);
JUICE_EXPORT int juice_get_selected_addresses(juice_agent_t *agent, char *local, size_t local_size,
                                              char *remote, size_t remote_size);
JUICE_EXPORT int juice_set_local_ice_attributes(juice_agent_t *agent, const char *ufrag, const char *pwd);
JUICE_EXPORT const char *juice_state_to_string(juice_state_t state);
JUICE_EXPORT int juice_mux_listen(const char *bind_address, int local_port, juice_cb_mux_incoming_t cb, void *user_ptr);
/** One exclusive pending or legacy listener per endpoint. NULL config uses defaults.
 * Stop with cb=NULL and the same address/port. Stop cancels unaccepted requests and
 * waits for callbacks; attached agents retain their first packet and continue normally.
 * Request IDs are process-unique and remain invalid after cancellation or stop.
 */
JUICE_EXPORT int juice_mux_listen_pending(const char *bind_address, int local_port,
	const juice_mux_pending_config_t *config, juice_cb_mux_pending_t cb, void *user_ptr);
/** Authenticate and claim the held request before constructing an agent.
 * A failed integrity check discards the request. A second verification fails.
 */
JUICE_EXPORT int juice_mux_verify_request(const char *bind_address, int local_port,
	uint64_t request_id, const char *local_pwd);
/** Attach a configured, gathered mux agent and schedule the held first request.
 * The agent must use this endpoint and match both username fragments and the
 * verified password. Processing takes place on the mux thread, never inline.
 */
JUICE_EXPORT int juice_mux_attach_request(const char *bind_address, int local_port,
	uint64_t request_id, juice_agent_t *agent);
JUICE_EXPORT int juice_mux_reject_request(const char *bind_address, int local_port,
	uint64_t request_id);
JUICE_EXPORT int juice_mux_get_stats(const char *bind_address, int local_port,
                                    juice_mux_stats_t *stats);

JUICE_EXPORT int juice_set_ice_tcp_mode(juice_agent_t *agent, juice_ice_tcp_mode_t ice_tcp_mode);

// ICE server

typedef struct juice_server juice_server_t;

typedef struct juice_server_credentials {
	const char *username;
	const char *password;
	int allocations_quota;
} juice_server_credentials_t;

typedef struct juice_server_config {
	juice_server_credentials_t *credentials;
	int credentials_count;

	int max_allocations;
	int max_peers;

	const char *bind_address;
	const char *external_address;
	uint16_t port;

	uint16_t relay_port_range_begin;
	uint16_t relay_port_range_end;

	const char *realm;

} juice_server_config_t;

JUICE_EXPORT juice_server_t *juice_server_create(const juice_server_config_t *config);
JUICE_EXPORT void juice_server_destroy(juice_server_t *server);

JUICE_EXPORT uint16_t juice_server_get_port(juice_server_t *server);
JUICE_EXPORT int juice_server_add_credentials(juice_server_t *server,
                                              const juice_server_credentials_t *credentials,
                                              unsigned long lifetime_ms);

// Logging

typedef enum juice_log_level {
	JUICE_LOG_LEVEL_VERBOSE = 0,
	JUICE_LOG_LEVEL_DEBUG,
	JUICE_LOG_LEVEL_INFO,
	JUICE_LOG_LEVEL_WARN,
	JUICE_LOG_LEVEL_ERROR,
	JUICE_LOG_LEVEL_FATAL,
	JUICE_LOG_LEVEL_NONE
} juice_log_level_t;

typedef void (*juice_log_cb_t)(juice_log_level_t level, const char *message);

JUICE_EXPORT void juice_set_log_level(juice_log_level_t level);
JUICE_EXPORT void juice_set_log_handler(juice_log_cb_t cb);

#ifdef __cplusplus
}
#endif

#endif

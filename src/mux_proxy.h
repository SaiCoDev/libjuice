/* SPDX-License-Identifier: MPL-2.0 */
#ifndef JUICE_MUX_PROXY_H
#define JUICE_MUX_PROXY_H

#include "addr.h"
#include "thread.h"
#include "timestamp.h"

#include <stddef.h>

// PROXY protocol v2 on a mux endpoint: the listed relays and the clients they speak for.
// Receiving runs on one thread and takes the lock only to add or remove a flow. Routing runs
// under the lock.
typedef struct mux_proxy mux_proxy_t;

// Keeps previous' flows of relays still listed. Returns JUICE_ERR_INVALID if an entry is not a
// numeric address or CIDR range.
int mux_proxy_create(const char *const *relays, size_t count, mutex_t *lock,
                     const mux_proxy_t *previous, mux_proxy_t **proxy);
void mux_proxy_destroy(mux_proxy_t *proxy);

// Strips a listed relay's header and attributes the datagram to the client it declares.
// Returns -1 to drop the datagram.
int mux_proxy_receive(mux_proxy_t *proxy, char **data, size_t *size, addr_record_t *src,
                      timestamp_t now);

// The relay a client is reached through, or dst itself
const addr_record_t *mux_proxy_route(mux_proxy_t *proxy, const addr_record_t *dst);

#endif

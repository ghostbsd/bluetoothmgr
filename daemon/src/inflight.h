/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * inflight.h - operations whose reply arrives later.
 *
 * Create_Connection returns Command_Status immediately and Connection_Complete
 * seconds afterwards. The daemon cannot block waiting for that, so a request
 * is parked here and answered when the passive listener sees the completion.
 *
 * Correlation is by remote address. Connection_Complete carries the bdaddr
 * even when status is non-zero, which is what makes this work for failures as
 * well as successes.
 *
 * Entries also carry a deadline. If a completion never arrives, the tick
 * expires the entry and the client gets a timeout rather than waiting forever.
 */

#ifndef BTMGRD_INFLIGHT_H_
#define	BTMGRD_INFLIGHT_H_

#include <time.h>

#include "btmgr.h"

/*
 * Small on purpose. A user cannot meaningfully have more than a couple of
 * connection attempts running at once, and a bounded table means a client
 * cannot make the daemon allocate by spamming requests.
 */
#define	INFLIGHT_MAX		8

/*
 * Slightly longer than the controller's page timeout, so the controller gets
 * to report its own failure before we give up on it. A page timeout is around
 * 10 seconds by default.
 */
#define	INFLIGHT_TIMEOUT_SEC	20

struct client;

enum inflight_kind {
	INFLIGHT_CONNECT = 1,
	INFLIGHT_DISCONNECT
};

struct inflight {
	int			 used;
	enum inflight_kind	 kind;
	int			 id;		/* the client's request id */
	struct client		*client;	/* who asked. May die first */
	bdaddr_t		 addr;		/* correlation key */
	uint16_t		 handle;	/* for disconnect */
	time_t			 deadline;
};

struct inflight_table {
	struct inflight	e[INFLIGHT_MAX];
};

/*
 * Park a request. Returns 0 on success, -1 if the table is full, which the
 * caller should report as "busy" per SPEC.md B6.
 */
int	inflight_add(struct inflight_table *t, enum inflight_kind kind,
	    int id, struct client *c, const bdaddr_t *addr, uint16_t handle);

/*
 * Find and remove the entry matching this address and kind.
 * Returns a pointer to a detached copy, or NULL if nothing matched.
 * The pointer is valid until the next call.
 */
struct inflight *inflight_take(struct inflight_table *t,
	    enum inflight_kind kind, const bdaddr_t *addr);

/* Same, by connection handle, for disconnect completions. */
struct inflight *inflight_take_handle(struct inflight_table *t,
	    enum inflight_kind kind, uint16_t handle);

/*
 * Expire anything past its deadline. Calls cb once per expired entry.
 * Called from the reconcile tick, so no extra timer is needed.
 */
void	inflight_expire(struct inflight_table *t, time_t now,
	    void (*cb)(const struct inflight *, void *), void *arg);

/*
 * Forget every entry belonging to a client that is going away, so a
 * completion arriving later does not write to freed memory.
 */
void	inflight_drop_client(struct inflight_table *t, const struct client *c);

#endif /* !BTMGRD_INFLIGHT_H_ */

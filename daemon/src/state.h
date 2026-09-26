/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * state.h - the daemon's view of the world, and how it decides it changed.
 */

#ifndef BTMGRD_STATE_H_
#define	BTMGRD_STATE_H_

#include "btmgr.h"

/*
 * One complete snapshot. Small enough to copy by value, which is the whole
 * point: we keep the last snapshot we sent to clients and compare against it
 * rather than tracking dirtiness field by field.
 */
struct state {
	int			adapter_present;
	int			powered;	/* netgraph stack is inited */
	int			discoverable;	/* inquiry scan enabled */
	int			scanning;	/* reserved, always 0 in M2 */

	/*
	 * M2 runs unprivileged, so /etc/bluetooth/hcsecd.conf (mode 0600) is
	 * unreadable and we cannot report paired or has_key honestly. The
	 * flag lets clients tell "not paired" from "we could not look".
	 * M3 sets this once the daemon owns the config.
	 */
	int			config_readable;

	struct btmgr_adapter	adapter;	/* valid if adapter_present */

	struct btmgr_conn	conns[BTMGR_MAX_CONNS];
	int			nconns;
};

/*
 * Rebuild a snapshot from the kernel. Never fails in a way worth propagating:
 * no adapter is an ordinary state, so this always leaves *out usable.
 */
void	state_snapshot(struct state *out);

/* Do two snapshots describe the same world? Non-zero if identical. */
int	state_equal(const struct state *a, const struct state *b);

#endif /* !BTMGRD_STATE_H_ */
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * state.h - the daemon's view of the world, and how it decides it changed.
 */

#ifndef BTMGRD_STATE_H_
#define	BTMGRD_STATE_H_

#include "btmgr.h"
#include "sanitise.h"
#include "store.h"

#define	STATE_MAX_DEVICES	64
#define	STATE_TYPE_SIZE		16

/* One device from the A4 store, as B5's devices array reports it. */
struct state_device {
	uint8_t			addr[BTMGR_ADDR_LEN];
	char			name[BTMGR_NAME_SIZE];
	char			alias[BTMGR_ALIAS_BUFSZ];
	char			type[STATE_TYPE_SIZE];
};

/*
 * One complete snapshot. Small enough to copy by value, which is the whole
 * point: we keep the last snapshot we sent to clients and compare against it
 * rather than tracking dirtiness field by field.
 */
struct state {
	int			adapter_present;
	int			powered;	/* netgraph stack is inited */
	int			discoverable;	/* inquiry scan enabled */
	int			scanning;

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

	struct state_device	devices[STATE_MAX_DEVICES];
	int			ndevices;
};

#define	USB_LOCATION_SIZE	256

/* A8.5.5: the adapter as last read live, kept for while it is powered off. */
struct adapter_cache {
	int			valid;
	int			unit;
	int			details_read;	/* since the unit last came up */
	struct btmgr_adapter	adapter;
	char			location[USB_LOCATION_SIZE];
};

/*
 * Rebuild a snapshot from the kernel. Never fails in a way worth propagating:
 * no adapter is an ordinary state, so this always leaves *out usable.
 */
void	state_snapshot(struct state *out, struct adapter_cache *cache);

/* Fill out->devices from the A4 store. A NULL store gives none. */
void	state_add_devices(struct state *out, const struct store *store);

/* Do two snapshots describe the same world? Non-zero if identical. */
int	state_equal(const struct state *a, const struct state *b);

#endif /* !BTMGRD_STATE_H_ */

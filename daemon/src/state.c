/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * state.c - build a snapshot of the world, and compare two of them.
 *
 * Everything here is unprivileged, per PLAN.md F2. The daemon's entire polling
 * path needs no root; only M3's operations will.
 */

#include <string.h>

#include "state.h"

/*
 * Rebuild a snapshot.
 *
 * Deliberately returns nothing. Every failure here has a sensible "world is
 * empty" reading: no adapter plugged in, or a stack that is not up yet. The
 * applet has to render those states anyway, so turning them into errors would
 * just move the problem.
 */
void
state_snapshot(struct state *out)
{
	struct btmgr_adapter	adapters[BTMGR_MAX_ADAPTERS];
	int			n;

	memset(out, 0, sizeof(*out));

	n = (int)(sizeof(adapters) / sizeof(adapters[0]));
	if (btmgr_adapter_list(adapters, &n) < 0 || n == 0)
		return;

	/*
	 * M2 manages one adapter, the first. Multi-adapter machines exist but
	 * the UI has no way to express them yet, and picking the first is
	 * what hccontrol and bluetooth-config do.
	 */
	out->adapter_present = 1;
	out->adapter = adapters[0];
	out->powered = adapters[0].inited;
	out->discoverable = adapters[0].inquiry_scan;

	/*
	 * A stack that is not inited will refuse the connection list, so skip
	 * it rather than logging a failure every five seconds.
	 */
	if (!out->powered)
		return;

	out->nconns = (int)(sizeof(out->conns) / sizeof(out->conns[0]));
	if (btmgr_conn_list(out->adapter.node, out->conns, &out->nconns) < 0)
		out->nconns = 0;
}

/*
 * Compare two snapshots.
 *
 * Field by field rather than memcmp(), because a struct can carry padding
 * bytes that memcmp() sees but nobody set. Comparing padding would make every
 * tick look like a change.
 */
int
state_equal(const struct state *a, const struct state *b)
{
	int	i;

	if (a->adapter_present != b->adapter_present ||
	    a->powered != b->powered ||
	    a->discoverable != b->discoverable ||
	    a->scanning != b->scanning ||
	    a->config_readable != b->config_readable ||
	    a->nconns != b->nconns)
		return (0);

	if (a->adapter_present) {
		if (strcmp(a->adapter.node, b->adapter.node) != 0 ||
		    strcmp(a->adapter.name, b->adapter.name) != 0 ||
		    !bdaddr_same(&a->adapter.bdaddr, &b->adapter.bdaddr) ||
		    memcmp(a->adapter.devclass, b->adapter.devclass,
			sizeof(a->adapter.devclass)) != 0 ||
		    a->adapter.page_scan != b->adapter.page_scan)
			return (0);
	}

	for (i = 0; i < a->nconns; i++) {
		if (!bdaddr_same(&a->conns[i].bdaddr, &b->conns[i].bdaddr) ||
		    a->conns[i].handle != b->conns[i].handle ||
		    a->conns[i].acl != b->conns[i].acl ||
		    a->conns[i].encrypted != b->conns[i].encrypted ||
		    a->conns[i].master != b->conns[i].master)
			return (0);
	}

	return (1);
}
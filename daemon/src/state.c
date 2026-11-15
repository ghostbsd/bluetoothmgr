/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * state.c - build a snapshot of the world, and compare two of them.
 *
 * Everything here is unprivileged, per SPEC.md C1. The daemon's entire polling
 * path needs no root; only M3's operations will.
 */

#include <sys/types.h>
#include <sys/sysctl.h>

#include <stdio.h>
#include <string.h>

#include "btmgr.h"
#include "state.h"

static int	first_usb_unit(char *location, size_t location_size);
static void	copy_details(struct btmgr_adapter *to,
		    const struct btmgr_adapter *from);

/* What btmgr_adapter_read_details() fills in, and nothing else. */
static void
copy_details(struct btmgr_adapter *to, const struct btmgr_adapter *from)
{

	memcpy(to->name, from->name, sizeof(to->name));
	memcpy(to->devclass, from->devclass, sizeof(to->devclass));
	to->inquiry_scan = from->inquiry_scan;
	to->page_scan = from->page_scan;
}

/*
 * The USB device outlives a stopped stack, so it is what A8.5.4 calls
 * present. Returns the first ubt unit and its location, or -1 if none.
 */
static int
first_usb_unit(char *location, size_t location_size)
{
	char	name[64];
	size_t	length;
	int	unit;

	for (unit = 0; unit < BTMGR_MAX_ADAPTERS; unit++) {
		(void)snprintf(name, sizeof(name), "dev.ubt.%d.%%location",
		    unit);
		length = location_size - 1;
		if (sysctlbyname(name, location, &length, NULL, 0) == 0) {
			location[length] = '\0';
			return (unit);
		}
	}

	return (-1);
}

/*
 * Rebuild a snapshot.
 *
 * Deliberately returns nothing. Every failure here has a sensible "world is
 * empty" reading: no adapter plugged in, or a stack that is not up yet. The
 * applet has to render those states anyway, so turning them into errors would
 * just move the problem.
 */
void
state_snapshot(struct state *out, struct adapter_cache *cache)
{
	struct btmgr_adapter	adapters[BTMGR_MAX_ADAPTERS];
	char			location[USB_LOCATION_SIZE];
	int			n, unit;

	memset(out, 0, sizeof(*out));

	unit = first_usb_unit(location, sizeof(location));
	if (unit < 0 || (cache->valid &&
	    strcmp(cache->location, location) != 0)) {
		cache->valid = 0;
		cache->details_read = 0;
	}
	if (unit < 0)
		return;

	out->adapter_present = 1;

	/*
	 * M2 manages one adapter, the first. Multi-adapter machines exist but
	 * the UI has no way to express them yet, and picking the first is
	 * what hccontrol and bluetooth-config do.
	 */
	n = (int)(sizeof(adapters) / sizeof(adapters[0]));
	if (btmgr_adapter_list(adapters, &n) < 0 || n == 0) {
		cache->details_read = 0;
		if (cache->valid)
			out->adapter = cache->adapter;
		out->adapter.inquiry_scan = 0;
		out->adapter.page_scan = 0;
		(void)snprintf(out->adapter.node, sizeof(out->adapter.node),
		    "ubt%dhci", unit);
		return;
	}

	out->adapter = adapters[0];
	out->powered = adapters[0].inited;

	/* C3.3: the controller is asked once per power-up, never per tick. */
	if (out->powered) {
		if (!cache->details_read &&
		    btmgr_adapter_read_details(&out->adapter) == 0)
			cache->details_read = 1;
		else if (cache->valid) {
			copy_details(&out->adapter, &cache->adapter);
			if (!cache->details_read) {
				out->adapter.inquiry_scan = 0;
				out->adapter.page_scan = 0;
			}
		}
		out->discoverable = out->adapter.inquiry_scan;

		cache->adapter = out->adapter;
		(void)strlcpy(cache->location, location,
		    sizeof(cache->location));
		cache->valid = 1;
	} else {
		cache->details_read = 0;
		/* A8.5.5 covers a stack still starting, too. */
		if (cache->valid) {
			out->adapter = cache->adapter;
			out->adapter.inquiry_scan = 0;
			out->adapter.page_scan = 0;
			out->discoverable = 0;
		}
	}

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

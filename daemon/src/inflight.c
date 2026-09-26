/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * inflight.c - operations whose reply arrives later. See inflight.h.
 *
 * A fixed array rather than a list: it is at most eight entries, a linear
 * scan is faster than chasing pointers at that size, and a fixed array cannot
 * leak. M2 introduced heap ownership deliberately; there is no reason to add
 * more of it here.
 */

#include <string.h>

#include "inflight.h"

/*
 * Storage for the detached copy returned by inflight_take(). Valid until the
 * next call, which the header promises. Returning a copy rather than a
 * pointer into the table means the caller cannot be surprised by the slot
 * being reused while it is still working with it.
 */
static struct inflight	taken;

int
inflight_add(struct inflight_table *t, enum inflight_kind kind, int id,
    struct client *c, const bdaddr_t *addr, uint16_t handle)
{
	int	i;

	for (i = 0; i < INFLIGHT_MAX; i++) {
		if (t->e[i].used)
			continue;

		memset(&t->e[i], 0, sizeof(t->e[i]));
		t->e[i].used = 1;
		t->e[i].kind = kind;
		t->e[i].id = id;
		t->e[i].client = c;
		if (addr != NULL)
			bdaddr_copy(&t->e[i].addr, addr);
		t->e[i].handle = handle;
		t->e[i].deadline = time(NULL) + INFLIGHT_TIMEOUT_SEC;

		return (0);
	}

	return (-1);	/* full: caller reports "busy" */
}

struct inflight *
inflight_take(struct inflight_table *t, enum inflight_kind kind,
    const bdaddr_t *addr)
{
	int	i;

	for (i = 0; i < INFLIGHT_MAX; i++) {
		if (!t->e[i].used || t->e[i].kind != kind)
			continue;
		if (!bdaddr_same(&t->e[i].addr, addr))
			continue;

		taken = t->e[i];
		t->e[i].used = 0;

		return (&taken);
	}

	return (NULL);
}

struct inflight *
inflight_take_handle(struct inflight_table *t, enum inflight_kind kind,
    uint16_t handle)
{
	int	i;

	for (i = 0; i < INFLIGHT_MAX; i++) {
		if (!t->e[i].used || t->e[i].kind != kind)
			continue;
		if (t->e[i].handle != handle)
			continue;

		taken = t->e[i];
		t->e[i].used = 0;

		return (&taken);
	}

	return (NULL);
}

void
inflight_expire(struct inflight_table *t, time_t now,
    void (*cb)(const struct inflight *, void *), void *arg)
{
	struct inflight	copy;
	int		i;

	for (i = 0; i < INFLIGHT_MAX; i++) {
		if (!t->e[i].used || t->e[i].deadline > now)
			continue;

		/*
		 * Copy and clear the slot before calling back. The callback
		 * may queue a reply, which can drop the client, which can
		 * call inflight_drop_client() and walk this same table.
		 * Clearing first keeps that re-entry harmless.
		 */
		copy = t->e[i];
		t->e[i].used = 0;

		if (cb != NULL)
			cb(&copy, arg);
	}
}

void
inflight_drop_client(struct inflight_table *t, const struct client *c)
{
	int	i;

	for (i = 0; i < INFLIGHT_MAX; i++) {
		if (t->e[i].used && t->e[i].client == c)
			t->e[i].used = 0;
	}
}

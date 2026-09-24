/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * adapter.c - enumerate local HCI adapters and read their state.
 *
 * Everything here works unprivileged. bt_devinfo() is a wrapper over nine
 * read-only ioctls, and the three HCI commands we send below are all on the
 * kernel's unprivileged allowlist. See PLAN.md F2.
 *
 * One trap worth knowing about, see PLAN.md F8: the socket bt_devenum() hands
 * to its callback can be read and ioctl'd but NEVER written to. bt_devenum()
 * connect()s that socket once per adapter, and a second connect() on a
 * non-PR_CONNREQUIRED socket makes the kernel sodisconnect() first, which sets
 * SS_CANTSENDMORE. The following connect() restores SS_ISCONNECTED but does
 * not clear it, so every later write returns EPIPE and raises SIGPIPE. That is
 * why adapter_read_extra() opens a socket of its own rather than reusing the
 * one it is given.
 */

#include <errno.h>
#include <string.h>

#include "btmgr.h"

/*
 * Context carried through bt_devenum()'s callback.
 *
 * C has no closures, so the only way to get our own state into a callback is
 * the void * argument the library passes through untouched. This struct is
 * that state.
 */
struct adapter_ctx {
	struct btmgr_adapter	*out;	/* caller's array */
	int			 cap;	/* how many fit */
	int			 count;	/* how many filled so far */
};

static int	adapter_cb(int, struct bt_devinfo const *, void *);
static void	adapter_from_devinfo(struct bt_devinfo const *,
		    struct btmgr_adapter *);
static void	adapter_read_extra(const char *, struct btmgr_adapter *);

/*
 * Fill in the parts of btmgr_adapter that bt_devinfo() already gives us.
 */
static void
adapter_from_devinfo(struct bt_devinfo const *di, struct btmgr_adapter *a)
{
	memset(a, 0, sizeof(*a));

	strlcpy(a->node, di->devname, sizeof(a->node));
	bdaddr_copy(&a->bdaddr, &di->bdaddr);
	a->inited = (di->state & NG_HCI_UNIT_INITED) ? 1 : 0;
}

/*
 * Read the three things bt_devinfo() does not report: the friendly name, the
 * scan enable state, and our own class of device.
 *
 * Opens its own socket. See the note at the top of this file about why the
 * one bt_devenum() provides cannot be written to.
 *
 * Failures here are deliberately not fatal. An adapter whose stack is not yet
 * inited will refuse these commands, and reporting it with an empty name is
 * far more useful than reporting nothing at all. Each field keeps the zero
 * value memset() left behind.
 */
static void
adapter_read_extra(const char *node, struct btmgr_adapter *a)
{
	struct bt_devreq		r;
	ng_hci_read_local_name_rp	name_rp;
	ng_hci_read_scan_enable_rp	scan_rp;
	ng_hci_read_unit_class_rp	class_rp;
	int				s;

	s = bt_devopen(node);
	if (s < 0)
		return;

	/* Friendly name. */
	memset(&r, 0, sizeof(r));
	memset(&name_rp, 0, sizeof(name_rp));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_READ_LOCAL_NAME);
	r.rparam = &name_rp;
	r.rlen = sizeof(name_rp);
	if (bt_devreq(s, &r, 3) == 0 && name_rp.status == 0)
		strlcpy(a->name, (const char *)name_rp.name, sizeof(a->name));

	/*
	 * Scan enable. Bit 0 is inquiry scan, which is what makes us
	 * discoverable. Bit 1 is page scan, which is what lets a paired
	 * device reconnect to us.
	 */
	memset(&r, 0, sizeof(r));
	memset(&scan_rp, 0, sizeof(scan_rp));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_READ_SCAN_ENABLE);
	r.rparam = &scan_rp;
	r.rlen = sizeof(scan_rp);
	if (bt_devreq(s, &r, 3) == 0 && scan_rp.status == 0) {
		a->inquiry_scan = (scan_rp.scan_enable & 0x01) ? 1 : 0;
		a->page_scan = (scan_rp.scan_enable & 0x02) ? 1 : 0;
	}

	/* Our own class of device. */
	memset(&r, 0, sizeof(r));
	memset(&class_rp, 0, sizeof(class_rp));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_READ_UNIT_CLASS);
	r.rparam = &class_rp;
	r.rlen = sizeof(class_rp);
	if (bt_devreq(s, &r, 3) == 0 && class_rp.status == 0)
		memcpy(a->devclass, class_rp.uclass, sizeof(a->devclass));

	bt_devclose(s);
}

/*
 * Called by bt_devenum() once per adapter.
 *
 * The socket argument is deliberately unused: it cannot be written to, per the
 * note at the top of this file, so adapter_read_extra() opens its own.
 *
 * Returns 0 to keep enumerating, 1 to stop. We stop once the caller's array
 * is full rather than walking adapters we have nowhere to put.
 */
static int
adapter_cb(int s, struct bt_devinfo const *di, void *arg)
{
	struct adapter_ctx	*ctx = arg;
	struct btmgr_adapter	*a;

	(void)s;

	if (ctx->count >= ctx->cap)
		return (1);

	a = &ctx->out[ctx->count];
	adapter_from_devinfo(di, a);
	adapter_read_extra(a->node, a);
	ctx->count++;

	return (ctx->count >= ctx->cap ? 1 : 0);
}

/*
 * List every local adapter.
 *
 * out  caller-allocated array
 * n    in: how many fit. out: how many were filled.
 *
 * Returns 0 on success, -1 with errno set on failure. Zero adapters is a
 * success with *n == 0, not an error, since "no dongle plugged in" is an
 * ordinary state the applet has to render.
 */
int
btmgr_adapter_list(struct btmgr_adapter *out, int *n)
{
	struct adapter_ctx	ctx;

	if (out == NULL || n == NULL || *n <= 0) {
		errno = EINVAL;
		return (-1);
	}

	ctx.out = out;
	ctx.cap = *n;
	ctx.count = 0;

	*n = 0;

	if (bt_devenum(adapter_cb, &ctx) < 0)
		return (-1);

	*n = ctx.count;

	return (0);
}

/*
 * Read one adapter by netgraph node name, for example "ubt0hci".
 */
int
btmgr_adapter_get(const char *node, struct btmgr_adapter *out)
{
	struct bt_devinfo	di;

	if (node == NULL || out == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&di, 0, sizeof(di));
	strlcpy(di.devname, node, sizeof(di.devname));

	if (bt_devinfo(&di) < 0)
		return (-1);

	adapter_from_devinfo(&di, out);
	adapter_read_extra(node, out);

	return (0);
}
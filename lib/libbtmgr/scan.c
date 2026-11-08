/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * scan.c - inquiry, plus remote name resolution for what it finds.
 *
 * Inquiry and Remote_Name_Request are both on the kernel's unprivileged
 * allowlist, so scanning works as an ordinary user. Verified: see
 * tools/probe/probe2-privilege.c.
 *
 * Note on the two allocation conventions in play here. bt_devinquiry()
 * allocates an array and hands us ownership, and bt_devremote_name() returns
 * a strdup'd string we must free. Our own API allocates nothing, so this file
 * is where the library's heap meets our caller-provided arrays. Every exit
 * path below has to free what it took.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "btmgr.h"

/*
 * Run an inquiry and resolve the name of everything it finds.
 *
 * node  netgraph node name, or NULL to let libbluetooth pick the first
 * secs  roughly how long to scan. Clamped by libbluetooth to 2..62
 * out   caller-allocated array
 * n     in: how many fit. out: how many were filled.
 *
 * Returns 0 on success, -1 with errno set on failure. Finding nothing is a
 * success with *n == 0.
 *
 * This blocks for the duration of the scan. That is fine for the CLI, and it
 * is why the daemon will drive inquiry from its event loop instead of calling
 * this. See PLAN.md M2.
 */
int
btmgr_scan(const char *node, int secs, struct btmgr_device *out, int *n)
{
	struct bt_devinquiry	*ii = NULL;
	char			*name;
	int			 cap, found, i;

	if (out == NULL || n == NULL || *n <= 0) {
		errno = EINVAL;
		return (-1);
	}

	cap = *n;
	*n = 0;

	if (cap > BTMGR_MAX_SCAN)
		cap = BTMGR_MAX_SCAN;

	/*
	 * bt_devinquiry() allocates ii for us. From here on every return path
	 * owes it a free(). free(NULL) is well defined, so the no-adapter
	 * case where it leaves ii NULL is safe.
	 */
	found = bt_devinquiry(node, secs, cap, &ii);
	if (found < 0)
		return (-1);

	for (i = 0; i < found && i < cap; i++) {
		memset(&out[i], 0, sizeof(out[i]));
		bdaddr_copy(&out[i].bdaddr, &ii[i].bdaddr);
		memcpy(out[i].devclass, ii[i].dev_class,
		    sizeof(out[i].devclass));
		out[i].type = btmgr_class_type(out[i].devclass);

		/*
		 * Resolving a name is a second round trip to the device and
		 * can fail or time out, typically because the device has
		 * already gone back to sleep. An unnamed device is still worth
		 * reporting, so leave the name empty and carry on.
		 *
		 * We reuse the clock offset and page scan mode the inquiry
		 * gave us, which lets the controller skip a page scan and
		 * makes this much faster than a cold lookup.
		 */
		name = bt_devremote_name(node, &ii[i].bdaddr, 0,
		    ii[i].clock_offset, ii[i].pscan_rep_mode,
		    NG_HCI_MANDATORY_PAGE_SCAN_MODE);
		if (name != NULL) {
			strlcpy(out[i].name, name, sizeof(out[i].name));
			free(name);
		}
	}

	*n = i;
	free(ii);

	return (0);
}

/*
 * Start an inquiry and return without waiting. Results arrive on the event
 * socket as Inquiry_Result, then Inquiry_Complete when secs run out.
 */
int
btmgr_inquiry_start(const char *node, int secs)
{
	ng_hci_inquiry_cp	cp;
	int			s, saved;

	if (node == NULL || secs < 1 || secs > BTMGR_INQUIRY_MAX_SEC) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));

	/* The General Inquiry Access Code, 0x9e8b33, low byte first. */
	cp.lap[0] = 0x33;
	cp.lap[1] = 0x8b;
	cp.lap[2] = 0x9e;

	/* Units of 1.28 s, rounded up so the scan is never shorter. */
	cp.inquiry_length = (uint8_t)((secs * 100 + 127) / 128);
	cp.num_responses = 0;		/* no limit */

	s = bt_devopen(node);
	if (s < 0)
		return (-1);

	if (bt_devsend(s, NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
	    NG_HCI_OCF_INQUIRY), &cp, sizeof(cp)) < 0) {
		saved = errno;
		bt_devclose(s);
		errno = saved;
		return (-1);
	}

	bt_devclose(s);

	return (0);
}

/* Synchronous: a cancelled inquiry sends no Inquiry_Complete to wait for. */
int
btmgr_inquiry_cancel(const char *node)
{
	struct bt_devreq		r;
	ng_hci_inquiry_cancel_rp	rp;
	int				s, saved;

	if (node == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&rp, 0, sizeof(rp));
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
	    NG_HCI_OCF_INQUIRY_CANCEL);
	r.rparam = &rp;
	r.rlen = sizeof(rp);

	s = bt_devopen(node);
	if (s < 0)
		return (-1);

	if (bt_devreq(s, &r, 3) < 0) {
		saved = errno;
		bt_devclose(s);
		errno = saved;
		return (-1);
	}

	bt_devclose(s);

	if (rp.status != 0) {
		errno = EIO;
		return (-1);
	}

	return (0);
}

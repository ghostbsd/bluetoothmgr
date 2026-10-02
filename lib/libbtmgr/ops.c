/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * ops.c - privileged HCI operations.
 *
 * Everything here needs root. Per PLAN.md F2 the kernel's security filter
 * allows unprivileged sockets only Read_* commands plus inquiry and remote
 * name resolution; every command below is a write and returns EPERM to a
 * normal user.
 *
 * These live in libbtmgr rather than the daemon because the library boundary
 * is "talks HCI", not "is unprivileged". Keeping them here lets btmgr-probe
 * exercise them from the command line with no daemon involved, which is how
 * they get debugged.
 *
 * On blocking. btmgr_connect_start() deliberately does NOT wait for the
 * connection to complete. Create_Connection returns Command_Status at once and
 * Connection_Complete seconds later, up to the full page timeout when a device
 * is switched off. A daemon that waited would stall its whole event loop, so
 * one unreachable speaker would freeze Bluetooth machine-wide. The caller
 * watches for the completion event instead; see daemon/src/listen.c.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "btmgr.h"

/*
 * All six ACL packet types: DM1, DH1, DM3, DH3, DM5, DH5. Letting the
 * controller pick among all of them is what hccontrol's examples do, and it
 * is what we confirmed works against real hardware.
 */
#define	BTMGR_PKT_TYPE_ALL	0xcc18

/*
 * Ask the controller to page a remote device.
 *
 * Returns 0 once the command has been handed to the controller, which means
 * "accepted", not "connected". Returns -1 with errno set if it could not be
 * sent at all.
 */
int
btmgr_connect_start(const char *node, const bdaddr_t *addr)
{
	ng_hci_create_con_cp	cp;
	int			s, saved;

	if (node == NULL || addr == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	bdaddr_copy(&cp.bdaddr, addr);
	cp.pkt_type = htole16(BTMGR_PKT_TYPE_ALL);

	/*
	 * Page scan repetition mode R0 and the mandatory page scan mode are
	 * the safe defaults when we have no inquiry result to draw them from.
	 * A clock offset of zero means "unknown", which just costs the
	 * controller a little extra time locating the device.
	 */
	cp.page_scan_rep_mode = NG_HCI_SCAN_REP_MODE0;
	cp.page_scan_mode = NG_HCI_MANDATORY_PAGE_SCAN_MODE;
	cp.clock_offset = 0;
	cp.accept_role_switch = 1;

	s = bt_devopen(node);
	if (s < 0)
		return (-1);

	if (bt_devsend(s, NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
	    NG_HCI_OCF_CREATE_CON), &cp, sizeof(cp)) < 0) {
		saved = errno;
		bt_devclose(s);
		errno = saved;
		return (-1);
	}

	bt_devclose(s);

	return (0);
}

/*
 * Tear down a connection by handle.
 *
 * Also fire and forget: Disconnection_Complete arrives on the listener like
 * any other event. Reason 0x13 is "remote user terminated the connection",
 * which is what a user clicking disconnect means.
 */
int
btmgr_disconnect_start(const char *node, uint16_t handle, uint8_t reason)
{
	ng_hci_discon_cp	cp;
	int			s, saved;

	if (node == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.con_handle = htole16(handle);
	cp.reason = reason;

	s = bt_devopen(node);
	if (s < 0)
		return (-1);

	if (bt_devsend(s, NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
	    NG_HCI_OCF_DISCON), &cp, sizeof(cp)) < 0) {
		saved = errno;
		bt_devclose(s);
		errno = saved;
		return (-1);
	}

	bt_devclose(s);

	return (0);
}

/*
 * Set inquiry scan (discoverable) and page scan (connectable).
 *
 * Synchronous, unlike the two above: Write_Scan_Enable completes immediately
 * with a Command_Complete, so there is nothing to wait for beyond the usual
 * command round trip.
 *
 * Note that turning page scan off makes us unreachable even to already-paired
 * devices, so callers that only mean "stop being discoverable" must leave it
 * on.
 */
int
btmgr_set_scan(const char *node, int inquiry_scan, int page_scan)
{
	struct bt_devreq		r;
	ng_hci_write_scan_enable_cp	cp;
	ng_hci_write_scan_enable_rp	rp;
	int				s, saved;

	if (node == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.scan_enable = (uint8_t)((inquiry_scan ? 0x01 : 0) |
	    (page_scan ? 0x02 : 0));

	memset(&rp, 0, sizeof(rp));
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_WRITE_SCAN_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
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

	/*
	 * The command reached the controller but it refused. Translate the
	 * HCI status into errno so callers only have one failure convention
	 * to handle.
	 */
	if (rp.status != 0) {
		errno = EIO;
		return (-1);
	}

	return (0);
}

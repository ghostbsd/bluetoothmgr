/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr.h - BluetoothMgr HCI layer.
 *
 * This is the read-only half of the project. Everything declared here works
 * as an ordinary user: enumeration, adapter state, the connection list and
 * inquiry are all on the kernel's unprivileged allowlist. See PLAN.md F2.
 *
 * Conventions used throughout, fixed here and followed by every later module:
 *
 *   1. The caller provides the array. Functions that return a list take
 *      (T *out, int *n), where *n is the capacity going in and the number
 *      of entries filled coming out. Nothing below allocates on the caller's
 *      behalf, so there is nothing for the caller to free.
 *
 *   2. Return 0 on success, -1 on failure with errno set. Same convention as
 *      libbluetooth, so the two compose without a translation layer.
 *
 *   3. The structs here mirror SPEC.md B5 rather than libbluetooth's, so the
 *      wire protocol is not hostage to a kernel header.
 */

#ifndef BTMGR_H_
#define	BTMGR_H_

#include <sys/types.h>

#include <stdint.h>

/*
 * bluetooth.h emits a #warning unless this is defined first. It is the header
 * author's way of asking you to acknowledge that sockaddr_l2cap grew a field.
 * libbluetooth's own sources do exactly this.
 */
#define	L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

/*
 * Array bounds. These are the sizes a caller must allocate.
 *
 * BTMGR_MAX_CONNS is deliberately not NG_HCI_MAX_CON_NUM, which is 3276 and
 * would be 64KB of stack. A BR/EDR adapter addresses at most 7 active ACL
 * links (the LT_ADDR field is 3 bits), so 32 cannot be reached in practice.
 * The kernel clamps its copyout to whatever capacity we pass, so a smaller
 * value is safe rather than an overflow.
 */
#define	BTMGR_MAX_ADAPTERS	HCI_DEVMAX		/* 32 */
#define	BTMGR_MAX_CONNS		32
#define	BTMGR_MAX_SCAN		64

#define	BTMGR_NAME_SIZE		(NG_HCI_UNIT_NAME_SIZE + 1)	/* 249 */
#define	BTMGR_ADDR_STRSIZE	18	/* "00:11:22:33:44:55" + NUL */

/*
 * Device type, derived from the class of device. SPEC.md B5.3.
 * Provisional vocabulary; expect it to grow.
 */
enum btmgr_type {
	BTMGR_TYPE_UNKNOWN = 0,
	BTMGR_TYPE_COMPUTER,
	BTMGR_TYPE_PHONE,
	BTMGR_TYPE_HEADSET,
	BTMGR_TYPE_HEADPHONES,
	BTMGR_TYPE_SPEAKER,
	BTMGR_TYPE_AV,
	BTMGR_TYPE_KEYBOARD,
	BTMGR_TYPE_MOUSE
};

/* A local HCI adapter. */
struct btmgr_adapter {
	char		node[HCI_DEVNAME_SIZE];	/* netgraph name, "ubt0hci" */
	bdaddr_t	bdaddr;
	char		name[BTMGR_NAME_SIZE];	/* friendly name */
	uint8_t		devclass[NG_HCI_CLASS_SIZE];
	int		inited;			/* stack is up */
	int		inquiry_scan;		/* discoverable */
	int		page_scan;		/* connectable */
};

/* One live baseband connection, as the kernel sees it. */
struct btmgr_conn {
	bdaddr_t	bdaddr;
	uint16_t	handle;
	int		acl;			/* 1 = ACL, 0 = SCO */
	int		encrypted;
	int		master;			/* we are master */
};

/* A remote device seen during inquiry. */
struct btmgr_device {
	bdaddr_t	bdaddr;
	char		name[BTMGR_NAME_SIZE];
	uint8_t		devclass[NG_HCI_CLASS_SIZE];
	enum btmgr_type	type;
};

__BEGIN_DECLS

/* adapter.c */
int		 btmgr_adapter_list(struct btmgr_adapter *, int *);
int		 btmgr_adapter_get(const char *, struct btmgr_adapter *);

/* conn.c */
int		 btmgr_conn_list(const char *, struct btmgr_conn *, int *);

/* scan.c */
int		 btmgr_scan(const char *, int, struct btmgr_device *, int *);

/* class.c */
enum btmgr_type	 btmgr_class_type(const uint8_t *);
const char	*btmgr_type_name(enum btmgr_type);

__END_DECLS

#endif /* !BTMGR_H_ */
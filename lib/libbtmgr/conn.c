/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * conn.c - read the kernel's live baseband connection list.
 *
 * ng_hci keeps the authoritative connection list in the kernel, so this is a
 * single ioctl with no HCI round trip and no waiting on the controller. It
 * needs no privilege.
 */

#include <sys/ioctl.h>

#include <errno.h>
#include <string.h>

#include "btmgr.h"

/*
 * List the adapter's current connections.
 *
 * node  netgraph node name, for example "ubt0hci"
 * out   caller-allocated array
 * n     in: how many fit. out: how many were filled.
 *
 * Returns 0 on success, -1 with errno set on failure. No connections is a
 * success with *n == 0.
 */
int
btmgr_conn_list(const char *node, struct btmgr_conn *out, int *n)
{
	struct ng_btsocket_hci_raw_con_list	cl;
	ng_hci_node_con_ep			raw[BTMGR_MAX_CONNS];
	int					s, cap, i;
	uint32_t				got;

	if (node == NULL || out == NULL || n == NULL || *n <= 0) {
		errno = EINVAL;
		return (-1);
	}

	cap = *n;
	*n = 0;

	/*
	 * Our scratch buffer is fixed, so never ask the kernel for more than
	 * it holds even if the caller offered a larger array.
	 */
	if (cap > BTMGR_MAX_CONNS)
		cap = BTMGR_MAX_CONNS;

	s = bt_devopen(node);
	if (s < 0)
		return (-1);

	/*
	 * num_connections is both an input and an output. Going in it is the
	 * capacity we are offering; coming out it is how many the kernel
	 * actually copied. The kernel takes min() of the two, so a small
	 * capacity truncates safely rather than overflowing. It rejects a
	 * capacity of zero outright, which is why *n <= 0 is refused above.
	 */
	memset(&cl, 0, sizeof(cl));
	memset(raw, 0, sizeof(raw));
	cl.num_connections = (uint32_t)cap;
	cl.connections = raw;

	if (ioctl(s, SIOC_HCI_RAW_NODE_GET_CON_LIST, &cl, sizeof(cl)) < 0) {
		int saved = errno;	/* bt_devclose() may clobber errno */

		bt_devclose(s);
		errno = saved;
		return (-1);
	}

	bt_devclose(s);

	got = cl.num_connections;
	if (got > (uint32_t)cap)
		got = (uint32_t)cap;	/* defensive; the kernel already clamps */

	for (i = 0; i < (int)got; i++) {
		memset(&out[i], 0, sizeof(out[i]));
		bdaddr_copy(&out[i].bdaddr, &raw[i].bdaddr);
		out[i].handle = raw[i].con_handle;
		out[i].acl = (raw[i].link_type == NG_HCI_LINK_ACL) ? 1 : 0;
		out[i].encrypted =
		    (raw[i].encryption_mode != NG_HCI_ENCRYPTION_MODE_NONE)
		    ? 1 : 0;
		out[i].master = (raw[i].role == NG_HCI_ROLE_MASTER) ? 1 : 0;
	}

	*n = i;

	return (0);
}
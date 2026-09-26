/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * listen.c - passive HCI event listener.
 *
 * See listen.h for why this never writes. Two further notes:
 *
 * PLAN.md F2: an unprivileged socket is refused Link_Key_Notification,
 * Return_Link_Keys and Vendor events by the kernel's security filter. We ask
 * for the first anyway, because as root we want it and as a normal user the
 * kernel simply never delivers it. Asking is not an error.
 *
 * PLAN.md F8: this socket comes from bt_devopen(), which connect()s exactly
 * once, so it does not suffer the unwritable-socket defect. We never write to
 * it regardless.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "btmgr.h"
#include "listen.h"

/*
 * Events we care about. Every one of these can change what a client should be
 * seeing, except PIN_Code_Request, which is there so the settings window can
 * honestly report "pairing in progress".
 */
static const uint8_t	watched[] = {
	NG_HCI_EVENT_CON_COMPL,
	NG_HCI_EVENT_DISCON_COMPL,
	NG_HCI_EVENT_CON_REQ,
	NG_HCI_EVENT_AUTH_COMPL,
	NG_HCI_EVENT_ENCRYPTION_CHANGE,
	NG_HCI_EVENT_PIN_CODE_REQ,
	NG_HCI_EVENT_LINK_KEY_REQ,
	NG_HCI_EVENT_LINK_KEY_NOTIFICATION
};

int
listen_open(const char *node)
{
	struct bt_devfilter	f;
	size_t			i;
	int			s;

	s = bt_devopen(node);
	if (s < 0)
		return (-1);

	/*
	 * Start from the socket's current filter rather than a zeroed one, so
	 * we keep the Command_Complete and Command_Status bits the kernel sets
	 * by default and only add to them.
	 */
	if (bt_devfilter(s, NULL, &f) < 0)
		goto fail;

	bt_devfilter_pkt_set(&f, NG_HCI_EVENT_PKT);
	for (i = 0; i < sizeof(watched) / sizeof(watched[0]); i++)
		bt_devfilter_evt_set(&f, watched[i]);

	if (bt_devfilter(s, &f, NULL) < 0)
		goto fail;

	/*
	 * Non-blocking: the kqueue loop must never stall inside a read, even
	 * if it was told the socket was readable and the data then vanished.
	 */
	if (fcntl(s, F_SETFL, O_NONBLOCK) < 0)
		goto fail;

	return (s);

fail:
	{
		int saved = errno;

		bt_devclose(s);
		errno = saved;
	}
	return (-1);
}

void
listen_close(int fd)
{
	if (fd >= 0)
		bt_devclose(fd);
}

/*
 * Read and interpret everything queued on the socket.
 *
 * Loops until EAGAIN, because kqueue is edge-ish enough in practice that
 * leaving data unread risks not being woken again for it.
 */
int
listen_drain(int fd)
{
	uint8_t				buf[512];
	ng_hci_event_pkt_t		*e;
	ssize_t				 n;
	int				 changed = 0;

	for (;;) {
		n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				break;		/* drained */
			return (-1);
		}
		if (n == 0)
			return (-1);		/* socket died */

		if ((size_t)n < sizeof(*e))
			continue;		/* runt, ignore */

		e = (ng_hci_event_pkt_t *)buf;
		if (e->type != NG_HCI_EVENT_PKT)
			continue;

		switch (e->event) {
		case NG_HCI_EVENT_CON_COMPL:
		case NG_HCI_EVENT_DISCON_COMPL:
		case NG_HCI_EVENT_ENCRYPTION_CHANGE:
			changed = 1;
			break;

		case NG_HCI_EVENT_AUTH_COMPL:
			syslog(LOG_DEBUG, "authentication complete");
			changed = 1;
			break;

		case NG_HCI_EVENT_CON_REQ:
			syslog(LOG_DEBUG, "incoming connection request");
			break;

		/*
		 * Observed, never answered. hcsecd replies to these. See
		 * PLAN.md F3 and F7.
		 */
		case NG_HCI_EVENT_PIN_CODE_REQ:
			syslog(LOG_INFO, "PIN code requested, hcsecd is "
			    "answering");
			break;

		case NG_HCI_EVENT_LINK_KEY_REQ:
			syslog(LOG_DEBUG, "link key requested");
			break;

		/*
		 * Root only. Its arrival means hcsecd just learned a key, and
		 * per F7 that key is only kept if the device already has a
		 * block in hcsecd.conf. M3 acts on this; for now it is the
		 * single most diagnostic line in the log.
		 */
		case NG_HCI_EVENT_LINK_KEY_NOTIFICATION:
			syslog(LOG_INFO, "link key notification received");
			changed = 1;
			break;

		default:
			break;
		}
	}

	return (changed);
}
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * devd.h - ubt attach and detach from devd's event socket. SPEC.md C3.4.
 */

#ifndef BTMGRD_DEVD_H_
#define	BTMGRD_DEVD_H_

enum devd_event {
	DEVD_ATTACH = 1,
	DEVD_DETACH
};

/* Returns a non-blocking descriptor, or -1 with errno set. */
int	devd_open(void);

/*
 * Read every queued message and call cb for each ubt attach or detach.
 * Returns 0 once drained, or -1 if devd closed the socket.
 */
int	devd_drain(int fd, void (*cb)(enum devd_event event, int unit,
	    void *arg), void *arg);

#endif

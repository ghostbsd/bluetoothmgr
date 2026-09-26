/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * listen.h - passive HCI event listener.
 *
 * A raw HCI socket that only ever reads. PLAN.md F3: the kernel broadcasts
 * every event to every raw socket whose bind address and filter match, so we
 * can watch exactly what hcsecd watches without disturbing it.
 *
 * It must never reply. hcsecd owns the pairing replies in v1, and two agents
 * answering one PIN_Code_Request means the second gets Command_Disallowed.
 */

#ifndef BTMGRD_LISTEN_H_
#define	BTMGRD_LISTEN_H_

/*
 * Open a listening socket on the given netgraph node, for example "ubt0hci".
 * Returns a file descriptor, or -1 with errno set.
 */
int	listen_open(const char *node);

/*
 * Drain whatever has arrived and interpret it.
 *
 * Returns 1 if something happened that could have changed the world, so the
 * caller should rebuild its snapshot. Returns 0 if nothing relevant arrived,
 * and -1 if the socket died and should be closed and reopened.
 */
int	listen_drain(int fd);

void	listen_close(int fd);

#endif /* !BTMGRD_LISTEN_H_ */
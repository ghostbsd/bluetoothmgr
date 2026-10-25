/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * ipc.h - Unix socket server. SPEC.md A5 and B1.
 *
 * One JSON object per line. Both directions are non-blocking, so a client
 * that stops reading cannot stall the daemon.
 */

#ifndef BTMGRD_IPC_H_
#define	BTMGRD_IPC_H_

#include <sys/time.h>
#include <sys/types.h>

#include <stddef.h>

/*
 * Drop a client whose unsent output grows past this. A client that will not
 * drain is either wedged or hostile, and either way we would rather lose it
 * than grow without bound. SPEC.md A5 implies this; B1.3 caps the input side.
 */
#define	IPC_OUT_MAX	((size_t)256 * 1024)

struct client {
	int		 fd;

	char		*in;		/* input buffer, grows to a line */
	size_t		 in_len;
	size_t		 in_cap;
	size_t		 in_taken;	/* front bytes already handed out */

	char		*out;		/* output not yet written */
	size_t		 out_len;
	size_t		 out_cap;

	int		 want_write;	/* EVFILT_WRITE is currently enabled */

	/* Peer credentials, from LOCAL_PEERCRED. A5.3 needs the pid. */
	uid_t		 uid;
	gid_t		 gid;
	pid_t		 pid;		/* -1 when the kernel did not report one */

	/* A5.5. Who sent the bytes now buffered, from SCM_CREDS2. */
	pid_t		 send_pid;
	uid_t		 send_uid;	/* (uid_t)-1 when none was reported */
	int		 send_mixed;	/* more than one sender in one line */

	/* The A5.3 verdict at accept, for the cap only. Commands recheck. */
	int		 peer_in_gui_session;

	/* A5.4. Monotonic, when a sender A5.3 admitted last sent. 0 = never. */
	time_t		 lease;

	struct client	*next;
};

/*
 * Create and bind the listening socket. Unlinks a stale one first, per
 * SPEC.md A5.2. Returns a non-blocking listening fd, or -1 with errno set.
 */
int		 ipc_listen(const char *path, mode_t mode);

/* Accept one client. Returns NULL with errno set on failure. */
struct client	*ipc_accept(int lfd);

/* Free a client and close its fd. The only place client memory is released. */
void		 ipc_client_free(struct client *c);

/*
 * Read whatever has arrived into the client's input buffer.
 * Returns 0 normally, -1 if the client closed or must be dropped.
 */
int		 ipc_client_read(struct client *c);

/*
 * Pull the next complete line out of the input buffer.
 *
 * Returns 1 and points *line at it (without the newline, NUL terminated) if
 * one is available, 0 if not. The pointer is valid only until the next call
 * on this client.
 */
int		 ipc_client_line(struct client *c, char **line, size_t *len);

/*
 * Queue a line for sending, then try to flush immediately. Takes a plain
 * string; the caller keeps ownership of it.
 * Returns 0 on success, -1 if the client must be dropped.
 */
int		 ipc_client_send(struct client *c, const char *data);

/*
 * Push out whatever is buffered. Returns 0 on success, -1 if the client must
 * be dropped. After this, c->want_write says whether EVFILT_WRITE should be
 * enabled for this client.
 */
int		 ipc_client_flush(struct client *c);

#endif /* !BTMGRD_IPC_H_ */

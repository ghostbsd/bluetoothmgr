/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * ipc_client.h - the client end of the daemon socket. SPEC.md A5, B1.
 *
 * Owns no event loop and never blocks after connecting: the caller watches
 * btmgr_ipc_fd() in its own loop, GLib in the applet or kqueue elsewhere.
 * Framing is common/linebuf.c. Nothing here knows what the JSON means.
 */

#ifndef BTMGR_IPC_CLIENT_H_
#define	BTMGR_IPC_CLIENT_H_

#include <stddef.h>

#include "proto.h"

/* Must match the daemon's DEFAULT_SOCKET in daemon/src/main.c. */
#define	BTMGR_SOCKET_PATH	"/var/run/bluetoothmgr.sock"

/*
 * A frontend cannot usefully have many commands outstanding, and a bounded
 * table means a buggy one cannot grow this without limit.
 */
#define	BTMGR_MAX_PENDING_REQUESTS	16

struct btmgr_ipc;

/*
 * Called once per request, which B3.2 guarantees. On a lost connection every
 * pending request is failed with error_code "io_error" so a frontend never
 * waits forever for a daemon that has gone.
 */
typedef void (*btmgr_reply_fn)(const struct proto_msg *reply, void *user_data);

typedef void (*btmgr_event_fn)(const struct proto_msg *event, void *user_data);

/*
 * path NULL selects BTMGR_SOCKET_PATH. NULL with ENOENT or ECONNREFUSED means
 * the daemon is not running, which a frontend should treat as retry-later
 * rather than as an error to show the user.
 */
struct btmgr_ipc *btmgr_ipc_open(const char *path);

/* NULL is accepted. */
void		  btmgr_ipc_close(struct btmgr_ipc *conn);

int		  btmgr_ipc_fd(const struct btmgr_ipc *conn);
int		  btmgr_ipc_has_unwritten(const struct btmgr_ipc *conn);

/* line must already end in '\n'. -1 means close and reopen. */
int		  btmgr_ipc_send(struct btmgr_ipc *conn, const char *line);

int		  btmgr_ipc_flush(struct btmgr_ipc *conn);

/* -1 means close and reopen; errno 0 is the clean close of a daemon restart. */
int		  btmgr_ipc_fill(struct btmgr_ipc *conn);

/* *line stays valid until the next call on this connection. */
int		  btmgr_ipc_next_line(struct btmgr_ipc *conn, char **line,
		      size_t *len);

/*
 * Send a command and register on_reply for its answer. cmd->id is assigned
 * here, so B3.1 uniqueness holds without the caller tracking ids. Returns 0,
 * -1 with EBUSY when BTMGR_MAX_PENDING_REQUESTS are already outstanding, and
 * -1 otherwise for an unencodable command or a dead connection.
 */
int		  btmgr_ipc_request(struct btmgr_ipc *conn,
		      struct proto_cmd *cmd, btmgr_reply_fn on_reply,
		      void *user_data);

/*
 * Read and route everything that has arrived: replies to the callback their
 * request registered, events to on_event, which may be NULL. Returns 0, or -1
 * when the connection is finished, in which case every pending reply callback
 * has already been failed and the caller should close and reopen.
 */
int		  btmgr_ipc_dispatch(struct btmgr_ipc *conn,
		      btmgr_event_fn on_event, void *user_data);

/* How many requests are waiting for a reply. */
int		  btmgr_ipc_pending_count(const struct btmgr_ipc *conn);

#endif

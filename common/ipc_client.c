/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * ipc_client.c - connect to the daemon socket. See ipc_client.h.
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ipc_client.h"
#include "linebuf.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"	/* IWYU pragma: keep */

struct pending_request {
	int		 in_use;
	int		 request_id;
	btmgr_reply_fn	 on_reply;
	void		*user_data;
};

struct btmgr_ipc {
	int			 fd;
	struct linebuf		 buf;
	struct pending_request	 pending[BTMGR_MAX_PENDING_REQUESTS];
	unsigned int		 next_request_id;
};

static struct pending_request	*claim_slot(struct btmgr_ipc *conn);
static void			 fail_all_pending(struct btmgr_ipc *conn);
static void			 deliver_reply(struct btmgr_ipc *conn,
				     const struct proto_msg *reply);

/*
 * A free slot with an id no other slot is using. The counter alone is not
 * enough: it wraps, and a long-lived frontend could reach an id still
 * outstanding, which B3.1 forbids.
 */
static struct pending_request *
claim_slot(struct btmgr_ipc *conn)
{
	struct pending_request	*slot = NULL;
	int			 candidate, taken, i, tries;

	for (i = 0; i < BTMGR_MAX_PENDING_REQUESTS; i++) {
		if (!conn->pending[i].in_use) {
			slot = &conn->pending[i];
			break;
		}
	}
	if (slot == NULL) {
		errno = EBUSY;
		return (NULL);
	}

	for (tries = 0; tries <= BTMGR_MAX_PENDING_REQUESTS; tries++) {
		/* Keep it positive: the parser refuses a negative id. */
		candidate = (int)(conn->next_request_id++ & 0x7fffffff);

		taken = 0;
		for (i = 0; i < BTMGR_MAX_PENDING_REQUESTS; i++) {
			if (conn->pending[i].in_use &&
			    conn->pending[i].request_id == candidate) {
				taken = 1;
				break;
			}
		}
		if (!taken) {
			slot->request_id = candidate;
			return (slot);
		}
	}

	errno = EBUSY;

	return (NULL);
}

static void
fail_all_pending(struct btmgr_ipc *conn)
{
	struct proto_msg	 failure;
	int			 i;

	for (i = 0; i < BTMGR_MAX_PENDING_REQUESTS; i++) {
		struct pending_request	*slot = &conn->pending[i];
		btmgr_reply_fn		 callback;
		void			*user_data;

		if (!slot->in_use)
			continue;

		memset(&failure, 0, sizeof(failure));
		failure.kind = PROTO_MSG_REPLY;
		failure.request_id = slot->request_id;
		failure.succeeded = 0;
		strlcpy(failure.error_code, "io_error",
		    sizeof(failure.error_code));
		strlcpy(failure.error_detail, "the daemon connection closed",
		    sizeof(failure.error_detail));

		callback = slot->on_reply;
		user_data = slot->user_data;

		/* Released first, so the callback may issue a new request. */
		memset(slot, 0, sizeof(*slot));

		if (callback != NULL)
			callback(&failure, user_data);
	}
}

static void
deliver_reply(struct btmgr_ipc *conn, const struct proto_msg *reply)
{
	int	 i;

	for (i = 0; i < BTMGR_MAX_PENDING_REQUESTS; i++) {
		struct pending_request	*slot = &conn->pending[i];
		btmgr_reply_fn		 callback;
		void			*user_data;

		if (!slot->in_use || slot->request_id != reply->request_id)
			continue;

		callback = slot->on_reply;
		user_data = slot->user_data;
		memset(slot, 0, sizeof(*slot));

		if (callback != NULL)
			callback(reply, user_data);

		return;
	}

	/* A reply to nothing: a late duplicate, or a daemon bug. Ignore it. */
}

struct btmgr_ipc *
btmgr_ipc_open(const char *path)
{
	struct btmgr_ipc	*conn;
	struct sockaddr_un	 sa;
	int			 fd, saved;

	if (path == NULL)
		path = BTMGR_SOCKET_PATH;

	if (strlen(path) >= sizeof(sa.sun_path)) {
		errno = ENAMETOOLONG;
		return (NULL);
	}

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL)
		return (NULL);

	/* A frontend that execs anything must not leak the daemon channel. */
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		saved = errno;
		free(conn);
		errno = saved;
		return (NULL);
	}

	/*
	 * Without this, writing to a daemon that has exited kills the whole
	 * frontend with SIGPIPE. The daemon ignores SIGPIPE process-wide, but
	 * a library cannot assume its caller did, and a panel applet dying
	 * because bluetoothmgrd restarted is not acceptable. Set on the socket
	 * rather than via MSG_NOSIGNAL so linebuf.c stays fd-generic.
	 */
	{
		int	on = 1;

		if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on,
		    sizeof(on)) != 0) {
			saved = errno;
			(void)close(fd);
			free(conn);
			errno = saved;
			return (NULL);
		}
	}

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, path, sizeof(sa.sun_path));

	/*
	 * Connect while still blocking. An AF_UNIX connect to a listening
	 * socket completes in the kernel and a missing daemon fails at once,
	 * so the EINPROGRESS dance TCP needs would be dead code. O_NONBLOCK
	 * goes on after, for the reads and writes that can really block.
	 */
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
		saved = errno;
		(void)close(fd);
		free(conn);
		errno = saved;
		return (NULL);
	}

	conn->fd = fd;
	linebuf_init(&conn->buf);

	return (conn);
}

void
btmgr_ipc_close(struct btmgr_ipc *conn)
{

	if (conn == NULL)
		return;

	linebuf_free(&conn->buf);
	if (conn->fd >= 0)
		(void)close(conn->fd);
	free(conn);
}

int
btmgr_ipc_fd(const struct btmgr_ipc *conn)
{

	return (conn->fd);
}

int
btmgr_ipc_has_unwritten(const struct btmgr_ipc *conn)
{

	return (conn->buf.has_unwritten);
}

int
btmgr_ipc_send(struct btmgr_ipc *conn, const char *line)
{

	return (linebuf_send(&conn->buf, conn->fd, line));
}

int
btmgr_ipc_flush(struct btmgr_ipc *conn)
{

	return (linebuf_flush(&conn->buf, conn->fd));
}

int
btmgr_ipc_fill(struct btmgr_ipc *conn)
{

	return (linebuf_fill(&conn->buf, conn->fd));
}

int
btmgr_ipc_next_line(struct btmgr_ipc *conn, char **line, size_t *len)
{

	return (linebuf_next_line(&conn->buf, line, len));
}

int
btmgr_ipc_request(struct btmgr_ipc *conn, struct proto_cmd *cmd,
    btmgr_reply_fn on_reply, void *user_data)
{
	struct pending_request	*slot;
	char			*line;
	int			 saved;

	if (conn == NULL || cmd == NULL) {
		errno = EINVAL;
		return (-1);
	}

	slot = claim_slot(conn);
	if (slot == NULL)
		return (-1);

	cmd->id = slot->request_id;

	line = proto_encode_cmd(cmd);
	if (line == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Register before sending. A reply cannot arrive before send returns
	 * on this thread, but registering first means no ordering to reason
	 * about, and the failure path below unregisters.
	 */
	slot->in_use = 1;
	slot->on_reply = on_reply;
	slot->user_data = user_data;

	if (btmgr_ipc_send(conn, line) != 0) {
		saved = errno;
		free(line);

		/*
		 * The connection is unusable, so earlier requests will never be
		 * answered either. Failing only this one leaves their callbacks
		 * waiting for a reply that cannot come.
		 */
		memset(slot, 0, sizeof(*slot));
		fail_all_pending(conn);

		errno = saved;
		return (-1);
	}

	free(line);

	return (0);
}

int
btmgr_ipc_dispatch(struct btmgr_ipc *conn, btmgr_event_fn on_event,
    void *user_data)
{
	struct proto_msg	 msg;
	char			*line;
	size_t			 len;
	int			 filled, saved;

	if (conn == NULL) {
		errno = EINVAL;
		return (-1);
	}

	filled = btmgr_ipc_fill(conn);
	saved = errno;

	/*
	 * Drain what did arrive before reporting the close. A daemon that
	 * exits right after answering still gets its reply delivered.
	 */
	while (btmgr_ipc_next_line(conn, &line, &len) == 1) {
		if (proto_parse_msg(line, len, &msg) != 0)
			continue;		/* not ours to understand */

		if (msg.kind == PROTO_MSG_REPLY)
			deliver_reply(conn, &msg);
		else if (on_event != NULL)
			on_event(&msg, user_data);
	}

	if (filled != 0) {
		fail_all_pending(conn);
		errno = saved;
		return (-1);
	}

	return (0);
}

int
btmgr_ipc_pending_count(const struct btmgr_ipc *conn)
{
	int	 count = 0, i;

	for (i = 0; i < BTMGR_MAX_PENDING_REQUESTS; i++) {
		if (conn->pending[i].in_use)
			count++;
	}

	return (count);
}

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * ipc_client.c - connect to the daemon socket. See ipc_client.h.
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ipc_client.h"
#include "linebuf.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"	/* IWYU pragma: keep */

struct pending_request {
	int		 in_use;
	int		 request_id;
	time_t		 deadline;
	btmgr_reply_fn	 on_reply;
	void		*user_data;
};

enum handshake {
	HANDSHAKE_WAITING = 0,
	HANDSHAKE_AGREED,
	HANDSHAKE_REFUSED
};

struct btmgr_ipc {
	int			 fd;
	struct linebuf		 buf;
	struct pending_request	 pending[BTMGR_MAX_PENDING_REQUESTS];
	unsigned int		 next_request_id;
	enum handshake		 handshake;
	int			 request_timeout;
};

static int			 await_connect(int fd);
static struct pending_request	*claim_slot(struct btmgr_ipc *conn);
static void			 fail_slot(struct pending_request *slot,
				     const char *code, const char *detail);
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

/* Release the slot, then report the failure to whoever registered it. */
static void
fail_slot(struct pending_request *slot, const char *code, const char *detail)
{
	struct proto_msg	 failure;
	btmgr_reply_fn		 callback;
	void			*user_data;

	memset(&failure, 0, sizeof(failure));
	failure.kind = PROTO_MSG_REPLY;
	failure.request_id = slot->request_id;
	failure.succeeded = 0;
	strlcpy(failure.error_code, code, sizeof(failure.error_code));
	strlcpy(failure.error_detail, detail, sizeof(failure.error_detail));

	callback = slot->on_reply;
	user_data = slot->user_data;

	/* Released first, so the callback may issue a new request. */
	memset(slot, 0, sizeof(*slot));

	if (callback != NULL)
		callback(&failure, user_data);
}

static void
fail_all_pending(struct btmgr_ipc *conn)
{
	int	 i;

	for (i = 0; i < BTMGR_MAX_PENDING_REQUESTS; i++) {
		if (conn->pending[i].in_use)
			fail_slot(&conn->pending[i], "io_error",
			    "the daemon connection closed");
	}
}

void
btmgr_ipc_set_request_timeout(struct btmgr_ipc *conn, int seconds)
{
	if (conn != NULL && seconds > 0)
		conn->request_timeout = seconds;
}

int
btmgr_ipc_expire_requests(struct btmgr_ipc *conn)
{
	time_t	 now;
	int	 expired = 0, i;

	if (conn == NULL)
		return (0);

	now = time(NULL);
	for (i = 0; i < BTMGR_MAX_PENDING_REQUESTS; i++) {
		struct pending_request	*slot = &conn->pending[i];

		if (!slot->in_use || slot->deadline > now)
			continue;

		fail_slot(slot, "timeout", "the daemon never answered");
		expired++;
	}

	return (expired);
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

/*
 * Wait out an in-progress connect, up to BTMGR_CONNECT_TIMEOUT_MS. Returns 0
 * once writable and error-free, -1 with errno set otherwise.
 */
static int
await_connect(int fd)
{
	struct pollfd	 pfd;
	socklen_t	 len;
	int		 err, ready;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	pfd.revents = 0;

	do {
		ready = poll(&pfd, 1, BTMGR_CONNECT_TIMEOUT_MS);
	} while (ready < 0 && errno == EINTR);

	if (ready == 0) {
		errno = ETIMEDOUT;
		return (-1);
	}
	if (ready < 0)
		return (-1);

	/* Writable does not mean connected: the error lands in SO_ERROR. */
	len = sizeof(err);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0)
		return (-1);
	if (err != 0) {
		errno = err;
		return (-1);
	}

	return (0);
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

	if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
		saved = errno;
		(void)close(fd);
		free(conn);
		errno = saved;
		return (NULL);
	}

	/*
	 * An AF_UNIX connect either completes in the kernel or fails at once,
	 * even against a full accept queue, which refuses rather than waits.
	 * EINPROGRESS is therefore not reached here, but the wait is bounded
	 * anyway so that a frontend's startup can never hang on it.
	 */
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		if (errno != EINPROGRESS ||
		    await_connect(fd) != 0) {
			saved = errno;
			(void)close(fd);
			free(conn);
			errno = saved;
			return (NULL);
		}
	}

	conn->fd = fd;
	conn->request_timeout = BTMGR_REQUEST_TIMEOUT_SEC;
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

	/*
	 * B2.1 again. Sending before the handshake would hand a PIN to a
	 * daemon whose protocol we have not agreed on.
	 */
	if (conn->handshake != HANDSHAKE_AGREED) {
		errno = conn->handshake == HANDSHAKE_REFUSED ?
		    EPROTONOSUPPORT : ENOTCONN;
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
	slot->deadline = time(NULL) + conn->request_timeout;

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

	(void)btmgr_ipc_expire_requests(conn);

	filled = btmgr_ipc_fill(conn);
	saved = errno;

	/*
	 * Drain what did arrive before reporting the close. A daemon that
	 * exits right after answering still gets its reply delivered.
	 */
	while (btmgr_ipc_next_line(conn, &line, &len) == 1) {
		/*
		 * A line that does not parse breaks B1.2, and the reply it may
		 * have been has now been consumed. Skipping it would leave that
		 * request pending with nothing left to answer it. An unknown
		 * event still decodes, so this really is malformed.
		 */
		if (proto_parse_msg(line, len, &msg) != 0) {
			fail_all_pending(conn);
			errno = EPROTO;
			return (-1);
		}

		/*
		 * B2.1. The connection is marked unusable rather than closed
		 * here: freeing it would leave the caller holding a dangling
		 * pointer, and it already closes on any -1 from this call.
		 */
		if (msg.kind == PROTO_MSG_EVENT &&
		    strcmp(msg.event_name, "hello") == 0) {
			if (!msg.has_proto_version ||
			    msg.proto_version != BTMGR_PROTO_VERSION)
				conn->handshake = HANDSHAKE_REFUSED;
			else
				conn->handshake = HANDSHAKE_AGREED;
		}

		if (msg.kind == PROTO_MSG_REPLY)
			deliver_reply(conn, &msg);
		else if (on_event != NULL)
			on_event(&msg, user_data);

		if (conn->handshake == HANDSHAKE_REFUSED) {
			fail_all_pending(conn);
			errno = EPROTONOSUPPORT;
			return (-1);
		}
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

int
btmgr_ipc_is_ready(const struct btmgr_ipc *conn)
{
	return (conn != NULL && conn->handshake == HANDSHAKE_AGREED);
}

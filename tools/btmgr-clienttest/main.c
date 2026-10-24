/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-clienttest - verification for common/ipc_client.c. SPEC.md A5, B1.
 *
 * Stands up a real AF_UNIX listening socket and plays daemon, so the connect
 * path is exercised rather than mocked. Needs no root and no bluetoothmgrd.
 *
 * The socket lives in a short mkdtemp path on purpose: sun_path is 104 bytes,
 * and a long scratch directory silently overflows it.
 *
 * Exits 0 when every check passes, 1 otherwise.
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ipc_client.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"

static int	 failures;
static int	 checks;
static char	 dir[64];
static char	 sockpath[96];

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 eq(const char *got, const char *want, const char *what);
static int	 fake_daemon(void);

static void
ok(int cond, const char *fmt, ...)
{
	va_list	 ap;

	checks++;
	va_start(ap, fmt);
	if (cond) {
		(void)fputs("ok   ", stdout);
	} else {
		(void)fputs("FAIL ", stdout);
		failures++;
	}
	vprintf(fmt, ap);
	putchar('\n');
	va_end(ap);
}

static void
eq(const char *got, const char *want, const char *what)
{
	int	 same;

	if (got == NULL) {
		ok(0, "%s (got NULL)", what);
		return;
	}
	same = strcmp(got, want) == 0;
	ok(same, "%s%s%s%s", what, same ? "" : " (got \"", same ? "" : got,
	    same ? "" : "\")");
}

/* A listening socket at sockpath. Returns the listening fd, or -1. */
static int
fake_daemon(void)
{
	struct sockaddr_un	sa;
	int			lfd;

	lfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (lfd < 0)
		return (-1);

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, sockpath, sizeof(sa.sun_path));

	if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    listen(lfd, 4) != 0) {
		(void)close(lfd);
		return (-1);
	}

	return (lfd);
}

static void
test_absent_daemon(void)
{
	struct btmgr_ipc	*c;
	char			 missing[96];

	printf("\nno daemon listening\n");

	(void)snprintf(missing, sizeof(missing), "%s/nothing", dir);

	errno = 0;
	c = btmgr_ipc_open(missing);
	ok(c == NULL && errno == ENOENT,
	    "a missing socket is ENOENT, which means retry later");

	errno = 0;
	c = btmgr_ipc_open("/this/path/does/not/exist/either");
	ok(c == NULL, "so is a path with no directory");
	btmgr_ipc_close(c);

	/* The header promises NULL is accepted. */
	btmgr_ipc_close(NULL);
	ok(1, "closing NULL is harmless");
}

static void
test_default_path(void)
{
	char	 toolong[128];

	printf("\nthe default socket path\n");

	(void)unsetenv(BTMGR_SOCKET_ENV);
	eq(btmgr_ipc_default_path(), BTMGR_SOCKET_PATH,
	    "unset falls back to the compiled-in path");

	(void)setenv(BTMGR_SOCKET_ENV, "/var/run/elsewhere.sock", 1);
	eq(btmgr_ipc_default_path(), "/var/run/elsewhere.sock",
	    "an absolute override is taken");

	(void)setenv(BTMGR_SOCKET_ENV, "", 1);
	eq(btmgr_ipc_default_path(), BTMGR_SOCKET_PATH,
	    "empty is ignored rather than becoming a relative path");

	(void)setenv(BTMGR_SOCKET_ENV, "relative/path.sock", 1);
	eq(btmgr_ipc_default_path(), BTMGR_SOCKET_PATH,
	    "a relative override is ignored");

	/*
	 * sun_path is 104 bytes on FreeBSD, and btmgr_ipc_open() would reject
	 * an over-long path with ENAMETOOLONG anyway. Falling back here keeps
	 * a typo in the session environment from disabling the applet.
	 */
	memset(toolong, 'x', sizeof(toolong) - 1);
	toolong[0] = '/';
	toolong[sizeof(toolong) - 1] = '\0';
	(void)setenv(BTMGR_SOCKET_ENV, toolong, 1);
	eq(btmgr_ipc_default_path(), BTMGR_SOCKET_PATH,
	    "an override too long for sun_path is ignored");

	(void)unsetenv(BTMGR_SOCKET_ENV);
}

static void
test_roundtrip(void)
{
	struct btmgr_ipc	*c;
	struct sockaddr_un	 sa;
	socklen_t		 salen;
	char			*line;
	char			 buf[256];
	size_t			 len;
	ssize_t			 n;
	int			 lfd, sfd;

	printf("\nconnect and exchange lines\n");

	lfd = fake_daemon();
	if (lfd < 0) {
		ok(0, "could not listen on %s", sockpath);
		return;
	}

	c = btmgr_ipc_open(sockpath);
	ok(c != NULL, "the client connects");
	if (c == NULL) {
		(void)close(lfd);
		return;
	}
	ok(btmgr_ipc_fd(c) >= 0, "and exposes an fd to watch");

	salen = sizeof(sa);
	sfd = accept(lfd, (struct sockaddr *)&sa, &salen);
	ok(sfd >= 0, "the daemon side accepts");

	/* Daemon to client, two lines in one write. */
	(void)write(sfd, "{\"event\":\"hello\"}\n{\"id\":1,\"ok\":true}\n", 37);

	ok(btmgr_ipc_fill(c) == 0, "the client fills");
	ok(btmgr_ipc_next_line(c, &line, &len) == 1, "and gets the first line");
	eq(line, "{\"event\":\"hello\"}", "with the newline stripped");
	ok(btmgr_ipc_next_line(c, &line, &len) == 1, "then the second");
	eq(line, "{\"id\":1,\"ok\":true}", "intact");
	ok(btmgr_ipc_next_line(c, &line, &len) == 0, "and then nothing");

	/* Client to daemon. */
	ok(btmgr_ipc_send(c, "{\"id\":2,\"cmd\":\"get_state\"}\n") == 0,
	    "the client sends");
	ok(btmgr_ipc_has_unwritten(c) == 0, "with nothing left pending");

	n = read(sfd, buf, sizeof(buf) - 1);
	ok(n > 0, "the daemon side receives it");
	if (n > 0) {
		buf[n] = '\0';
		eq(buf, "{\"id\":2,\"cmd\":\"get_state\"}\n",
		    "byte for byte, newline included");
	}

	ok(btmgr_ipc_flush(c) == 0, "a flush with nothing pending succeeds");

	btmgr_ipc_close(c);
	(void)close(sfd);
	(void)close(lfd);
	(void)unlink(sockpath);
}

/* M6 wants the applet to survive the daemon restarting under it. */
static void
test_daemon_restart(void)
{
	struct btmgr_ipc	*c;
	struct sockaddr_un	 sa;
	socklen_t		 salen;
	char			*line;
	size_t			 len;
	int			 lfd, sfd;

	printf("\nthe daemon goes away\n");

	lfd = fake_daemon();
	if (lfd < 0) {
		ok(0, "could not listen");
		return;
	}

	c = btmgr_ipc_open(sockpath);
	if (c == NULL) {
		ok(0, "could not connect");
		(void)close(lfd);
		(void)unlink(sockpath);
		return;
	}

	salen = sizeof(sa);
	sfd = accept(lfd, (struct sockaddr *)&sa, &salen);

	/* A line, then the daemon exits mid-stream. */
	(void)write(sfd, "{\"event\":\"state\"}\n", 18);
	(void)close(sfd);
	(void)close(lfd);
	(void)unlink(sockpath);

	ok(btmgr_ipc_fill(c) == 0 || errno == 0,
	    "the buffered line survives the close");
	ok(btmgr_ipc_next_line(c, &line, &len) == 1,
	    "and is still handed out after the peer is gone");
	eq(line, "{\"event\":\"state\"}", "intact");

	errno = EINVAL;			/* so errno == 0 proves it was set */
	ok(btmgr_ipc_fill(c) == -1 && errno == 0,
	    "then the close reports -1 with errno 0");

	/* A send on a dead connection must fail rather than appear to work. */
	ok(btmgr_ipc_send(c, "{\"id\":1,\"cmd\":\"get_state\"}\n") == -1,
	    "and a send afterwards fails");

	btmgr_ipc_close(c);

	/* Reopening is how a frontend recovers, and must work. */
	lfd = fake_daemon();
	if (lfd < 0) {
		ok(0, "could not listen again");
		return;
	}
	c = btmgr_ipc_open(sockpath);
	ok(c != NULL, "and reconnecting to a restarted daemon works");
	btmgr_ipc_close(c);
	(void)close(lfd);
	(void)unlink(sockpath);
}

struct reply_capture {
	int	calls;
	int	request_id;
	int	succeeded;
	char	error_code[BTMGR_ERROR_CODE_MAX];
};

struct event_capture {
	int	calls;
	char	event_name[BTMGR_EVENT_NAME_MAX];
};

static void
capture_reply(const struct proto_msg *reply, void *user_data)
{
	struct reply_capture	*cap = user_data;

	cap->calls++;
	cap->request_id = reply->request_id;
	cap->succeeded = reply->succeeded;
	strlcpy(cap->error_code, reply->error_code, sizeof(cap->error_code));
}

static void
capture_event(const struct proto_msg *event, void *user_data)
{
	struct event_capture	*cap = user_data;

	cap->calls++;
	strlcpy(cap->event_name, event->event_name, sizeof(cap->event_name));
}

/* Connect a client to a listening socket and accept it. */
static int
connect_pair(int *listen_fd, int *server_fd, struct btmgr_ipc **conn)
{
	struct sockaddr_un	sa;
	socklen_t		salen;

	*listen_fd = fake_daemon();
	if (*listen_fd < 0)
		return (-1);

	*conn = btmgr_ipc_open(sockpath);
	if (*conn == NULL) {
		(void)close(*listen_fd);
		(void)unlink(sockpath);
		return (-1);
	}

	salen = sizeof(sa);
	*server_fd = accept(*listen_fd, (struct sockaddr *)&sa, &salen);
	if (*server_fd < 0) {
		btmgr_ipc_close(*conn);
		(void)close(*listen_fd);
		(void)unlink(sockpath);
		return (-1);
	}

	return (0);
}

/* Takes ownership, so each allocation has exactly one free at one point. */
static void
send_owned(int fd, char *line)
{
	if (line == NULL)
		return;

	(void)write(fd, line, strlen(line));
	free(line);
}

/* B2: the daemon speaks first, and requests are refused until it has. */
static void
handshake(struct btmgr_ipc *conn, int server_fd)
{
	send_owned(server_fd, proto_hello());
	(void)btmgr_ipc_dispatch(conn, NULL, NULL);
}

static void
teardown(int listen_fd, int server_fd, struct btmgr_ipc *conn)
{

	btmgr_ipc_close(conn);
	if (server_fd >= 0)
		(void)close(server_fd);
	if (listen_fd >= 0)
		(void)close(listen_fd);
	(void)unlink(sockpath);
}

/* Read the id the client chose, so the fake daemon can answer it. */
static int
read_request_id(int server_fd)
{
	struct proto_cmd	cmd;
	char			buf[512];
	char			code[32];
	char			*newline;
	ssize_t			n;

	n = read(server_fd, buf, sizeof(buf) - 1);
	if (n <= 0)
		return (-1);
	buf[n] = '\0';

	newline = strchr(buf, '\n');
	if (newline != NULL)
		*newline = '\0';

	if (proto_parse_cmd(buf, strlen(buf), &cmd, code, sizeof(code)) != 0)
		return (-1);

	return (cmd.id);
}

static void
test_request_reply(void)
{
	struct btmgr_ipc	*conn;
	struct proto_cmd	 cmd;
	struct reply_capture	 cap;
	int			 listen_fd, server_fd, id;

	printf("\nB3.1 a request and its reply\n");

	if (connect_pair(&listen_fd, &server_fd, &conn) != 0) {
		ok(0, "could not set up a connection");
		return;
	}
	handshake(conn, server_fd);

	memset(&cap, 0, sizeof(cap));
	memset(&cmd, 0, sizeof(cmd));
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));

	ok(btmgr_ipc_request(conn, &cmd, capture_reply, &cap) == 0,
	    "a request is sent");
	ok(cmd.id >= 0, "with an id assigned by the client, not the caller");
	ok(btmgr_ipc_pending_count(conn) == 1, "and is counted as pending");

	id = read_request_id(server_fd);
	ok(id == cmd.id, "the daemon side sees that same id");

	/* Answer it, exactly once, as B3.2 requires. */
	send_owned(server_fd, proto_ok(id));

	ok(btmgr_ipc_dispatch(conn, NULL, NULL) == 0, "dispatch succeeds");
	ok(cap.calls == 1, "the callback fired once");
	ok(cap.request_id == id, "for the right request");
	ok(cap.succeeded == 1, "reporting success");
	ok(btmgr_ipc_pending_count(conn) == 0, "and the slot was released");

	/* A second dispatch must not fire it again. */
	ok(btmgr_ipc_dispatch(conn, NULL, NULL) == 0, "a further dispatch is quiet");
	ok(cap.calls == 1, "and does not call back twice");

	teardown(listen_fd, server_fd, conn);
}

/* Two outstanding at once, answered in the wrong order. */
static void
test_out_of_order(void)
{
	struct btmgr_ipc	*conn;
	struct proto_cmd	 first, second;
	struct reply_capture	 cap_first, cap_second;
	int			 listen_fd, server_fd;

	printf("\ntwo requests, answered out of order\n");

	if (connect_pair(&listen_fd, &server_fd, &conn) != 0) {
		ok(0, "could not set up a connection");
		return;
	}
	handshake(conn, server_fd);

	memset(&cap_first, 0, sizeof(cap_first));
	memset(&cap_second, 0, sizeof(cap_second));

	memset(&first, 0, sizeof(first));
	(void)strlcpy(first.name, "get_state", sizeof(first.name));
	(void)btmgr_ipc_request(conn, &first, capture_reply, &cap_first);

	memset(&second, 0, sizeof(second));
	(void)strlcpy(second.name, "get_state", sizeof(second.name));
	(void)btmgr_ipc_request(conn, &second, capture_reply, &cap_second);

	ok(first.id != second.id, "the two requests get different ids, per B3.1");
	ok(btmgr_ipc_pending_count(conn) == 2, "both are pending");

	/* Answer the second one first. */
	send_owned(server_fd, proto_error(second.id, "busy", NULL));
	send_owned(server_fd, proto_ok(first.id));

	(void)btmgr_ipc_dispatch(conn, NULL, NULL);

	ok(cap_second.calls == 1 && cap_second.succeeded == 0,
	    "the second request got its own failure");
	eq(cap_second.error_code, "busy", "with its own error code");
	ok(cap_first.calls == 1 && cap_first.succeeded == 1,
	    "and the first got its own success, not the other's");
	ok(btmgr_ipc_pending_count(conn) == 0, "both slots released");

	teardown(listen_fd, server_fd, conn);
}

static void
test_events_and_strays(void)
{
	struct btmgr_ipc	*conn;
	struct event_capture	 cap;
	int			 listen_fd, server_fd;

	printf("\nevents, and replies to nothing\n");

	if (connect_pair(&listen_fd, &server_fd, &conn) != 0) {
		ok(0, "could not set up a connection");
		return;
	}
	handshake(conn, server_fd);

	memset(&cap, 0, sizeof(cap));

	send_owned(server_fd, proto_hello());

	ok(btmgr_ipc_dispatch(conn, capture_event, &cap) == 0, "dispatch succeeds");
	ok(cap.calls == 1, "the event callback fired");
	eq(cap.event_name, "hello", "with the event name");

	/* An event with no handler must be dropped, not break dispatch. */
	send_owned(server_fd, proto_hello());
	ok(btmgr_ipc_dispatch(conn, NULL, NULL) == 0,
	    "an event with no handler is harmless");

	/* A reply to an id nobody is waiting on. */
	send_owned(server_fd, proto_ok(99999));
	ok(btmgr_ipc_dispatch(conn, NULL, NULL) == 0,
	    "a reply to an unknown id is ignored, not an error");

	teardown(listen_fd, server_fd, conn);
}

/*
 * A line that does not parse is a B1.2 violation. Skipping it used to leave
 * any request whose reply it was pending forever, since there is no
 * client-side timeout.
 */
static void
test_unparseable_line(void)
{
	struct btmgr_ipc	*conn;
	struct proto_cmd	 cmd;
	struct reply_capture	 cap;
	int			 listen_fd, server_fd;

	printf("\nB1.2 a line that does not parse\n");

	if (connect_pair(&listen_fd, &server_fd, &conn) != 0) {
		ok(0, "could not set up a connection");
		return;
	}
	handshake(conn, server_fd);

	memset(&cap, 0, sizeof(cap));
	memset(&cmd, 0, sizeof(cmd));
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	(void)btmgr_ipc_request(conn, &cmd, capture_reply, &cap);
	ok(btmgr_ipc_pending_count(conn) == 1, "a request is pending");

	(void)write(server_fd, "not json\n", 9);

	errno = 0;
	ok(btmgr_ipc_dispatch(conn, NULL, NULL) == -1 && errno == EPROTO,
	    "dispatch reports EPROTO rather than skipping it");
	ok(cap.calls == 1, "the pending request was failed, not left waiting");
	eq(cap.error_code, "io_error", "with io_error");
	ok(btmgr_ipc_pending_count(conn) == 0, "and the table was cleared");

	teardown(listen_fd, server_fd, conn);
}

static void
test_table_full(void)
{
	struct btmgr_ipc	*conn;
	struct proto_cmd	 cmd;
	int			 listen_fd, server_fd, i, refused = 0;

	printf("\nthe pending table is bounded\n");

	if (connect_pair(&listen_fd, &server_fd, &conn) != 0) {
		ok(0, "could not set up a connection");
		return;
	}
	handshake(conn, server_fd);

	for (i = 0; i < BTMGR_MAX_PENDING_REQUESTS; i++) {
		memset(&cmd, 0, sizeof(cmd));
		(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
		if (btmgr_ipc_request(conn, &cmd, NULL, NULL) != 0)
			break;
	}
	ok(i == BTMGR_MAX_PENDING_REQUESTS,
	    "all %d slots can be filled", BTMGR_MAX_PENDING_REQUESTS);
	ok(btmgr_ipc_pending_count(conn) == BTMGR_MAX_PENDING_REQUESTS,
	    "and all are counted");

	memset(&cmd, 0, sizeof(cmd));
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	errno = 0;
	refused = btmgr_ipc_request(conn, &cmd, NULL, NULL) == -1 &&
	    errno == EBUSY;
	ok(refused, "one more is refused with EBUSY rather than overflowing");

	teardown(listen_fd, server_fd, conn);
}

/* A frontend must never wait forever on a daemon that has gone. */
static void
test_connection_lost(void)
{
	struct btmgr_ipc	*conn;
	struct proto_cmd	 cmd;
	struct reply_capture	 cap;
	int			 listen_fd, server_fd;

	printf("\nthe daemon dies with a request outstanding\n");

	if (connect_pair(&listen_fd, &server_fd, &conn) != 0) {
		ok(0, "could not set up a connection");
		return;
	}
	handshake(conn, server_fd);

	memset(&cap, 0, sizeof(cap));
	memset(&cmd, 0, sizeof(cmd));
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	(void)btmgr_ipc_request(conn, &cmd, capture_reply, &cap);
	ok(btmgr_ipc_pending_count(conn) == 1, "the request is pending");

	/* The daemon exits without answering. */
	(void)close(server_fd);
	server_fd = -1;

	ok(btmgr_ipc_dispatch(conn, NULL, NULL) == -1,
	    "dispatch reports the connection finished");
	ok(cap.calls == 1, "the pending callback was failed, not left hanging");
	ok(cap.succeeded == 0, "as a failure");
	eq(cap.error_code, "io_error", "with io_error");
	ok(btmgr_ipc_pending_count(conn) == 0, "and the table was cleared");

	teardown(listen_fd, server_fd, conn);
}

/* A send failure makes the connection unusable, so nobody may be left waiting. */
static void
test_send_failure_fails_all(void)
{
	struct btmgr_ipc	*conn;
	struct proto_cmd	 cmd;
	struct reply_capture	 first, later;
	int			 listen_fd, server_fd;

	printf("\na send fails with earlier requests pending\n");

	if (connect_pair(&listen_fd, &server_fd, &conn) != 0) {
		ok(0, "could not set up a connection");
		return;
	}
	handshake(conn, server_fd);

	memset(&first, 0, sizeof(first));
	memset(&later, 0, sizeof(later));

	memset(&cmd, 0, sizeof(cmd));
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	(void)btmgr_ipc_request(conn, &cmd, capture_reply, &first);
	ok(btmgr_ipc_pending_count(conn) == 1, "one request is pending");

	/* Kill the peer, so the next send cannot succeed. */
	(void)close(server_fd);
	server_fd = -1;
	(void)btmgr_ipc_fill(conn);		/* notice the close */

	memset(&cmd, 0, sizeof(cmd));
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	ok(btmgr_ipc_request(conn, &cmd, capture_reply, &later) == -1,
	    "the next request fails to send");
	ok(first.calls == 1 && first.succeeded == 0,
	    "and the earlier request was failed, not left waiting");
	eq(first.error_code, "io_error", "with io_error");
	ok(btmgr_ipc_pending_count(conn) == 0, "the table is empty");

	teardown(listen_fd, server_fd, conn);
}

/* B2.1: an incompatible daemon must not stay connected and usable. */
static void
test_handshake(void)
{
	struct btmgr_ipc	*conn;
	struct proto_cmd	 cmd;
	struct reply_capture	 cap;
	char			 wrong[128];
	int			 listen_fd, server_fd;

	printf("\nB2.1 the version handshake\n");

	if (connect_pair(&listen_fd, &server_fd, &conn) != 0) {
		ok(0, "could not set up a connection");
		return;
	}

	/* Before hello, a request would reach a daemon we have not agreed with. */
	ok(btmgr_ipc_is_ready(conn) == 0, "a fresh connection is not ready");
	memset(&cmd, 0, sizeof(cmd));
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	errno = 0;
	ok(btmgr_ipc_request(conn, &cmd, NULL, NULL) == -1 && errno == ENOTCONN,
	    "and a request before hello is refused with ENOTCONN");

	handshake(conn, server_fd);
	ok(btmgr_ipc_is_ready(conn) == 1, "after hello it is ready");
	memset(&cmd, 0, sizeof(cmd));
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	ok(btmgr_ipc_request(conn, &cmd, NULL, NULL) == 0,
	    "and a request is accepted");

	teardown(listen_fd, server_fd, conn);

	/* A daemon announcing a version we do not speak. */
	if (connect_pair(&listen_fd, &server_fd, &conn) != 0) {
		ok(0, "could not set up a second connection");
		return;
	}

	memset(&cap, 0, sizeof(cap));
	(void)snprintf(wrong, sizeof(wrong),
	    "{\"event\":\"hello\",\"proto\":%d,\"daemon\":\"other\"}\n",
	    BTMGR_PROTO_VERSION + 1);
	(void)write(server_fd, wrong, strlen(wrong));

	errno = 0;
	ok(btmgr_ipc_dispatch(conn, NULL, NULL) == -1 &&
	    errno == EPROTONOSUPPORT,
	    "a mismatched proto makes dispatch report EPROTONOSUPPORT");
	ok(btmgr_ipc_is_ready(conn) == 0, "the connection is not ready");

	memset(&cmd, 0, sizeof(cmd));
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	errno = 0;
	ok(btmgr_ipc_request(conn, &cmd, NULL, NULL) == -1 &&
	    errno == EPROTONOSUPPORT,
	    "and no further request is sent to it");

	teardown(listen_fd, server_fd, conn);

	/* A hello with no proto field at all is equally unusable. */
	if (connect_pair(&listen_fd, &server_fd, &conn) != 0) {
		ok(0, "could not set up a third connection");
		return;
	}
	(void)write(server_fd, "{\"event\":\"hello\"}\n", 19);
	errno = 0;
	ok(btmgr_ipc_dispatch(conn, NULL, NULL) == -1 &&
	    errno == EPROTONOSUPPORT,
	    "a hello with no proto version is refused too");

	teardown(listen_fd, server_fd, conn);
}

/*
 * B3.2 says the daemon answers exactly once. A daemon that does not would
 * otherwise hold its slot until the connection is replaced, and with sixteen
 * of those a frontend is wedged.
 */
static void
test_request_timeout(void)
{
	struct btmgr_ipc	*conn;
	struct proto_cmd	 cmd;
	struct reply_capture	 cap;
	int			 listen_fd, server_fd;

	printf("\na reply that never comes\n");

	if (connect_pair(&listen_fd, &server_fd, &conn) != 0) {
		ok(0, "could not set up a connection");
		return;
	}
	handshake(conn, server_fd);

	memset(&cap, 0, sizeof(cap));
	memset(&cmd, 0, sizeof(cmd));
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	(void)btmgr_ipc_request(conn, &cmd, capture_reply, &cap);

	/* Nothing is due yet, so a sweep must leave it alone. */
	ok(btmgr_ipc_expire_requests(conn) == 0,
	    "a fresh request is not expired");
	ok(btmgr_ipc_pending_count(conn) == 1, "and stays pending");

	/* A one second timeout on the next request, then outlive it. */
	btmgr_ipc_set_request_timeout(conn, 1);
	memset(&cmd, 0, sizeof(cmd));
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	(void)btmgr_ipc_request(conn, &cmd, capture_reply, &cap);
	ok(btmgr_ipc_pending_count(conn) == 2, "two are pending");

	sleep(2);

	ok(btmgr_ipc_expire_requests(conn) == 1,
	    "the one past its deadline is failed");
	ok(cap.calls == 1, "its callback fired");
	eq(cap.error_code, "timeout", "reporting timeout, per B6");
	ok(btmgr_ipc_pending_count(conn) == 1,
	    "and the other, still in date, is untouched");

	teardown(listen_fd, server_fd, conn);
}

int
main(void)
{

	(void)snprintf(dir, sizeof(dir), "/tmp/btmgr-ct.XXXXXX");
	if (mkdtemp(dir) == NULL) {
		perror("mkdtemp");
		return (2);
	}
	(void)snprintf(sockpath, sizeof(sockpath), "%s/s", dir);

	printf("btmgr-clienttest: %s\n", sockpath);

	test_absent_daemon();
	test_default_path();
	test_roundtrip();
	test_daemon_restart();

	test_request_reply();
	test_out_of_order();
	test_events_and_strays();
	test_table_full();
	test_connection_lost();
	test_send_failure_fails_all();
	test_handshake();
	test_unparseable_line();
	test_request_timeout();

	(void)unlink(sockpath);
	(void)rmdir(dir);

	if (btmgr_mc_report() != 0) {
		printf("memcheck: allocations still live\n");
		failures++;
	}

	printf("\n%d checks, %d failures\n", checks, failures);

	return (failures != 0);
}

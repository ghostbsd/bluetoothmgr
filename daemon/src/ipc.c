/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * ipc.c - Unix socket server, line framing, and non-blocking IO.
 *
 * Two problems this file exists to solve.
 *
 * Partial reads. read() returns whatever has arrived, not what you asked for.
 * A client's line can arrive in three pieces, or three lines can arrive in one
 * read. So each client keeps an input buffer, and we consume whole lines out
 * of it only when a '\n' is actually present.
 *
 * Slow clients. A blocking write() to a client that has stopped reading blocks
 * the daemon forever, which for a root daemon means Bluetooth stops working
 * machine-wide because somebody suspended an applet. So writes are
 * non-blocking, the remainder is buffered, and EVFILT_WRITE is enabled only
 * while there is something to flush.
 */

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ipc.h"
#include "proto.h"
#include "session.h"

/*
 * Must come after the system headers: it redefines malloc and friends. The
 * pragma says so to clang-include-cleaner, which sees no direct use of this
 * header because the use is macro replacement of malloc(), not a symbol.
 */
#include "memcheck.h"	/* IWYU pragma: keep */

static int	set_nonblock(int fd);
static void	read_peer_cred(struct client *c);
static pid_t	read_sender(struct msghdr *msg);
static int	buf_append(char **buf, size_t *len, size_t *cap,
		    const char *data, size_t n, size_t limit);

static int
set_nonblock(int fd)
{
	int	flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return (-1);

	return (fcntl(fd, F_SETFL, flags | O_NONBLOCK));
}

/*
 * Append to a growable buffer, doubling as needed.
 *
 * Returns -1 if the buffer would exceed limit, which is the caller's signal to
 * drop the client rather than keep allocating on its behalf.
 *
 * Note the temporary in the realloc() path. Assigning straight to *buf would
 * leak the original allocation if realloc() returned NULL, which is the
 * classic realloc bug.
 */
static int
buf_append(char **buf, size_t *len, size_t *cap, const char *data, size_t n,
    size_t limit)
{
	char	*tmp;
	size_t	 need, want;

	need = *len + n;
	if (need > limit)
		return (-1);

	if (need > *cap) {
		want = (*cap == 0) ? 1024 : *cap;
		while (want < need)
			want *= 2;
		if (want > limit)
			want = limit;

		tmp = realloc(*buf, want);
		if (tmp == NULL)
			return (-1);

		*buf = tmp;
		*cap = want;
	}

	memcpy(*buf + *len, data, n);
	*len += n;

	return (0);
}

/*
 * A5.3 needs the peer's pid, which getpeereid() does not report. xucred keeps
 * cr_pid in a union with an old unused pointer, so cr_version has to be right
 * before the pid means anything.
 *
 * On failure the fields are left unusable rather than zeroed: uid 0 and pid 0
 * would both read as privileged.
 */
static void
read_peer_cred(struct client *c)
{
	struct xucred	cred;
	socklen_t	len;

	c->uid = (uid_t)-1;
	c->gid = (gid_t)-1;
	c->pid = -1;

	len = sizeof(cred);
	if (getsockopt(c->fd, SOL_LOCAL, LOCAL_PEERCRED, &cred, &len) < 0)
		return;

	if (len != sizeof(cred) || cred.cr_version != XUCRED_VERSION)
		return;

	c->uid = cred.cr_uid;
	c->gid = cred.cr_gid;

	/* pid 0 is the kernel, so it is never a real peer. */
	if (cred.cr_pid > 0)
		c->pid = cred.cr_pid;
}

/*
 * A5.5. The sending process, which the kernel fills in per message once the
 * socket carries LOCAL_CREDS_PERSISTENT. -1 when absent, which authorizes
 * nothing.
 */
static pid_t
read_sender(struct msghdr *msg)
{
	struct cmsghdr		*cm;
	const struct sockcred2	*sc;

	if ((msg->msg_flags & MSG_CTRUNC) != 0)
		return (-1);

	for (cm = CMSG_FIRSTHDR(msg); cm != NULL; cm = CMSG_NXTHDR(msg, cm)) {
		if (cm->cmsg_level != SOL_SOCKET ||
		    cm->cmsg_type != SCM_CREDS2 ||
		    cm->cmsg_len < CMSG_LEN(sizeof(*sc)))
			continue;

		sc = (const void *)CMSG_DATA(cm);
		if (sc->sc_pid > 0)
			return (sc->sc_pid);
	}

	return (-1);
}

/*
 * Whether something is still accepting on this path. An AF_UNIX connect
 * completes or fails in the kernel, so there is nothing to wait for: a stale
 * socket gives ECONNREFUSED, a live one connects.
 */
static int
socket_is_live(const char *path)
{
	struct sockaddr_un	sa;
	int			fd, connected;

	if (strlen(path) >= sizeof(sa.sun_path))
		return (0);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return (0);

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, path, sizeof(sa.sun_path));

	connected = connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
	(void)close(fd);

	return (connected);
}

int
ipc_listen(const char *path, mode_t mode)
{
	struct sockaddr_un	sa;
	int			fd, on, saved;

	if (strlen(path) >= sizeof(sa.sun_path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	/*
	 * SOCK_CLOEXEC: nothing here spawns today, but a child inheriting the
	 * listening socket would hold the channel that A5.3 authorizes on.
	 */
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return (-1);

	/*
	 * SPEC.md A5.2 says stale, not live: unlinking a socket another daemon
	 * is listening on would silently take its clients.
	 */
	if (socket_is_live(path)) {
		(void)close(fd);
		errno = EADDRINUSE;
		return (-1);
	}
	(void)unlink(path);

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, path, sizeof(sa.sun_path));

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		goto fail;

	if (chmod(path, mode) < 0)
		goto fail;

	/*
	 * A5.5, on the listener: unp_connect() copies UNP_WANTCRED from the
	 * listening socket to the new one, so an accepted socket already has
	 * it. Setting it after accept() is too late for a client that writes
	 * the moment connect() returns.
	 */
	on = 1;
	if (setsockopt(fd, SOL_LOCAL, LOCAL_CREDS_PERSISTENT, &on,
	    sizeof(on)) < 0)
		goto fail;

	if (listen(fd, 8) < 0)
		goto fail;

	if (set_nonblock(fd) < 0)
		goto fail;

	return (fd);

fail:
	saved = errno;
	close(fd);
	(void)unlink(path);
	errno = saved;
	return (-1);
}

struct client *
ipc_accept(int lfd)
{
	struct client	*c;
	int		 fd, saved;

	/* accept() does not inherit SOCK_CLOEXEC from the listener. */
	fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
	if (fd < 0)
		return (NULL);

	if (set_nonblock(fd) < 0) {
		saved = errno;
		close(fd);
		errno = saved;
		return (NULL);
	}

	c = calloc(1, sizeof(*c));
	if (c == NULL) {
		close(fd);
		errno = ENOMEM;
		return (NULL);
	}

	c->fd = fd;
	c->send_pid = -1;

	read_peer_cred(c);

	return (c);
}

void
ipc_client_free(struct client *c)
{
	if (c == NULL)
		return;

	if (c->fd >= 0)
		close(c->fd);

	free(c->in);
	free(c->out);
	free(c);
}

int
ipc_client_read(struct client *c)
{
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(SOCKCRED2SIZE(CMGROUP_MAX))];
	} control;
	struct msghdr	 msg;
	struct iovec	 iov;
	char		 buf[4096];
	ssize_t		 n;
	pid_t		 sender;

	for (;;) {
		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);

		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.buf;
		msg.msg_controllen = sizeof(control.buf);

		n = recvmsg(c->fd, &msg, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return (0);	/* drained */
			return (-1);
		}
		if (n == 0)
			return (-1);		/* peer closed */

		/* A5.5. No credentials means no sender we can authorize. */
		sender = read_sender(&msg);

		/*
		 * A5.5. Bytes still waiting to complete a line came from
		 * send_pid; a different sender now is splicing into them.
		 */
		if (c->in_len == c->in_taken) {
			c->send_pid = sender;
			c->send_mixed = 0;
		} else if (sender != c->send_pid) {
			c->send_mixed = 1;
		}

		/*
		 * SPEC.md B1.3: a line longer than the cap closes the
		 * connection unparsed, so the limit is enforced here on the
		 * buffer as a whole.
		 */
		if (buf_append(&c->in, &c->in_len, &c->in_cap, buf,
		    (size_t)n, BTMGR_LINE_MAX) < 0)
			return (-1);
	}
}

/*
 * Hand out the next complete line.
 *
 * The line we return points straight into the input buffer, with no copy. The
 * header promises that pointer stays valid until the next call, so we cannot
 * compact the buffer while the caller still holds it. Instead we record how
 * much was handed out in in_taken and drop it at the start of the next call.
 * That is what makes "valid until the next call" literally true.
 */
int
ipc_client_line(struct client *c, char **line, size_t *len)
{
	char	*nl;

	/* Discard whatever the previous call handed out. */
	if (c->in_taken > 0) {
		memmove(c->in, c->in + c->in_taken, c->in_len - c->in_taken);
		c->in_len -= c->in_taken;
		c->in_taken = 0;
	}

	if (c->in == NULL || c->in_len == 0)
		return (0);

	nl = memchr(c->in, '\n', c->in_len);
	if (nl == NULL)
		return (0);		/* incomplete, wait for more */

	/*
	 * Terminate in place so the caller gets a plain C string. This
	 * overwrites the newline, which we are discarding anyway.
	 */
	*nl = '\0';
	*line = c->in;
	*len = (size_t)(nl - c->in);

	c->in_taken = *len + 1;		/* the line plus its newline */

	return (1);
}

int
ipc_client_flush(struct client *c)
{
	ssize_t	n;

	while (c->out_len > 0) {
		n = write(c->fd, c->out, c->out_len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				c->want_write = 1;
				return (0);	/* try again when writable */
			}
			return (-1);
		}

		if ((size_t)n < c->out_len)
			memmove(c->out, c->out + n, c->out_len - (size_t)n);
		c->out_len -= (size_t)n;
	}

	c->want_write = 0;

	return (0);
}

int
ipc_client_send(struct client *c, const char *data)
{
	if (data == NULL)
		return (0);

	if (buf_append(&c->out, &c->out_len, &c->out_cap, data,
	    strlen(data), IPC_OUT_MAX) < 0)
		return (-1);

	return (ipc_client_flush(c));
}

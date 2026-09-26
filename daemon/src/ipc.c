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
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ipc.h"
#include "proto.h"

static int	set_nonblock(int fd);
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

int
ipc_listen(const char *path, mode_t mode)
{
	struct sockaddr_un	sa;
	int			fd, saved;

	if (strlen(path) >= sizeof(sa.sun_path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return (-1);

	/* SPEC.md A5.2: a stale socket from a crash must not block startup. */
	(void)unlink(path);

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, path, sizeof(sa.sun_path));

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		goto fail;

	if (chmod(path, mode) < 0)
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

	fd = accept(lfd, NULL, NULL);
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

	/*
	 * SPEC.md A5.3. Recorded now so M3 can refuse state-changing commands
	 * from a peer that is neither root nor in the socket's group.
	 */
	if (getpeereid(fd, &c->uid, &c->gid) < 0) {
		c->uid = (uid_t)-1;
		c->gid = (gid_t)-1;
	}

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
	char	buf[4096];
	ssize_t	n;

	for (;;) {
		n = read(c->fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return (0);	/* drained */
			return (-1);
		}
		if (n == 0)
			return (-1);		/* peer closed */

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
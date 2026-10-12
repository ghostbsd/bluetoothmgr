/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * linebuf.c - buffered newline-delimited I/O. See linebuf.h.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "linebuf.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"	/* IWYU pragma: keep */

static int	append_bounded(char **buffer, size_t *used, size_t *capacity,
		    const char *data, size_t datalen, size_t max);
static int	reserve(char **buffer, size_t *capacity, size_t needed);
static size_t	pending_line_len(const struct linebuf *buf);

static int
reserve(char **buffer, size_t *capacity, size_t needed)
{
	char	*grown;
	size_t	 new_capacity;

	if (needed <= *capacity)
		return (0);

	new_capacity = (*capacity == 0) ? 1024 : *capacity;
	while (new_capacity < needed)
		new_capacity *= 2;

	/* Via a temporary: realloc failing must not leak *buffer. */
	grown = realloc(*buffer, new_capacity);
	if (grown == NULL)
		return (-1);

	*buffer = grown;
	*capacity = new_capacity;

	return (0);
}

static int
append_bounded(char **buffer, size_t *used, size_t *capacity, const char *data,
    size_t datalen, size_t max)
{
	size_t	 needed = *used + datalen;

	if (needed > max) {
		errno = EMSGSIZE;
		return (-1);
	}
	if (reserve(buffer, capacity, needed) != 0)
		return (-1);

	memcpy(*buffer + *used, data, datalen);
	*used += datalen;

	return (0);
}

/* Bytes after the last newline: the line still being received. */
static size_t
pending_line_len(const struct linebuf *buf)
{
	const char	*last;

	if (buf->read_len == 0)
		return (0);

	last = memrchr(buf->read_buf, '\n', buf->read_len);
	if (last == NULL)
		return (buf->read_len);

	return (buf->read_len - (size_t)(last - buf->read_buf) - 1);
}

void
linebuf_init(struct linebuf *buf)
{
	memset(buf, 0, sizeof(*buf));
}

void
linebuf_free(struct linebuf *buf)
{
	free(buf->read_buf);
	free(buf->line_buf);
	free(buf->write_buf);
	memset(buf, 0, sizeof(*buf));
}

int
linebuf_fill(struct linebuf *buf, int fd)
{
	char	 chunk[4096];
	ssize_t	 nread;
	size_t	 line_max = buf->line_max != 0 ?
		     buf->line_max : LINEBUF_LINE_MAX;
	size_t	 buffer_max = buf->buffer_max != 0 ?
		     buf->buffer_max : LINEBUF_BUFFER_MAX;

	for (;;) {
		nread = read(fd, chunk, sizeof(chunk));
		if (nread < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return (0);
			return (-1);
		}
		if (nread == 0) {
			errno = 0;
			return (-1);
		}

		if (append_bounded(&buf->read_buf, &buf->read_len,
		    &buf->read_capacity, chunk, (size_t)nread,
		    buffer_max) != 0)
			return (-1);

		/* B1.3 is about one line, not about everything unread. */
		if (pending_line_len(buf) > line_max) {
			errno = EMSGSIZE;
			return (-1);
		}
	}
}

int
linebuf_next_line(struct linebuf *buf, char **line, size_t *len)
{
	char	*newline;
	size_t	 linelen;

	if (buf->read_buf == NULL || buf->read_len == 0)
		return (0);

	newline = memchr(buf->read_buf, '\n', buf->read_len);
	if (newline == NULL)
		return (0);

	linelen = (size_t)(newline - buf->read_buf);

	/* Copied out because a later fill can realloc read_buf and move it. */
	if (reserve(&buf->line_buf, &buf->line_capacity, linelen + 1) != 0)
		return (0);

	memcpy(buf->line_buf, buf->read_buf, linelen);
	buf->line_buf[linelen] = '\0';

	buf->read_len -= linelen + 1;
	memmove(buf->read_buf, newline + 1, buf->read_len);

	*line = buf->line_buf;
	*len = linelen;

	return (1);
}

int
linebuf_send(struct linebuf *buf, int fd, const char *line)
{
	size_t	 max = buf->write_max != 0 ? buf->write_max : LINEBUF_WRITE_MAX;

	if (append_bounded(&buf->write_buf, &buf->write_len,
	    &buf->write_capacity, line, strlen(line), max) != 0)
		return (-1);

	return (linebuf_flush(buf, fd));
}

int
linebuf_flush(struct linebuf *buf, int fd)
{
	ssize_t	 nwritten;

	while (buf->write_len > 0) {
		nwritten = write(fd, buf->write_buf, buf->write_len);
		if (nwritten < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				break;
			buf->has_unwritten = 0;
			return (-1);
		}

		memmove(buf->write_buf, buf->write_buf + nwritten,
		    buf->write_len - (size_t)nwritten);
		buf->write_len -= (size_t)nwritten;
	}

	buf->has_unwritten = buf->write_len > 0;

	return (0);
}

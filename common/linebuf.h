/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * linebuf.h - buffered newline-delimited I/O over one non-blocking fd.
 *
 * Owns no event loop and never blocks. The caller watches the fd in its own
 * loop, GLib in the applet and kqueue in the daemon, and calls in when it is
 * ready. That is why there is no send-and-wait here.
 */

#ifndef BTMGR_LINEBUF_H_
#define	BTMGR_LINEBUF_H_

#include <stddef.h>

/* SPEC.md B1.3. One line longer than this is refused unparsed. */
#define	LINEBUF_LINE_MAX	((size_t)64 * 1024)

/* Total unread. Bigger than a line: a burst of valid lines is not an abuse. */
#define	LINEBUF_BUFFER_MAX	((size_t)1024 * 1024)

/* A peer that will not drain is wedged or hostile. SPEC.md A5. */
#define	LINEBUF_WRITE_MAX	((size_t)256 * 1024)

struct linebuf {
	char	*read_buf;
	size_t	 read_len;
	size_t	 read_capacity;

	char	*line_buf;
	size_t	 line_capacity;

	char	*write_buf;
	size_t	 write_len;
	size_t	 write_capacity;

	size_t	 line_max;	/* 0 selects LINEBUF_LINE_MAX */
	size_t	 buffer_max;	/* 0 selects LINEBUF_BUFFER_MAX */
	size_t	 write_max;	/* 0 selects LINEBUF_WRITE_MAX */

	int	 has_unwritten;
};

void	linebuf_init(struct linebuf *buf);
void	linebuf_free(struct linebuf *buf);

/*
 * Returns 0 normally, or -1 when the connection is finished and the caller
 * should drop it. errno tells which: 0 for a clean close, EMSGSIZE for a line
 * past line_max or a buffer past buffer_max, otherwise the failing read's.
 */
int	linebuf_fill(struct linebuf *buf, int fd);

/*
 * Returns 1 with *line and *len set, or 0 when no complete line is buffered.
 *
 * *line stays valid until the next linebuf_next_line() on this linebuf.
 * linebuf_fill() does not disturb it.
 */
int	linebuf_next_line(struct linebuf *buf, char **line, size_t *len);

/* line must already end in '\n'. Returns 0, or -1 to drop the connection. */
int	linebuf_send(struct linebuf *buf, int fd, const char *line);

int	linebuf_flush(struct linebuf *buf, int fd);

#endif

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

/* SPEC.md B1.3. A longer line is refused unparsed. */
#define	LINEBUF_READ_MAX	((size_t)64 * 1024)

/* A peer that will not drain is wedged or hostile. SPEC.md A5. */
#define	LINEBUF_WRITE_MAX	((size_t)256 * 1024)

struct linebuf {
	char	*read_buf;
	size_t	 read_len;
	size_t	 read_capacity;
	size_t	 read_handed_out;

	char	*write_buf;
	size_t	 write_len;
	size_t	 write_capacity;

	size_t	 read_max;		/* 0 selects LINEBUF_READ_MAX */
	size_t	 write_max;		/* 0 selects LINEBUF_WRITE_MAX */

	int	 has_unwritten;
};

void	linebuf_init(struct linebuf *buf);
void	linebuf_free(struct linebuf *buf);

/*
 * Returns 0 normally, or -1 when the connection is finished and the caller
 * should drop it. errno tells which: 0 for a clean close, EMSGSIZE for a line
 * past read_max, otherwise the failing read's errno.
 */
int	linebuf_fill(struct linebuf *buf, int fd);

/*
 * Returns 1 with *line and *len set, or 0 when no complete line is buffered.
 * *line points into read_buf and stays valid until the next call.
 */
int	linebuf_next_line(struct linebuf *buf, char **line, size_t *len);

/* line must already end in '\n'. Returns 0, or -1 to drop the connection. */
int	linebuf_send(struct linebuf *buf, int fd, const char *line);

int	linebuf_flush(struct linebuf *buf, int fd);

#endif

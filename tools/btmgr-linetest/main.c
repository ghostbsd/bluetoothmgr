/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-linetest - verification for common/linebuf.c. SPEC.md B1.
 *
 * Drives it over a socketpair, so there is no daemon, no listening socket and
 * no root. The cases that matter are the ones a real connection produces but a
 * naive test never does: a line split across two reads, several lines in one
 * read, a line with no trailing newline, and a write the kernel only partly
 * accepts.
 *
 * Exits 0 when every check passes, 1 otherwise.
 */

#include <sys/socket.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "linebuf.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"	/* IWYU pragma: keep */

static int	 failures;
static int	 checks;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 eq(const char *got, const char *want, const char *what);
static int	 pair_open(int *a, int *b);
static void	 push(int fd, const char *data);

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

/* Both ends non-blocking, like the real thing. */
static int
pair_open(int *a, int *b)
{
	int	 sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return (-1);
	if (fcntl(sv[0], F_SETFL, O_NONBLOCK) != 0 ||
	    fcntl(sv[1], F_SETFL, O_NONBLOCK) != 0) {
		(void)close(sv[0]);
		(void)close(sv[1]);
		return (-1);
	}

	*a = sv[0];
	*b = sv[1];

	return (0);
}

static void
push(int fd, const char *data)
{

	(void)write(fd, data, strlen(data));
}

static void
test_framing(void)
{
	struct linebuf	 buf;
	char		*line;
	size_t		 len;
	int		 us, them;

	printf("\nB1.2 one object per line\n");

	if (pair_open(&us, &them) != 0) {
		ok(0, "could not make a socketpair");
		return;
	}
	linebuf_init(&buf);

	/* Nothing buffered yet. */
	ok(linebuf_next_line(&buf, &line, &len) == 0, "an empty buffer yields no line");

	/* Two whole lines in a single read. */
	push(them, "{\"a\":1}\n{\"b\":2}\n");
	ok(linebuf_fill(&buf, us) == 0, "fill succeeds");
	ok(linebuf_next_line(&buf, &line, &len) == 1, "the first line comes out");
	eq(line, "{\"a\":1}", "with the newline stripped");
	ok(len == 7, "and the length excludes the newline");
	ok(linebuf_next_line(&buf, &line, &len) == 1, "the second line too");
	eq(line, "{\"b\":2}", "intact");
	ok(linebuf_next_line(&buf, &line, &len) == 0, "then nothing is left");

	/* A line split across two reads is the case a naive reader fails. */
	push(them, "{\"split\":");
	ok(linebuf_fill(&buf, us) == 0, "a partial line fills");
	ok(linebuf_next_line(&buf, &line, &len) == 0,
	    "and yields nothing until the newline arrives");
	push(them, "true}\n");
	ok(linebuf_fill(&buf, us) == 0, "the rest fills");
	ok(linebuf_next_line(&buf, &line, &len) == 1, "now the line comes out");
	eq(line, "{\"split\":true}", "rejoined across the two reads");

	/* Trailing bytes with no newline stay buffered, not handed out. */
	push(them, "no newline here");
	ok(linebuf_fill(&buf, us) == 0, "a tail with no newline fills");
	ok(linebuf_next_line(&buf, &line, &len) == 0, "and is never handed out");

	linebuf_free(&buf);
	(void)close(us);
	(void)close(them);
}

/* The read_handed_out contract: the pointer stays valid until the next call. */
static void
test_pointer_lifetime(void)
{
	struct linebuf	 buf;
	char		*first, *second;
	size_t		 len;
	int		 us, them;

	printf("\nthe handed-out pointer\n");

	if (pair_open(&us, &them) != 0) {
		ok(0, "could not make a socketpair");
		return;
	}
	linebuf_init(&buf);

	push(them, "first\nsecond\n");
	(void)linebuf_fill(&buf, us);

	ok(linebuf_next_line(&buf, &first, &len) == 1, "the first line comes out");
	eq(first, "first", "and reads correctly");

	/*
	 * A fill between the two calls must not move the buffer out from under
	 * the pointer we are still holding.
	 */
	push(them, "third\n");
	(void)linebuf_fill(&buf, us);
	eq(first, "first", "and survives a fill while still held");

	ok(linebuf_next_line(&buf, &second, &len) == 1, "the next line comes out");
	eq(second, "second", "and is the one after it, not a repeat");

	linebuf_free(&buf);
	(void)close(us);
	(void)close(them);
}

static void
test_caps(void)
{
	struct linebuf	 buf;
	char		*big;
	int		 us, them;

	printf("\nB1.3 the input cap\n");

	if (pair_open(&us, &them) != 0) {
		ok(0, "could not make a socketpair");
		return;
	}

	big = malloc(8192);
	if (big == NULL) {
		ok(0, "out of memory");
		(void)close(us);
		(void)close(them);
		return;
	}
	memset(big, 'a', 8192);

	/* A small cap, so the test does not have to push 64 KiB. */
	linebuf_init(&buf);
	buf.read_max = 4096;

	push(them, big);
	errno = 0;
	ok(linebuf_fill(&buf, us) == -1 && errno == EMSGSIZE,
	    "a line past read_max is refused with EMSGSIZE");

	linebuf_free(&buf);

	/* The default applies when read_max is left at zero. */
	linebuf_init(&buf);
	push(them, big);
	ok(linebuf_fill(&buf, us) == 0,
	    "the same data fits under the default cap");

	free(big);
	linebuf_free(&buf);
	(void)close(us);
	(void)close(them);
}

static void
test_send(void)
{
	struct linebuf	 buf, peer;
	char		*line;
	size_t		 len;
	int		 us, them;

	printf("\nsending\n");

	if (pair_open(&us, &them) != 0) {
		ok(0, "could not make a socketpair");
		return;
	}
	linebuf_init(&buf);
	linebuf_init(&peer);

	ok(linebuf_send(&buf, us, "{\"id\":1}\n") == 0, "a line sends");
	ok(buf.write_len == 0, "and leaves nothing buffered, the socket took it");
	ok(buf.has_unwritten == 0, "so no writability watch is needed");

	ok(linebuf_fill(&peer, them) == 0, "the peer reads it");
	ok(linebuf_next_line(&peer, &line, &len) == 1, "and gets a line");
	eq(line, "{\"id\":1}", "byte for byte");

	linebuf_free(&buf);
	linebuf_free(&peer);
	(void)close(us);
	(void)close(them);
}

/*
 * Fill the socket until the kernel stops accepting, which is what exercises
 * the partial write path. With nobody reading the other end, the
 * send buffer fills and write() starts returning EAGAIN.
 */
static void
test_partial_write(void)
{
	struct linebuf	 buf;
	char		*chunk;
	size_t		 i;
	int		 us, them, buffered = 0;

	printf("\npartial writes\n");

	if (pair_open(&us, &them) != 0) {
		ok(0, "could not make a socketpair");
		return;
	}

	chunk = malloc(4097);
	if (chunk == NULL) {
		ok(0, "out of memory");
		(void)close(us);
		(void)close(them);
		return;
	}
	memset(chunk, 'x', 4095);
	chunk[4095] = '\n';
	chunk[4096] = '\0';

	linebuf_init(&buf);
	buf.write_max = (size_t)4 * 1024 * 1024;

	/* Nobody is reading them, so this must eventually back up. */
	for (i = 0; i < 256; i++) {
		if (linebuf_send(&buf, us, chunk) != 0)
			break;
		if (buf.write_len > 0) {
			buffered = 1;
			break;
		}
	}

	ok(buffered, "the socket eventually stops accepting and output buffers");
	ok(buf.has_unwritten == 1, "and has_unwritten is set so the caller waits");

	/* Draining the peer lets the rest go out. */
	{
		char	 sink[4096];
		ssize_t	 n;
		int	 drained = 0;

		for (i = 0; i < 4096; i++) {
			n = read(them, sink, sizeof(sink));
			if (n <= 0)
				break;
			if (linebuf_flush(&buf, us) != 0)
				break;
			if (buf.write_len == 0) {
				drained = 1;
				break;
			}
		}
		ok(drained, "and a flush after the peer reads clears it");
		ok(buf.has_unwritten == 0, "leaving has_unwritten clear");
	}

	free(chunk);
	linebuf_free(&buf);
	(void)close(us);
	(void)close(them);
}

static void
test_closed_peer(void)
{
	struct linebuf	 buf;
	int		 us, them;

	printf("\na closed peer\n");

	if (pair_open(&us, &them) != 0) {
		ok(0, "could not make a socketpair");
		return;
	}
	linebuf_init(&buf);

	(void)close(them);

	errno = EINVAL;			/* so errno == 0 means it was set */
	ok(linebuf_fill(&buf, us) == -1 && errno == 0,
	    "a clean close is -1 with errno 0, per linebuf.h");

	linebuf_free(&buf);
	(void)close(us);
}

int
main(void)
{
	test_framing();
	test_pointer_lifetime();
	test_caps();
	test_send();
	test_partial_write();
	test_closed_peer();

	if (btmgr_mc_report() != 0) {
		printf("memcheck: allocations still live\n");
		failures++;
	}

	printf("\n%d checks, %d failures\n", checks, failures);

	return (failures != 0);
}

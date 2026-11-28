/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * safefile.c - the A0 write discipline. SPEC.md Part A, section A0.
 */

#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "safefile.h"

/*
 * Must come after the system headers: it redefines malloc and friends. The
 * pragma says so to clang-include-cleaner, which sees no direct use of this
 * header because the use is macro replacement of malloc(), not a symbol.
 */
#include "memcheck.h"	/* IWYU pragma: keep */

static int	 ensure_backup(const char *path, char *err, size_t errlen);
static int	 copy_preserving(const char *src, const char *dst,
		     char *err, size_t errlen);
static int	 write_all(int fd, const void *buf, size_t len);
static void	 seterr(char *err, size_t errlen, const char *fmt, ...)
		     __printflike(3, 4);

/*
 * Format a message into err without disturbing errno, which the caller
 * promises to leave intact for its own caller.
 */
static void
seterr(char *err, size_t errlen, const char *fmt, ...)
{
	va_list	 ap;
	int	 saved;

	if (err == NULL || errlen == 0)
		return;

	saved = errno;
	va_start(ap, fmt);
	(void)vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
	errno = saved;
}

void
safefile_init(struct safefile_ctx *context, int dry_run)
{

	memset(context, 0, sizeof(*context));
	context->dry_run = dry_run;
}

char *
safefile_read(const char *path, size_t *lenp)
{
	struct stat	 sb;
	char		*buf;
	ssize_t		 n;
	size_t		 off, want;
	int		 fd, saved;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return (NULL);

	if (fstat(fd, &sb) == -1) {
		saved = errno;
		close(fd);
		errno = saved;
		return (NULL);
	}

	/*
	 * Refuse anything that is not a plain file. A symlink we followed to a
	 * device, or a fifo, would block here or return nonsense, and these
	 * paths are attacker-adjacent enough to be worth the check.
	 */
	if (!S_ISREG(sb.st_mode)) {
		close(fd);
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * st_size is a hint, not a contract: the file can grow or shrink under
	 * us. Read until EOF and grow as needed rather than trusting it.
	 */
	want = (size_t)sb.st_size + 1;
	buf = malloc(want);
	if (buf == NULL) {
		saved = errno;
		close(fd);
		errno = saved;
		return (NULL);
	}

	off = 0;
	for (;;) {
		if (off + 1 >= want) {
			char	*nbuf;

			want *= 2;
			nbuf = realloc(buf, want);
			if (nbuf == NULL) {
				saved = errno;
				free(buf);
				close(fd);
				errno = saved;
				return (NULL);
			}
			buf = nbuf;
		}
		n = read(fd, buf + off, want - off - 1);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			saved = errno;
			free(buf);
			close(fd);
			errno = saved;
			return (NULL);
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}

	close(fd);
	buf[off] = '\0';
	if (lenp != NULL)
		*lenp = off;
	return (buf);
}

/*
 * Copy source to destination with its mode and, if we may, its owner. Written
 * to a temporary file and renamed, so a symlink at destination is replaced.
 */
static int
copy_preserving(const char *source, const char *destination, char *err,
    size_t errlen)
{
	struct stat	 status;
	char		 buffer[65536], temporary[PATH_MAX];
	ssize_t		 count;
	int		 input, output = -1, created = 0, saved_errno;

	if ((size_t)snprintf(temporary, sizeof(temporary), "%s.XXXXXX",
	    destination) >= sizeof(temporary)) {
		seterr(err, errlen, "temp path for %s too long", destination);
		errno = ENAMETOOLONG;
		return (-1);
	}

	input = open(source, O_RDONLY | O_CLOEXEC);
	if (input == -1) {
		seterr(err, errlen, "open %s: %s", source, strerror(errno));
		return (-1);
	}
	if (fstat(input, &status) == -1) {
		seterr(err, errlen, "fstat %s: %s", source, strerror(errno));
		goto fail;
	}

	output = mkstemp(temporary);
	if (output == -1) {
		seterr(err, errlen, "mkstemp %s: %s", temporary, strerror(errno));
		goto fail;
	}
	created = 1;

	for (;;) {
		count = read(input, buffer, sizeof(buffer));
		if (count == -1) {
			if (errno == EINTR)
				continue;
			seterr(err, errlen, "read %s: %s", source, strerror(errno));
			goto fail;
		}
		if (count == 0)
			break;
		if (write_all(output, buffer, (size_t)count) == -1) {
			seterr(err, errlen, "write %s: %s", temporary, strerror(errno));
			goto fail;
		}
	}

	/* Owner before mode, since fchown(2) can clear setuid and setgid. */
	if (fchown(output, status.st_uid, status.st_gid) == -1 && errno != EPERM && errno != EINVAL) {
		seterr(err, errlen, "fchown %s: %s", temporary, strerror(errno));
		goto fail;
	}
	if (fchmod(output, status.st_mode & ALLPERMS) == -1) {
		seterr(err, errlen, "fchmod %s: %s", temporary, strerror(errno));
		goto fail;
	}
	if (fsync(output) == -1) {
		seterr(err, errlen, "fsync %s: %s", temporary, strerror(errno));
		goto fail;
	}
	if (close(output) == -1) {
		output = -1;
		seterr(err, errlen, "close %s: %s", temporary, strerror(errno));
		goto fail;
	}
	output = -1;

	if (rename(temporary, destination) == -1) {
		seterr(err, errlen, "rename %s to %s: %s", temporary, destination, strerror(errno));
		goto fail;
	}
	close(input);

	return (0);

fail:
	saved_errno = errno;
	if (output != -1)
		close(output);
	if (created)
		unlink(temporary);
	close(input);
	errno = saved_errno;

	return (-1);
}

/* A0.2: copy the file before its first change; an existing .bak is never touched. */
static int
ensure_backup(const char *path, char *err, size_t errlen)
{
	struct stat	 status;
	char		 backup[PATH_MAX];

	if ((size_t)snprintf(backup, sizeof(backup), "%s.bak", path) >= sizeof(backup)) {
		seterr(err, errlen, "backup path for %s too long", path);
		errno = ENAMETOOLONG;
		return (-1);
	}

	if (lstat(backup, &status) == 0 || access(path, F_OK) != 0)
		return (0);

	return (copy_preserving(path, backup, err, errlen));
}

static int
write_all(int fd, const void *buf, size_t len)
{
	const char	*p = buf;
	ssize_t		 n;

	while (len > 0) {
		n = write(fd, p, len);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		p += n;
		len -= (size_t)n;
	}
	return (0);
}

int
safefile_write(const struct safefile_ctx *context, const char *path,
    mode_t mode, const void *buf, size_t len, char *err, size_t errlen)
{
	char	*current;
	size_t	 current_length;
	int	 descriptor, saved_errno;

	if (err != NULL && errlen > 0)
		err[0] = '\0';

	/* A0.5 before the backup, so an identical write never makes a .bak. */
	current = safefile_read(path, &current_length);
	if (current != NULL) {
		if (current_length == len && (len == 0 || memcmp(current, buf, len) == 0)) {
			free(current);
			return (SAFEFILE_UNCHANGED);
		}
		free(current);
	} else if (errno != ENOENT) {
		seterr(err, errlen, "read %s: %s", path, strerror(errno));
		return (SAFEFILE_ERROR);
	}

	if (context->dry_run)
		return (SAFEFILE_DRYRUN);

	if (ensure_backup(path, err, errlen) == -1)
		return (SAFEFILE_ERROR);

	/* A0.1, A0.6: edited in place, so an existing file keeps its owner and mode. */
	descriptor = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, mode);
	if (descriptor == -1) {
		seterr(err, errlen, "open %s: %s", path, strerror(errno));
		return (SAFEFILE_ERROR);
	}

	if (write_all(descriptor, buf, len) == -1 || ftruncate(descriptor, (off_t)len) == -1 ||
	    fsync(descriptor) == -1) {
		seterr(err, errlen, "write %s: %s", path, strerror(errno));
		saved_errno = errno;
		(void)close(descriptor);
		errno = saved_errno;
		return (SAFEFILE_ERROR);
	}

	if (close(descriptor) == -1) {
		seterr(err, errlen, "close %s: %s", path, strerror(errno));
		return (SAFEFILE_ERROR);
	}

	return (SAFEFILE_WRITTEN);
}

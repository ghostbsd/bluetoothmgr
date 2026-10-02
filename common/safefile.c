/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * safefile.c - the A0 write discipline. SPEC.md Part A, section A0.
 *
 * See safefile.h for which rule each piece implements and why the per-boot
 * marker is a file rather than a clock comparison.
 */

#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
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

static int	 marker_path(const struct safefile_ctx *ctx, const char *path,
		     char *out, size_t outlen);
static int	 ensure_backup(const struct safefile_ctx *ctx,
		     const char *path, char *err, size_t errlen);
static int	 copy_preserving(const char *src, const char *dst,
		     char *err, size_t errlen);
static int	 write_all(int fd, const void *buf, size_t len);
static int	 sync_dir(const char *path);
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

int
safefile_init(struct safefile_ctx *ctx, const char *rundir, int dry_run)
{
	const char	*dir;

	memset(ctx, 0, sizeof(*ctx));
	dir = (rundir != NULL) ? rundir : SAFEFILE_RUNDIR;

	if (strlcpy(ctx->rundir, dir, sizeof(ctx->rundir)) >=
	    sizeof(ctx->rundir)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	ctx->dry_run = dry_run;
	return (0);
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
 * Name the per-boot marker for a target path.
 *
 * basename plus a hash of the whole path: the basename is there so someone
 * looking in /var/run can tell what the marker is for, and the hash is there
 * because two directories can hold the same basename. FNV-1a, which is not a
 * security property here, only a spread.
 */
static int
marker_path(const struct safefile_ctx *ctx, const char *path, char *out,
    size_t outlen)
{
	const char	*base;
	uint64_t	 h;
	size_t		 i;

	h = 14695981039346656037ULL;
	for (i = 0; path[i] != '\0'; i++) {
		h ^= (unsigned char)path[i];
		h *= 1099511628211ULL;
	}

	base = strrchr(path, '/');
	if (base != NULL)
		base++;
	else
		base = path;
	if (*base == '\0')
		base = "unnamed";

	if ((size_t)snprintf(out, outlen, "%s/%.64s.%016llx", ctx->rundir,
	    base, (unsigned long long)h) >= outlen) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	return (0);
}

/*
 * Copy src to dst, preserving mode and, if we have the privilege, ownership.
 *
 * Not atomic, and deliberately so: dst is a .bak that nothing else reads, and
 * making this atomic too would mean a temp file whose own failure modes need
 * the same care. What matters is that we never get here twice per boot.
 */
static int
copy_preserving(const char *src, const char *dst, char *err, size_t errlen)
{
	struct stat	 sb;
	char		 buf[65536];
	ssize_t		 n;
	int		 in, out, saved;

	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in == -1) {
		seterr(err, errlen, "open %s: %s", src, strerror(errno));
		return (-1);
	}
	if (fstat(in, &sb) == -1) {
		seterr(err, errlen, "fstat %s: %s", src, strerror(errno));
		goto fail_in;
	}

	/* 0600 until the content is in place, then the source's real mode. */
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out == -1) {
		seterr(err, errlen, "open %s: %s", dst, strerror(errno));
		goto fail_in;
	}

	for (;;) {
		n = read(in, buf, sizeof(buf));
		if (n == -1) {
			if (errno == EINTR)
				continue;
			seterr(err, errlen, "read %s: %s", src,
			    strerror(errno));
			goto fail_out;
		}
		if (n == 0)
			break;
		if (write_all(out, buf, (size_t)n) == -1) {
			seterr(err, errlen, "write %s: %s", dst,
			    strerror(errno));
			goto fail_out;
		}
	}

	/*
	 * Ownership before mode: fchown(2) clears the setuid and setgid bits
	 * on some systems, so setting the mode afterwards is what makes the
	 * copy faithful. Not being root is normal here, since the test harness
	 * runs unprivileged, and a .bak that we could not chown is still a
	 * correct backup of the content.
	 */
	if (fchown(out, sb.st_uid, sb.st_gid) == -1 &&
	    errno != EPERM && errno != EINVAL) {
		seterr(err, errlen, "fchown %s: %s", dst, strerror(errno));
		goto fail_out;
	}
	if (fchmod(out, sb.st_mode & ALLPERMS) == -1) {
		seterr(err, errlen, "fchmod %s: %s", dst, strerror(errno));
		goto fail_out;
	}
	if (fsync(out) == -1) {
		seterr(err, errlen, "fsync %s: %s", dst, strerror(errno));
		goto fail_out;
	}
	if (close(out) == -1) {
		seterr(err, errlen, "close %s: %s", dst, strerror(errno));
		close(in);
		return (-1);
	}
	close(in);
	return (0);

fail_out:
	saved = errno;
	close(out);
	unlink(dst);
	errno = saved;
fail_in:
	saved = errno;
	close(in);
	errno = saved;
	return (-1);
}

/*
 * A0.2. Make sure this boot's backup of path exists, then record that we have
 * done it.
 *
 * The marker is written even when there was nothing to back up, because a file
 * that did not exist before we ran has no pre-BluetoothMgr state to preserve.
 * Without the marker, our second write of a file we created ourselves would
 * "back up" our own first write and call it the user's original.
 */
static int
ensure_backup(const struct safefile_ctx *ctx, const char *path, char *err,
    size_t errlen)
{
	char	 marker[PATH_MAX], bak[PATH_MAX];
	int	 fd;

	if (marker_path(ctx, path, marker, sizeof(marker)) == -1) {
		seterr(err, errlen, "marker path for %s too long", path);
		return (-1);
	}

	if (access(marker, F_OK) == 0)
		return (0);		/* already backed up this boot */

	if (mkdir(ctx->rundir, 0755) == -1 && errno != EEXIST) {
		seterr(err, errlen, "mkdir %s: %s", ctx->rundir,
		    strerror(errno));
		return (-1);
	}

	if (access(path, F_OK) == 0) {
		if ((size_t)snprintf(bak, sizeof(bak), "%s.bak", path) >=
		    sizeof(bak)) {
			seterr(err, errlen, "backup path for %s too long",
			    path);
			errno = ENAMETOOLONG;
			return (-1);
		}
		if (copy_preserving(path, bak, err, errlen) == -1)
			return (-1);
	}

	/*
	 * O_EXCL so that two daemons racing here cannot both conclude they own
	 * the backup. Losing the race means someone else just made it, which
	 * is the result we wanted anyway.
	 */
	fd = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (fd == -1) {
		if (errno == EEXIST)
			return (0);
		seterr(err, errlen, "create %s: %s", marker, strerror(errno));
		return (-1);
	}
	close(fd);
	return (0);
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

/*
 * fsync the directory holding path, so the rename itself is durable and not
 * just the bytes it points at. Without this a crash can leave the old name
 * intact on a filesystem that has already discarded the new file's blocks.
 */
static int
sync_dir(const char *path)
{
	char		 dir[PATH_MAX];
	const char	*slash;
	int		 fd, rc, saved;

	slash = strrchr(path, '/');
	if (slash == NULL) {
		if (strlcpy(dir, ".", sizeof(dir)) >= sizeof(dir))
			return (-1);
	} else {
		size_t	n = (size_t)(slash - path);

		if (n == 0)
			n = 1;		/* the file is directly in "/" */
		if (n >= sizeof(dir)) {
			errno = ENAMETOOLONG;
			return (-1);
		}
		memcpy(dir, path, n);
		dir[n] = '\0';
	}

	fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd == -1)
		return (-1);
	rc = fsync(fd);
	saved = errno;
	close(fd);
	errno = saved;
	return (rc);
}

int
safefile_write(const struct safefile_ctx *ctx, const char *path,
    mode_t mode, const void *buf, size_t len, char *err, size_t errlen)
{
	struct stat	 sb;
	char		 tmp[PATH_MAX];
	char		*cur;
	size_t		 curlen;
	mode_t		 target_mode;
	int		 fd, have_old, saved;

	if (err != NULL && errlen > 0)
		err[0] = '\0';

	/*
	 * A0.5 first, before the backup: a write that changes nothing must not
	 * consume this boot's one backup slot, or a daemon that starts, emits
	 * an identical file and exits would replace the user's .bak with a
	 * copy of a file we had already rewritten.
	 */
	have_old = 0;
	target_mode = mode;
	cur = safefile_read(path, &curlen);
	if (cur != NULL) {
		if (curlen == len && (len == 0 || memcmp(cur, buf, len) == 0)) {
			free(cur);
			return (SAFEFILE_UNCHANGED);
		}
		free(cur);

		/*
		 * An existing file keeps its own mode and ownership, so we
		 * need its stat. Only a successful stat sets have_old, because
		 * have_old is what later licenses reading sb: treating a
		 * failed stat as "the file is there" would hand fchown(2) an
		 * uninitialised uid.
		 */
		if (stat(path, &sb) == 0) {
			have_old = 1;
			target_mode = sb.st_mode & ALLPERMS;
		}
	} else if (errno != ENOENT) {
		seterr(err, errlen, "read %s: %s", path, strerror(errno));
		return (SAFEFILE_ERROR);
	}

	if (ctx->dry_run)
		return (SAFEFILE_DRYRUN);

	if (ensure_backup(ctx, path, err, errlen) == -1)
		return (SAFEFILE_ERROR);

	/*
	 * A0.1: the temp file lives in the target's own directory, so that the
	 * rename is within one filesystem and therefore atomic. /tmp would not
	 * do: rename(2) across filesystems fails with EXDEV, and copying
	 * instead would reintroduce the partial write we are here to avoid.
	 */
	if ((size_t)snprintf(tmp, sizeof(tmp), "%s.btmgr.XXXXXX", path) >=
	    sizeof(tmp)) {
		seterr(err, errlen, "temp path for %s too long", path);
		errno = ENAMETOOLONG;
		return (SAFEFILE_ERROR);
	}

	/* A0.6: mkstemp creates O_EXCL, mode 0600. */
	fd = mkstemp(tmp);
	if (fd == -1) {
		seterr(err, errlen, "mkstemp %s: %s", tmp, strerror(errno));
		return (SAFEFILE_ERROR);
	}

	if (write_all(fd, buf, len) == -1) {
		seterr(err, errlen, "write %s: %s", tmp, strerror(errno));
		goto fail;
	}

	/*
	 * Ownership, then mode, then fsync, then rename. Each step has to land
	 * before the file becomes visible under its real name, because after
	 * the rename there is no moment at which a reader would tolerate the
	 * file having the wrong permissions: hcsecd.conf holds link keys.
	 */
	if (have_old && fchown(fd, sb.st_uid, sb.st_gid) == -1 &&
	    errno != EPERM && errno != EINVAL) {
		seterr(err, errlen, "fchown %s: %s", tmp, strerror(errno));
		goto fail;
	}
	if (fchmod(fd, target_mode) == -1) {
		seterr(err, errlen, "fchmod %s: %s", tmp, strerror(errno));
		goto fail;
	}
	if (fsync(fd) == -1) {
		seterr(err, errlen, "fsync %s: %s", tmp, strerror(errno));
		goto fail;
	}
	if (close(fd) == -1) {
		seterr(err, errlen, "close %s: %s", tmp, strerror(errno));
		saved = errno;
		unlink(tmp);
		errno = saved;
		return (SAFEFILE_ERROR);
	}

	if (rename(tmp, path) == -1) {
		seterr(err, errlen, "rename %s to %s: %s", tmp, path,
		    strerror(errno));
		saved = errno;
		unlink(tmp);
		errno = saved;
		return (SAFEFILE_ERROR);
	}

	/*
	 * A failure to sync the directory is not worth undoing the write: the
	 * new content is already the visible one, and unwinding would mean
	 * restoring a file we no longer hold. Report it and carry on.
	 */
	if (sync_dir(path) == -1)
		seterr(err, errlen, "fsync directory of %s: %s", path,
		    strerror(errno));

	return (SAFEFILE_WRITTEN);

fail:
	saved = errno;
	close(fd);
	unlink(tmp);
	errno = saved;
	return (SAFEFILE_ERROR);
}

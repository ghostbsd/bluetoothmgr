/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * storefile.c - loading devices.json, with the A4.3 recovery.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "storefile.h"

/* After the system headers: it redefines malloc. */
#include "memcheck.h"	/* IWYU pragma: keep */

static int	read_store(const char *path, char **text, size_t *length,
		    struct stat *identity);
static int	set_aside(const char *path, const struct stat *identity);

/* 0 with *text NULL for a missing file; -1 for any other failure. */
static int
read_store(const char *path, char **text, size_t *length,
    struct stat *identity)
{
	char	*buffer;
	size_t	 size, got = 0;
	ssize_t	 n;
	int	 fd, saved;

	*text = NULL;
	*length = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);

	if (fstat(fd, identity) != 0) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}
	if (!S_ISREG(identity->st_mode)) {
		(void)close(fd);
		errno = EFTYPE;
		return (-1);
	}

	size = (size_t)identity->st_size;
	buffer = malloc(size + 1);
	if (buffer == NULL) {
		(void)close(fd);
		errno = ENOMEM;
		return (-1);
	}

	while (got < size) {
		n = read(fd, buffer + got, size - got);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			saved = errno;
			free(buffer);
			(void)close(fd);
			errno = saved;
			return (-1);
		}
		if (n == 0)
			break;
		got += (size_t)n;
	}
	(void)close(fd);

	buffer[got] = '\0';
	*text = buffer;
	*length = got;

	return (0);
}

/*
 * Keep a hard link to the file as path.bad, or path.bad.N if that is taken.
 * The file itself stays until the caller writes a new one over it.
 */
static int
set_aside(const char *path, const struct stat *identity)
{
	struct stat	linked;
	char		bad[PATH_MAX];
	int		attempt, length;

	/* Already linked aside by an earlier load. */
	if (identity->st_nlink > 1)
		return (0);

	for (attempt = 0; attempt < INT_MAX; attempt++) {
		if (attempt == 0)
			length = snprintf(bad, sizeof(bad), "%s%s", path,
			    STORE_BAD_SUFFIX);
		else
			length = snprintf(bad, sizeof(bad), "%s%s.%d", path,
			    STORE_BAD_SUFFIX, attempt);
		if (length < 0 || length >= (int)sizeof(bad))
			return (-1);

		if (link(path, bad) == 0) {
			/* Replaced since it was read: leave it alone. */
			if (stat(bad, &linked) != 0 ||
			    linked.st_dev != identity->st_dev ||
			    linked.st_ino != identity->st_ino) {
				(void)unlink(bad);
				errno = EAGAIN;
				return (-1);
			}
			return (0);
		}
		if (errno != EEXIST)
			return (-1);
	}

	return (-1);
}

enum store_load_result
store_load(const struct btmgr_paths *paths, struct store **out)
{
	struct stat	 identity;
	struct store	*st;
	char		*text;
	size_t		 length, skipped = 0;
	int		 malformed = 0;

	*out = NULL;

	if (read_store(paths->store, &text, &length, &identity) != 0)
		return (STORE_LOAD_ERROR);

	st = store_parse(text, &malformed, &skipped);
	if (text != NULL && length == 0)
		malformed = 1;
	free(text);
	if (st == NULL)
		return (STORE_LOAD_ERROR);

	if (!malformed && skipped == 0) {
		*out = st;
		return (STORE_LOAD_OK);
	}

	if (!paths->sf.dry_run && set_aside(paths->store, &identity) != 0) {
		store_free(st);
		return (STORE_LOAD_ERROR);
	}

	*out = st;

	return (STORE_LOAD_SET_ASIDE);
}

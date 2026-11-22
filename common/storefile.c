/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * storefile.c - loading devices.json, with the A4.3 recovery.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "safefile.h"
#include "storefile.h"

/* After the system headers: it redefines malloc. */
#include "memcheck.h"	/* IWYU pragma: keep */

#define	STORE_BAD_MAX	100

static int	set_aside(const char *path);

/*
 * Move path to path.bad, or path.bad.1 and on if that is taken. link() rather
 * than rename(), because rename() would replace an earlier bad file.
 */
static int
set_aside(const char *path)
{
	char	bad[PATH_MAX];
	int	attempt, length, saved;

	for (attempt = 0; attempt < STORE_BAD_MAX; attempt++) {
		if (attempt == 0)
			length = snprintf(bad, sizeof(bad), "%s%s", path,
			    STORE_BAD_SUFFIX);
		else
			length = snprintf(bad, sizeof(bad), "%s%s.%d", path,
			    STORE_BAD_SUFFIX, attempt);
		if (length < 0 || length >= (int)sizeof(bad))
			return (-1);

		if (link(path, bad) == 0) {
			if (unlink(path) == 0)
				return (0);
			saved = errno;
			(void)unlink(bad);
			errno = saved;
			return (-1);
		}
		if (errno != EEXIST)
			return (-1);
	}

	return (-1);
}

enum store_load_result
store_load(const struct btmgr_paths *paths, struct store **out)
{
	char		*text;
	struct store	*st;
	size_t		 length = 0;
	int		 malformed = 0;

	*out = NULL;

	/* Only a missing file is an empty store; an unreadable one is not. */
	errno = 0;
	text = safefile_read(paths->store, &length);
	if (text == NULL && errno != ENOENT)
		return (STORE_LOAD_ERROR);

	st = store_parse(text, &malformed, NULL);
	if (text != NULL && length == 0)
		malformed = 1;
	free(text);
	if (st == NULL)
		return (STORE_LOAD_ERROR);

	if (!malformed) {
		*out = st;
		return (STORE_LOAD_OK);
	}

	if (!paths->sf.dry_run && set_aside(paths->store) != 0) {
		store_free(st);
		return (STORE_LOAD_ERROR);
	}

	*out = st;

	return (STORE_LOAD_SET_ASIDE);
}

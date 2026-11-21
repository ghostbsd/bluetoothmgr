/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * storefile.c - loading devices.json, with the A4.3 recovery.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "safefile.h"
#include "storefile.h"

/* After the system headers: it redefines malloc. */
#include "memcheck.h"	/* IWYU pragma: keep */

enum store_load_result
store_load(const struct btmgr_paths *paths, struct store **out)
{
	char		 bad[PATH_MAX];
	char		*text;
	struct store	*st;
	int		 malformed = 0;

	*out = NULL;

	text = safefile_read(paths->store, NULL);
	st = store_parse(text, &malformed, NULL);
	free(text);
	if (st == NULL)
		return (STORE_LOAD_ERROR);

	if (!malformed) {
		*out = st;
		return (STORE_LOAD_OK);
	}

	if (!paths->sf.dry_run &&
	    (snprintf(bad, sizeof(bad), "%s%s", paths->store,
	    STORE_BAD_SUFFIX) >= (int)sizeof(bad) ||
	    rename(paths->store, bad) != 0)) {
		store_free(st);
		return (STORE_LOAD_ERROR);
	}

	*out = st;

	return (STORE_LOAD_SET_ASIDE);
}

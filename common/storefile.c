/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * storefile.c - loading devices.json. SPEC.md A4.
 */

#include <stdlib.h>

#include "safefile.h"
#include "storefile.h"

/* After the system headers: it redefines malloc. */
#include "memcheck.h"	/* IWYU pragma: keep */

struct store *
store_load(const struct btmgr_paths *paths)
{
	struct store	*store;
	char		*text;

	text = safefile_read(paths->store, NULL);
	store = store_parse(text, NULL, NULL);
	free(text);

	return (store);
}

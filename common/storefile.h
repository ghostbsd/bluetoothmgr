/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * storefile.h - loading devices.json, with the A4.3 recovery.
 */

#ifndef BTMGR_STOREFILE_H_
#define	BTMGR_STOREFILE_H_

#include "paths.h"
#include "store.h"

#define	STORE_BAD_SUFFIX	".bad"

enum store_load_result {
	STORE_LOAD_ERROR	= -1,
	STORE_LOAD_OK		= 0,
	STORE_LOAD_SET_ASIDE	= 1
};

/*
 * A missing file is an empty store. A malformed one is renamed to
 * <path>.bad and an empty store returned; a dry run renames nothing.
 * STORE_LOAD_ERROR, with *out NULL, means out of memory or a bad file that
 * could not be renamed, which must then not be written over.
 */
enum store_load_result store_load(const struct btmgr_paths *paths,
	    struct store **out);

#endif

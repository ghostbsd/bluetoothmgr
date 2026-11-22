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

/* On STORE_LOAD_ERROR, *out is NULL and the file must not be written. */
enum store_load_result store_load(const struct btmgr_paths *paths,
	    struct store **out);

#endif

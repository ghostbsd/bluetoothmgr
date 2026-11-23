/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * storefile.h - loading devices.json. SPEC.md A4.
 */

#ifndef BTMGR_STOREFILE_H_
#define	BTMGR_STOREFILE_H_

#include "paths.h"
#include "store.h"

/* Empty before the first pairing. NULL only when out of memory. */
struct store	*store_load(const struct btmgr_paths *paths);

#endif

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * paths.h - where the config files are, and the safefile context with the dry
 * run flag. The test harnesses fill in their own scratch paths instead.
 */

#ifndef BTMGR_PATHS_H_
#define	BTMGR_PATHS_H_

#include <limits.h>

#include "safefile.h"

/* The real locations, when no root is given. */
#define	BTMGR_ETCDIR		"/etc/bluetooth"
#define	BTMGR_HOSTS		BTMGR_ETCDIR "/hosts"
#define	BTMGR_HCSECD_CONF	BTMGR_ETCDIR "/hcsecd.conf"
#define	BTMGR_HCSECD_KEYS	"/var/db/hcsecd.keys"
#define	BTMGR_STOREDIR		"/var/db/bluetoothmgr"
#define	BTMGR_STORE		BTMGR_STOREDIR "/devices.json"

/* A4: directory 0700, file 0600. A2: hosts is world readable. A1: 0600. */
#define	BTMGR_MODE_HOSTS	0644
#define	BTMGR_MODE_HCSECD	0600
#define	BTMGR_MODE_KEYS		0600
#define	BTMGR_MODE_STORE	0600
#define	BTMGR_MODE_STOREDIR	0700

struct btmgr_paths {
	char			hosts[PATH_MAX];
	char			hcsecd[PATH_MAX];
	char			keys[PATH_MAX];
	char			store[PATH_MAX];
	char			storedir[PATH_MAX];
	struct safefile_ctx	sf;
};

void	btmgr_paths_init(struct btmgr_paths *p, int dry_run);

/* Create the files' directories: the A4 store directory 0700, the rest 0755. */
int	btmgr_paths_mkdirs(const struct btmgr_paths *p);

#endif /* !BTMGR_PATHS_H_ */

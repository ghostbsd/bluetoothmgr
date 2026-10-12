/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * paths.h - where the config files are, and whether we are allowed to write.
 *
 * Every path M3b touches comes from here, so that a whole run can be pointed at
 * copies under /tmp. That is not only for the tests: it is how someone can
 * exercise the pairing sequence against a throwaway tree before letting it near
 * /etc, which is the last checklist item of M3b.
 *
 * Holds the safefile_ctx too, so --dry-run is one flag in one place rather than
 * a parameter threaded through every generator.
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

/*
 * The recommended root for a --dry-run or -r trial. It sits inside
 * BTMGR_STOREDIR, which A4 already requires to be 0700 and root owned, so a
 * sandbox copy inherits that protection.
 *
 * Do NOT use a world-writable directory such as /tmp for this. A sandbox copy
 * of hcsecd.conf carries real PINs and link keys, and a predictable name under
 * /tmp also lets another user pre-create a path component as a symlink. A
 * mkdtemp(3) directory is acceptable, since it is 0700 with an unpredictable
 * name, and that is what the test harnesses use.
 */
#define	BTMGR_SANDBOX		BTMGR_STOREDIR "/sandbox"

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

/*
 * Fill in every path. root NULL selects the real system locations. Otherwise
 * each path is that same layout underneath root, so root "/tmp/x" gives
 * /tmp/x/etc/bluetooth/hosts and so on, and the per-boot backup markers of A0.2
 * go under root too rather than into the real /var/run.
 *
 * dry_run is passed to the safefile context, so nothing is written whatever the
 * paths say.
 *
 * Returns 0, or -1 with errno set to ENAMETOOLONG if root is too long for any
 * of the paths to fit.
 */
int	btmgr_paths_init(struct btmgr_paths *p, const char *root, int dry_run);

/*
 * Create the directories the files live in, the A4 store directory at mode 0700
 * and the rest at 0755, parents included. Note the 0755: a root that this
 * creates is not itself private, which is the other reason BTMGR_SANDBOX sits
 * inside a directory A4 already made 0700. On a real system only the store
 * directory is ever missing; under a root, none of them exist and
 * safefile_write() needs the target's directory before it can place its temp
 * file. Existing directories are success. A dry run creates nothing.
 */
int	btmgr_paths_mkdirs(const struct btmgr_paths *p);

#endif /* !BTMGR_PATHS_H_ */

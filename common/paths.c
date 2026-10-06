/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * paths.c - where the config files are. See paths.h.
 */

#include <sys/stat.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "paths.h"
#include "safefile.h"

static int	 join(char *out, size_t outlen, const char *root,
		     const char *tail);
static int	 mkpath(const char *path, mode_t mode);
static int	 mkparent(const char *file, mode_t mode);

/*
 * root + tail, or just tail when root is NULL. A trailing slash on root is
 * tolerated so that "/tmp/x" and "/tmp/x/" behave the same.
 */
static int
join(char *out, size_t outlen, const char *root, const char *tail)
{
	int	 n;

	{
		size_t	 rootlen = root == NULL ? 0 : strlen(root);

		/* Trailing slashes are noise: "/tmp/x", "/tmp/x/" and
		 * "/tmp/x///" all name the same directory. */
		while (rootlen > 0 && root[rootlen - 1] == '/')
			rootlen--;

		/*
		 * Nothing left means no root, which covers NULL, "" and "/".
		 * A root of "/" is the real system root, so it must produce
		 * "/etc/bluetooth/hosts" and not "//etc/bluetooth/hosts".
		 */
		if (rootlen == 0)
			n = snprintf(out, outlen, "%s", tail);
		else
			n = snprintf(out, outlen, "%.*s%s", (int)rootlen,
			    root, tail);
	}

	if (n < 0 || (size_t)n >= outlen) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	return (0);
}

int
btmgr_paths_init(struct btmgr_paths *p, const char *root, int dry_run)
{
	char	 rundir[PATH_MAX];

	memset(p, 0, sizeof(*p));

	/*
	 * A relative root would resolve against the process's working
	 * directory, which a daemonised process does not control and the
	 * person who typed it did not mean.
	 */
	if (root != NULL && *root != '\0' && *root != '/') {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Refuse a world-writable root. A sandbox holds copies of hcsecd.conf
	 * and the key store, so PINs and link keys end up under it, and a
	 * predictable name somewhere like /tmp also lets another user
	 * pre-create a path component as a symlink. A root that does not exist
	 * yet is fine: btmgr_paths_mkdirs() creates it.
	 */
	if (root != NULL && *root != '\0') {
		struct stat	 sb;

		if (stat(root, &sb) == 0 && (sb.st_mode & S_IWOTH) != 0) {
			errno = EPERM;
			return (-1);
		}
	}

	if (join(p->hosts, sizeof(p->hosts), root, BTMGR_HOSTS) != 0 ||
	    join(p->hcsecd, sizeof(p->hcsecd), root, BTMGR_HCSECD_CONF) != 0 ||
	    join(p->keys, sizeof(p->keys), root, BTMGR_HCSECD_KEYS) != 0 ||
	    join(p->store, sizeof(p->store), root, BTMGR_STORE) != 0 ||
	    join(p->storedir, sizeof(p->storedir), root, BTMGR_STOREDIR) != 0 ||
	    join(rundir, sizeof(rundir), root, SAFEFILE_RUNDIR) != 0)
		return (-1);

	/*
	 * The A0.2 markers follow root as well. Leaving them in the real
	 * /var/run would let a test run decide that the real /etc/bluetooth
	 * files had already been backed up this boot.
	 */
	return (safefile_init(&p->sf, rundir, dry_run));
}

/* mkdir -p. An existing directory is success. */
static int
mkpath(const char *path, mode_t mode)
{
	char	 tmp[PATH_MAX];
	char	*p;
	size_t	 len;

	len = strlen(path);
	if (len >= sizeof(tmp)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	memcpy(tmp, path, len + 1);

	/* Intermediate directories get 0755; only the leaf gets mode. */
	for (p = tmp + 1; *p != '\0'; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
			return (-1);
		*p = '/';
	}

	if (mkdir(tmp, mode) != 0 && errno != EEXIST)
		return (-1);

	return (0);
}

/* Create the directory a file lives in. */
static int
mkparent(const char *file, mode_t mode)
{
	char	 dir[PATH_MAX];
	char	*slash;
	size_t	 len;

	len = strlen(file);
	if (len >= sizeof(dir)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	memcpy(dir, file, len + 1);

	slash = strrchr(dir, '/');
	if (slash == NULL || slash == dir)
		return (0);
	*slash = '\0';

	return (mkpath(dir, mode));
}

int
btmgr_paths_mkdirs(const struct btmgr_paths *p)
{

	if (p->sf.dry_run)
		return (0);

	/*
	 * A4 wants the store directory at 0700. The others already exist on a
	 * real system; creating them matters only for a rooted run, where
	 * nothing under root exists yet and safefile_write() needs the target's
	 * directory to be there before it can put its temp file in it.
	 */
	if (mkparent(p->hosts, 0755) != 0 ||
	    mkparent(p->keys, 0755) != 0 ||
	    mkpath(p->storedir, BTMGR_MODE_STOREDIR) != 0 ||
	    mkpath(p->sf.rundir, 0755) != 0)
		return (-1);

	return (0);
}

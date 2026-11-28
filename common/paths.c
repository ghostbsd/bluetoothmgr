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
#include <unistd.h>

#include "paths.h"
#include "safefile.h"

static int	 join(char *path, size_t path_size, const char *root,
		     const char *tail);
static int	 directory_is_safe(const char *path, int allow_sticky);
static int	 secure_root(const char *root);
static int	 mkpath(const char *path, mode_t mode);
static int	 mkparent(const char *file, mode_t mode);

/* root + tail. Trailing slashes go, so a root of "/" is no root at all. */
static int
join(char *path, size_t path_size, const char *root, const char *tail)
{
	size_t	 root_length = root == NULL ? 0 : strlen(root);
	int	 written;

	while (root_length > 0 && root[root_length - 1] == '/')
		root_length--;

	written = snprintf(path, path_size, "%.*s%s", (int)root_length,
	    root_length == 0 ? "" : root, tail);
	if (written < 0 || (size_t)written >= path_size) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	return (0);
}

/* Only we or root can change it: no symlink, and nobody else may write it. */
static int
directory_is_safe(const char *path, int allow_sticky)
{
	struct stat	 status;

	if (lstat(path, &status) != 0)
		return (-1);

	if (!S_ISDIR(status.st_mode) ||
	    (status.st_uid != geteuid() && status.st_uid != 0) ||
	    ((status.st_mode & (S_IWGRP | S_IWOTH)) != 0 &&
	    !(allow_sticky && (status.st_mode & S_ISVTX) != 0))) {
		errno = EPERM;
		return (-1);
	}

	return (0);
}

/*
 * Every directory from / down to root must be safe; root itself may not be
 * sticky. A part not there yet, or not visible to us, is left to mkpath().
 */
static int
secure_root(const char *root)
{
	char	 path[PATH_MAX];
	char	*cursor, separator;
	size_t	 length = strlen(root);

	if (length >= sizeof(path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	memcpy(path, root, length + 1);
	while (length > 0 && path[length - 1] == '/')
		path[--length] = '\0';

	for (cursor = path + 1; length > 0; cursor++) {
		if (*cursor != '/' && *cursor != '\0')
			continue;

		separator = *cursor;
		*cursor = '\0';
		if (directory_is_safe(path, separator != '\0') != 0)
			return (errno == ENOENT || errno == EACCES ? 0 : -1);
		if (separator == '\0')
			break;
		*cursor = separator;
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

	if (root != NULL && *root != '\0' && secure_root(root) != 0)
		return (-1);

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

/* mkdir -p. Whatever already exists must be safe, not just present. */
static int
mkpath(const char *path, mode_t mode)
{
	char	 partial[PATH_MAX];
	char	*cursor;
	size_t	 length = strlen(path);

	if (length >= sizeof(partial)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	memcpy(partial, path, length + 1);

	/* Intermediate directories get 0755; only the leaf gets mode. */
	for (cursor = partial + 1; *cursor != '\0'; cursor++) {
		if (*cursor != '/')
			continue;
		*cursor = '\0';
		if ((mkdir(partial, 0755) != 0 && errno != EEXIST) ||
		    directory_is_safe(partial, 1) != 0)
			return (-1);
		*cursor = '/';
	}

	if ((mkdir(partial, mode) != 0 && errno != EEXIST) ||
	    directory_is_safe(partial, 1) != 0)
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

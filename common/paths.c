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

static int	 mkpath(const char *path, mode_t mode);
static int	 mkparent(const char *file, mode_t mode);

void
btmgr_paths_init(struct btmgr_paths *p, int dry_run)
{

	memset(p, 0, sizeof(*p));
	(void)strlcpy(p->hosts, BTMGR_HOSTS, sizeof(p->hosts));
	(void)strlcpy(p->hcsecd, BTMGR_HCSECD_CONF, sizeof(p->hcsecd));
	(void)strlcpy(p->keys, BTMGR_HCSECD_KEYS, sizeof(p->keys));
	(void)strlcpy(p->store, BTMGR_STORE, sizeof(p->store));
	(void)strlcpy(p->storedir, BTMGR_STOREDIR, sizeof(p->storedir));

	safefile_init(&p->sf, dry_run);
}

/* mkdir -p. An existing directory is success. */
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
		if (mkdir(partial, 0755) != 0 && errno != EEXIST)
			return (-1);
		*cursor = '/';
	}

	if (mkdir(partial, mode) != 0 && errno != EEXIST)
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

	/* A4: the store directory at 0700. On a real system the rest exist. */
	if (mkparent(p->hosts, 0755) != 0 ||
	    mkparent(p->keys, 0755) != 0 ||
	    mkpath(p->storedir, BTMGR_MODE_STOREDIR) != 0)
		return (-1);

	return (0);
}

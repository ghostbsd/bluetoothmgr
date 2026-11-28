/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-filetest - verification for the A0 write discipline.
 *
 * SPEC.md A0 is a list of promises about how configuration files get written.
 * This program is where each promise is checked, because the alternative is
 * discovering on someone's machine that hcsecd.conf was truncated.
 *
 * Everything runs against a scratch directory and needs no privilege and no
 * Bluetooth hardware, which is the point: the parts of M3b that can be
 * verified without root should be, leaving root for the parts that genuinely
 * need it.
 *
 *	btmgr-filetest [scratch-directory]
 *
 * Exits 0 when every check passes, 1 otherwise. With no argument it makes a
 * directory in the current directory and removes it on the way out.
 */

#include <sys/cdefs.h>
#include <sys/stat.h>

#include <dirent.h>
#include <fts.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "safefile.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"

static int	 failures;
static int	 checks;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 put_file(const char *path, const char *content, mode_t mode);
static char	*get_file(const char *path);
static int	 exists(const char *path);
static mode_t	 mode_of(const char *path);
static ino_t	 ino_of(const char *path);
static int	 count_temps(const char *dir);
static void	 rm_rf(const char *path);

static void
ok(int cond, const char *fmt, ...)
{
	va_list	 ap;

	checks++;
	va_start(ap, fmt);
	if (cond) {
		(void)fputs("ok   ", stdout);
	} else {
		(void)fputs("FAIL ", stdout);
		failures++;
	}
	vprintf(fmt, ap);
	putchar('\n');
	va_end(ap);
}

/*
 * Put a file in place the ordinary way, so that the thing under test is only
 * ever safefile_write(). A setup failure is fatal: a test that cannot build
 * its own fixture proves nothing.
 */
static void
put_file(const char *path, const char *content, mode_t mode)
{
	FILE	*f;

	f = fopen(path, "w");
	if (f == NULL || fputs(content, f) == EOF) {
		(void)fprintf(stderr, "setup: %s: %s\n", path, strerror(errno));
		if (f != NULL)
			(void)fclose(f);
		exit(2);
	}
	if (fclose(f) == EOF || chmod(path, mode) == -1) {
		(void)fprintf(stderr, "setup: %s: %s\n", path, strerror(errno));
		exit(2);
	}
}

static char *
get_file(const char *path)
{
	return (safefile_read(path, NULL));
}

static int
exists(const char *path)
{
	return (access(path, F_OK) == 0);
}

static mode_t
mode_of(const char *path)
{
	struct stat	sb;

	if (stat(path, &sb) == -1)
		return ((mode_t)-1);
	return (sb.st_mode & ALLPERMS);
}

static ino_t
ino_of(const char *path)
{
	struct stat	sb;

	if (stat(path, &sb) == -1)
		return ((ino_t)-1);
	return (sb.st_ino);
}

/* Any leftover "*.btmgr.*" means a failure path forgot to clean up. */
static int
count_temps(const char *dir)
{
	struct dirent	*de;
	DIR		*d;
	int		 n = 0;

	d = opendir(dir);
	if (d == NULL)
		return (-1);
	while ((de = readdir(d)) != NULL) {
		if (strstr(de->d_name, ".btmgr.") != NULL)
			n++;
	}
	closedir(d);
	return (n);
}

static void
rm_rf(const char *path)
{
	char	*argv[2];
	FTS	*fts;
	FTSENT	*ent;

	argv[0] = (char *)path;
	argv[1] = NULL;

	fts = fts_open(argv, FTS_PHYSICAL | FTS_NOSTAT, NULL);
	if (fts == NULL)
		return;

	for (;;) {
		ent = fts_read(fts);
		if (ent == NULL)
			break;

		/* FTS_DP is the post-order visit, so contents go before the dir. */
		if (ent->fts_info == FTS_DP)
			(void)rmdir(ent->fts_path);
		else if (ent->fts_info != FTS_D)
			(void)unlink(ent->fts_path);
	}

	(void)fts_close(fts);
}

int
main(int argc, char **argv)
{
	struct safefile_ctx	 ctx, dry;
	char			 root[PATH_MAX];
	char			 target[PATH_MAX], bak[PATH_MAX];
	char			 err[SAFEFILE_ERRLEN];
	char			*got;
	char			 working[PATH_MAX];
	ino_t			 before, after;
	int			 owned = 0, rc;

	if (argc > 2) {
		(void)fprintf(stderr, "usage: btmgr-filetest [scratch-directory]\n");
		return (2);
	}

	if (argc == 2) {
		if (strlcpy(root, argv[1], sizeof(root)) >= sizeof(root)) {
			(void)fprintf(stderr, "path too long\n");
			return (2);
		}
		if (mkdir(root, 0755) == -1 && errno != EEXIST) {
			(void)fprintf(stderr, "mkdir %s: %s\n", root,
			    strerror(errno));
			return (2);
		}
	} else {
		if (getcwd(working, sizeof(working)) == NULL) {
			(void)fprintf(stderr, "getcwd: %s\n", strerror(errno));
			return (2);
		}
		(void)snprintf(root, sizeof(root), "%s/btmgr-filetest.XXXXXX", working);
		if (mkdtemp(root) == NULL) {
			(void)fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
			return (2);
		}
		owned = 1;
	}

	(void)snprintf(target, sizeof(target), "%s/hcsecd.conf", root);
	(void)snprintf(bak, sizeof(bak), "%s.bak", target);

	safefile_init(&ctx, 0);
	safefile_init(&dry, 1);

	printf("scratch: %s\n\n", root);

	/*
	 * A0.2 with a pre-existing file. This is the case that matters: the
	 * user already has an hcsecd.conf and we are about to rewrite it.
	 */
	printf("-- A0.2 backup of a pre-existing file --\n");
	put_file(target, "original\n", 0600);
	before = ino_of(target);

	rc = safefile_write(&ctx, target, 0600, "first\n", 6, err, sizeof(err));
	ok(rc == SAFEFILE_WRITTEN, "first write reports WRITTEN (got %d, %s)",
	    rc, err);
	ok(exists(bak), ".bak was created");
	got = get_file(bak);
	ok(got != NULL && strcmp(got, "original\n") == 0,
	    ".bak holds the pre-BluetoothMgr content");
	free(got);
	got = get_file(target);
	ok(got != NULL && strcmp(got, "first\n") == 0,
	    "target holds the new content");
	free(got);
	ok(mode_of(bak) == 0600, ".bak preserved mode 0600 (got %04o)",
	    mode_of(bak));

	after = ino_of(target);
	ok(before == after, "the target keeps its inode, so it was edited in place, not replaced (A0.1)");

	/* A0.2 again: the second write must leave the first backup alone. */
	printf("\n-- A0.2 an existing .bak is never replaced --\n");
	rc = safefile_write(&ctx, target, 0600, "second\n", 7, err,
	    sizeof(err));
	ok(rc == SAFEFILE_WRITTEN, "second write reports WRITTEN (got %d, %s)",
	    rc, err);
	got = get_file(bak);
	ok(got != NULL && strcmp(got, "original\n") == 0,
	    ".bak still holds the ORIGINAL, not our first write");
	free(got);

	/* A0.5. */
	printf("\n-- A0.5 no write when nothing changed --\n");
	before = ino_of(target);
	rc = safefile_write(&ctx, target, 0600, "second\n", 7, err,
	    sizeof(err));
	ok(rc == SAFEFILE_UNCHANGED, "identical content reports UNCHANGED "
	    "(got %d)", rc);
	ok(ino_of(target) == before, "the file was not touched at all");

	printf("\n-- no temp files are left behind --\n");
	ok(count_temps(root) == 0, "no leftover temp files (found %d)",
	    count_temps(root));
	ok(mode_of(target) == 0600, "target kept mode 0600 (got %04o)",
	    mode_of(target));

	printf("\n-- an existing file's mode is never changed (A0.6) --\n");
	{
		char	wider[PATH_MAX], narrower[PATH_MAX];

		(void)snprintf(wider, sizeof(wider), "%s/hosts", root);
		put_file(wider, "old\n", 0644);
		rc = safefile_write(&ctx, wider, 0600, "new\n", 4, err, sizeof(err));
		ok(rc == SAFEFILE_WRITTEN && mode_of(wider) == 0644,
		    "a 0644 file written with 0600 stays 0644 (got %04o)", mode_of(wider));

		(void)snprintf(narrower, sizeof(narrower), "%s/narrower", root);
		put_file(narrower, "old\n", 0600);
		rc = safefile_write(&ctx, narrower, 0644, "new\n", 4, err, sizeof(err));
		ok(rc == SAFEFILE_WRITTEN && mode_of(narrower) == 0600,
		    "and a 0600 file written with 0644 stays 0600 (got %04o)", mode_of(narrower));
	}

	printf("\n-- a file that did not exist gets no .bak --\n");
	{
		char	fresh[PATH_MAX], freshbak[PATH_MAX];

		(void)snprintf(fresh, sizeof(fresh), "%s/devices.json", root);
		(void)snprintf(freshbak, sizeof(freshbak), "%s.bak", fresh);

		rc = safefile_write(&ctx, fresh, 0600, "{}\n", 3, err, sizeof(err));
		ok(rc == SAFEFILE_WRITTEN, "created devices.json (got %d, %s)", rc, err);
		ok(mode_of(fresh) == 0600, "a new file got the requested mode 0600 (got %04o)", mode_of(fresh));
		ok(!exists(freshbak), "no .bak for a file that did not exist");
	}

	printf("\n-- a later write never refreshes .bak --\n");
	rc = safefile_write(&ctx, target, 0600, "third\n", 6, err, sizeof(err));
	ok(rc == SAFEFILE_WRITTEN, "third write (got %d, %s)", rc, err);
	got = get_file(bak);
	ok(got != NULL && strcmp(got, "original\n") == 0, ".bak still holds the original");
	free(got);

	/* Whatever sits at the .bak name, even a symlink, is left alone. */
	printf("\n-- a symlink at .bak is not followed --\n");
	{
		char	victim[PATH_MAX];
		struct stat	status;

		(void)snprintf(victim, sizeof(victim), "%s/victim", root);
		put_file(victim, "untouched\n", 0644);
		(void)unlink(bak);
		if (symlink(victim, bak) != 0)
			ok(0, "could not plant the symlink: %s", strerror(errno));
		else {
			rc = safefile_write(&ctx, target, 0600, "fourth\n", 7, err, sizeof(err));
			ok(rc == SAFEFILE_WRITTEN, "write with a planted symlink (got %d, %s)", rc, err);
			got = get_file(victim);
			ok(got != NULL && strcmp(got, "untouched\n") == 0, "the symlink's target is untouched");
			free(got);
			ok(lstat(bak, &status) == 0 && S_ISLNK(status.st_mode), "and the planted .bak is left as it was");
		}
	}

	/* --dry-run. */
	printf("\n-- dry run changes nothing --\n");
	{
		char	dpath[PATH_MAX], dbak[PATH_MAX];

		(void)snprintf(dpath, sizeof(dpath), "%s/dry.conf", root);
		(void)snprintf(dbak, sizeof(dbak), "%s.bak", dpath);
		put_file(dpath, "untouched\n", 0600);

		rc = safefile_write(&dry, dpath, 0600, "changed\n", 8, err,
		    sizeof(err));
		ok(rc == SAFEFILE_DRYRUN, "reports DRYRUN (got %d)", rc);
		got = get_file(dpath);
		ok(got != NULL && strcmp(got, "untouched\n") == 0,
		    "the file is unchanged");
		free(got);
		ok(!exists(dbak), "no .bak was made");

		rc = safefile_write(&dry, dpath, 0600, "untouched\n", 10, err,
		    sizeof(err));
		ok(rc == SAFEFILE_UNCHANGED,
		    "a dry run still distinguishes UNCHANGED (got %d)", rc);
	}

	/* Failure leaves the target alone. */
	printf("\n-- a failed write leaves the target intact --\n");
	{
		char	bogus[PATH_MAX];

		(void)snprintf(bogus, sizeof(bogus), "%s/nonexistent/x.conf", root);
		err[0] = '\0';
		rc = safefile_write(&ctx, bogus, 0600, "x\n", 2, err,
		    sizeof(err));
		ok(rc == SAFEFILE_ERROR, "writing into a missing directory "
		    "fails (got %d)", rc);
		ok(err[0] != '\0', "an error message was produced: %s", err);
		ok(count_temps(root) == 0,
		    "still no leftover temp files (found %d)",
		    count_temps(root));
	}

	printf("\n-- safefile_read --\n");
	{
		char	missing[PATH_MAX];

		(void)snprintf(missing, sizeof(missing), "%s/not-here", root);
		errno = 0;
		got = safefile_read(missing, NULL);
		ok(got == NULL && errno == ENOENT,
		    "a missing file reports ENOENT, not a crash");
		free(got);

		got = safefile_read(root, NULL);
		ok(got == NULL && errno == EINVAL,
		    "a directory is refused with EINVAL");
		free(got);
	}

	printf("\n%d checks, %d failures\n", checks, failures);

	if (owned)
		rm_rf(root);
	else
		printf("scratch directory left at %s\n", root);

	if (btmgr_mc_report() != 0) {
		printf("memcheck: allocations still live\n");
		failures++;
	}

	return (failures == 0 ? 0 : 1);
}

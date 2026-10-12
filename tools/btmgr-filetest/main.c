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
 * directory under $TMPDIR (default /tmp) and removes it on the way out.
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
	char			 root[PATH_MAX], rundir[PATH_MAX];
	char			 target[PATH_MAX], bak[PATH_MAX];
	char			 err[SAFEFILE_ERRLEN];
	char			*got;
	const char		*tmpdir;
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
		tmpdir = getenv("TMPDIR");
		if (tmpdir == NULL || *tmpdir == '\0')
			tmpdir = "/tmp";
		(void)snprintf(root, sizeof(root), "%s/btmgr-filetest.XXXXXX",
		    tmpdir);
		if (mkdtemp(root) == NULL) {
			(void)fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
			return (2);
		}
		owned = 1;
	}

	(void)snprintf(rundir, sizeof(rundir), "%s/run", root);
	(void)snprintf(target, sizeof(target), "%s/hcsecd.conf", root);
	(void)snprintf(bak, sizeof(bak), "%s.bak", target);

	if (safefile_init(&ctx, rundir, 0) == -1 ||
	    safefile_init(&dry, rundir, 1) == -1) {
		(void)fprintf(stderr, "safefile_init: %s\n", strerror(errno));
		return (2);
	}

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
	ok(before != after,
	    "the target is a new inode, so it was renamed into place, "
	    "not edited (A0.1, A0.3)");

	/* A0.2 again: the second write must leave the first backup alone. */
	printf("\n-- A0.2 one backup per boot --\n");
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

	/* A0.1 and A0.6 leave nothing behind. */
	printf("\n-- A0.1, A0.6 temp file hygiene --\n");
	ok(count_temps(root) == 0, "no leftover temp files (found %d)",
	    count_temps(root));
	ok(mode_of(target) == 0600, "target kept mode 0600 (got %04o)",
	    mode_of(target));

	/*
	 * An existing file keeps its own mode even when the caller names a
	 * different one. /etc/bluetooth/hosts is 0644 and must stay readable.
	 */
	printf("\n-- an existing file keeps its own mode --\n");
	{
		char	hosts[PATH_MAX];

		(void)snprintf(hosts, sizeof(hosts), "%s/hosts", root);
		put_file(hosts, "old\n", 0644);
		rc = safefile_write(&ctx, hosts, 0600, "new\n", 4, err,
		    sizeof(err));
		ok(rc == SAFEFILE_WRITTEN, "wrote hosts (got %d, %s)", rc, err);
		ok(mode_of(hosts) == 0644,
		    "0644 preserved despite a 0600 argument (got %04o)",
		    mode_of(hosts));
	}

	/*
	 * A file we create ourselves has no pre-BluetoothMgr state, so it must
	 * get no .bak, and rewriting it must not produce one either. Without
	 * the marker, our second write would back up our own first write.
	 */
	printf("\n-- a file we created ourselves is never \"backed up\" --\n");
	{
		char	fresh[PATH_MAX], freshbak[PATH_MAX];

		(void)snprintf(fresh, sizeof(fresh), "%s/devices.json", root);
		(void)snprintf(freshbak, sizeof(freshbak), "%s.bak", fresh);

		rc = safefile_write(&ctx, fresh, 0600, "{}\n", 3, err,
		    sizeof(err));
		ok(rc == SAFEFILE_WRITTEN, "created devices.json (got %d, %s)",
		    rc, err);
		ok(mode_of(fresh) == 0600,
		    "a new file got the requested mode 0600 (got %04o)",
		    mode_of(fresh));
		ok(!exists(freshbak), "no .bak for a file that did not exist");

		rc = safefile_write(&ctx, fresh, 0600, "{\"a\":1}\n", 8, err,
		    sizeof(err));
		ok(rc == SAFEFILE_WRITTEN, "rewrote devices.json (got %d, %s)",
		    rc, err);
		ok(!exists(freshbak),
		    "still no .bak, so our own output was not mistaken for "
		    "the user's original");
	}

	/* A new boot clears the markers, so the next write refreshes .bak. */
	printf("\n-- a new boot takes a fresh backup --\n");
	rm_rf(rundir);
	rc = safefile_write(&ctx, target, 0600, "third\n", 6, err, sizeof(err));
	ok(rc == SAFEFILE_WRITTEN, "write after reboot (got %d, %s)", rc, err);
	got = get_file(bak);
	ok(got != NULL && strcmp(got, "second\n") == 0,
	    ".bak refreshed to the pre-boot content");
	free(got);

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

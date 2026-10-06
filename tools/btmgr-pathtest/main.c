/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-pathtest - verification for common/paths.c.
 *
 * paths.c is what lets every other M3b module be exercised against copies in a
 * scratch directory instead of /etc, so it is the one piece whose own
 * correctness nothing else can check. Needs no privilege.
 *
 *	btmgr-pathtest [scratch-directory]
 *
 * Exits 0 when every check passes, 1 otherwise. With no argument it makes a
 * directory under $TMPDIR (default /tmp) and removes it on the way out.
 */

#include <sys/stat.h>

#include <errno.h>
#include <fts.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "paths.h"
#include "safefile.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"	/* IWYU pragma: keep */

static int	 failures;
static int	 checks;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 eq(const char *got, const char *want, const char *what);
static int	 is_dir(const char *path);
static mode_t	 mode_of(const char *path);
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

static void
eq(const char *got, const char *want, const char *what)
{
	int	 same = strcmp(got, want) == 0;

	ok(same, "%s%s%s%s", what, same ? "" : " (got \"",
	    same ? "" : got, same ? "" : "\")");
}

static int
is_dir(const char *path)
{
	struct stat	 sb;

	return (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode));
}

static mode_t
mode_of(const char *path)
{
	struct stat	 sb;

	if (stat(path, &sb) != 0)
		return ((mode_t)-1);

	return (sb.st_mode & 07777);
}

/* fts(3) rather than recursion, as in btmgr-filetest. */
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
		if (ent->fts_info == FTS_DP)
			(void)rmdir(ent->fts_path);
		else if (ent->fts_info != FTS_D)
			(void)unlink(ent->fts_path);
	}

	(void)fts_close(fts);
}

/* The real locations, when no root is given. */
static void
test_system_paths(void)
{
	struct btmgr_paths	 paths;

	printf("\nno root: the real system locations\n");

	ok(btmgr_paths_init(&paths, NULL, 0) == 0, "init with a NULL root works");
	eq(paths.hosts, "/etc/bluetooth/hosts", "hosts is the real path");
	eq(paths.hcsecd, "/etc/bluetooth/hcsecd.conf", "hcsecd.conf is the real path");
	eq(paths.keys, "/var/db/hcsecd.keys", "the keys file is the real path");
	eq(paths.store, "/var/db/bluetoothmgr/devices.json", "the store is the real path");
	eq(paths.storedir, "/var/db/bluetoothmgr", "and so is its directory");
	eq(paths.sf.rundir, SAFEFILE_RUNDIR, "the A0.2 markers are in the real /var/run");
	ok(paths.sf.dry_run == 0, "dry_run is off when not asked for");

	/* An empty root means the same thing as no root. */
	ok(btmgr_paths_init(&paths, "", 0) == 0, "an empty root is accepted");
	eq(paths.hosts, "/etc/bluetooth/hosts", "and is treated as no root at all");
}

static void
test_rooted_paths(void)
{
	struct btmgr_paths	 paths;

	printf("\nunder a root\n");

	ok(btmgr_paths_init(&paths, "/tmp/bt", 0) == 0, "init under a root works");
	eq(paths.hosts, "/tmp/bt/etc/bluetooth/hosts", "hosts follows the root");
	eq(paths.hcsecd, "/tmp/bt/etc/bluetooth/hcsecd.conf", "so does hcsecd.conf");
	eq(paths.keys, "/tmp/bt/var/db/hcsecd.keys", "so does the keys file");
	eq(paths.store, "/tmp/bt/var/db/bluetoothmgr/devices.json", "so does the store");

	/*
	 * The markers must follow the root too. Left in the real /var/run, a
	 * test run would record that it had backed up /etc/bluetooth this boot,
	 * and the next real write would skip the A0.2 backup and lose the
	 * user's pristine file.
	 */
	eq(paths.sf.rundir, "/tmp/bt" SAFEFILE_RUNDIR,
	    "and the A0.2 markers follow it, so a test cannot poison /var/run");

	/* A trailing slash must not double up. */
	ok(btmgr_paths_init(&paths, "/tmp/bt/", 0) == 0, "a trailing slash is accepted");
	eq(paths.hosts, "/tmp/bt/etc/bluetooth/hosts", "and does not double the separator");

	ok(btmgr_paths_init(&paths, "/tmp/bt///", 0) == 0, "several trailing slashes too");
	eq(paths.hosts, "/tmp/bt/etc/bluetooth/hosts", "all of them collapse");

	/* A root of "/" is the system root spelled differently. */
	ok(btmgr_paths_init(&paths, "/", 0) == 0, "a root of \"/\" is accepted");
	eq(paths.hosts, "/etc/bluetooth/hosts", "and means the real path, not //etc/...");
}

/*
 * The sandbox must sit inside the 0700 store directory, not somewhere
 * world-writable. A sandbox copy of hcsecd.conf carries PINs and link keys.
 */
static void
test_sandbox_location(void)
{
	struct btmgr_paths	 paths;

	printf("\nthe recommended sandbox root\n");

	eq(BTMGR_SANDBOX, "/var/db/bluetoothmgr/sandbox",
	    "the sandbox is under the store directory");
	ok(strncmp(BTMGR_SANDBOX, BTMGR_STOREDIR "/",
	    sizeof(BTMGR_STOREDIR)) == 0,
	    "so it inherits that directory's 0700, per A4");
	ok(strncmp(BTMGR_SANDBOX, "/tmp", 4) != 0,
	    "and is not under any world-writable directory");

	/* It has to work as a root, since that is what it is for. */
	ok(btmgr_paths_init(&paths, BTMGR_SANDBOX, 0) == 0,
	    "and it is usable as a root");
	eq(paths.hosts, "/var/db/bluetoothmgr/sandbox/etc/bluetooth/hosts",
	    "giving a sandboxed hosts path");
}

static void
test_dry_run(void)
{
	struct btmgr_paths	 paths;

	printf("\ndry run\n");

	ok(btmgr_paths_init(&paths, "/tmp/bt", 1) == 0, "init with dry_run works");
	ok(paths.sf.dry_run == 1, "and the flag reaches the safefile context");
	eq(paths.hosts, "/tmp/bt/etc/bluetooth/hosts", "paths are unaffected by it");
}

static void
test_too_long(void)
{
	struct btmgr_paths	 paths;
	char			 big[PATH_MAX];

	printf("\na root that cannot fit\n");

	memset(big, 'a', sizeof(big) - 1);
	big[0] = '/';
	big[sizeof(big) - 1] = '\0';

	errno = 0;
	ok(btmgr_paths_init(&paths, big, 0) == -1 && errno == ENAMETOOLONG,
	    "a root too long for the paths is refused with ENAMETOOLONG");
}

/*
 * A world-writable root would expose a sandbox copy of hcsecd.conf, which
 * carries PINs and link keys.
 */
static void
test_unsafe_root(const char *scratch)
{
	struct btmgr_paths	 paths;
	char			 openroot[PATH_MAX];
	char			 tightroot[PATH_MAX];

	printf("\na world-writable root\n");

	(void)snprintf(openroot, sizeof(openroot), "%s/open", scratch);
	(void)snprintf(tightroot, sizeof(tightroot), "%s/tight", scratch);

	if (mkdir(openroot, 0777) != 0 || chmod(openroot, 0777) != 0 ||
	    mkdir(tightroot, 0700) != 0) {
		ok(0, "could not set up the two roots");
		return;
	}

	errno = 0;
	ok(btmgr_paths_init(&paths, openroot, 0) == -1 && errno == EPERM,
	    "a world-writable root is refused with EPERM");

	ok(btmgr_paths_init(&paths, tightroot, 0) == 0,
	    "while a 0700 root is accepted");

	/* A root that is not there yet is fine; mkdirs creates it. */
	{
		char	 absent[PATH_MAX];

		(void)snprintf(absent, sizeof(absent), "%s/absent", scratch);
		ok(btmgr_paths_init(&paths, absent, 0) == 0,
		    "and a root that does not exist yet is accepted");
	}
}

static void
test_mkdirs(const char *scratch)
{
	struct btmgr_paths	 paths;
	char			 root[PATH_MAX];
	char			 etcdir[PATH_MAX];

	printf("\nbtmgr_paths_mkdirs\n");

	(void)snprintf(root, sizeof(root), "%s/tree", scratch);
	if (btmgr_paths_init(&paths, root, 0) != 0) {
		ok(0, "init under the scratch root failed");
		return;
	}

	ok(!is_dir(paths.storedir), "the store directory does not exist yet");
	ok(btmgr_paths_mkdirs(&paths) == 0, "mkdirs succeeds");

	(void)snprintf(etcdir, sizeof(etcdir), "%s" BTMGR_ETCDIR, root);
	ok(is_dir(etcdir), "it creates the etc directory, parents included");
	ok(is_dir(paths.storedir), "and the store directory");
	ok(is_dir(paths.sf.rundir), "and the marker directory");

	/* A4: the store directory holds metadata about the user's devices. */
	ok(mode_of(paths.storedir) == BTMGR_MODE_STOREDIR,
	    "the store directory is 0700, per A4");
	ok(mode_of(etcdir) == 0755, "while the etc directory is 0755");

	/* Idempotent: an existing directory is success, not EEXIST. */
	ok(btmgr_paths_mkdirs(&paths) == 0, "a second call succeeds, not EEXIST");

	/* The parent of the keys file must exist for safefile_write to work. */
	{
		char	 vardb[PATH_MAX];

		(void)snprintf(vardb, sizeof(vardb), "%s/var/db", root);
		ok(is_dir(vardb), "the keys file's directory is created too");
	}
}

static void
test_mkdirs_dry_run(const char *scratch)
{
	struct btmgr_paths	 paths;
	char			 root[PATH_MAX];

	printf("\nmkdirs under dry run\n");

	(void)snprintf(root, sizeof(root), "%s/dry", scratch);
	if (btmgr_paths_init(&paths, root, 1) != 0) {
		ok(0, "init failed");
		return;
	}

	ok(btmgr_paths_mkdirs(&paths) == 0, "mkdirs reports success");
	ok(!is_dir(root), "but creates nothing at all");
	ok(!is_dir(paths.storedir), "not even the store directory");
}

/*
 * A relative root would put the files somewhere that depends on the daemon's
 * working directory, which for a daemonised process is not what the person who
 * typed it meant.
 */
static void
test_relative_root(void)
{
	struct btmgr_paths	 paths;

	printf("\na relative root\n");

	errno = 0;
	ok(btmgr_paths_init(&paths, "relative/path", 0) == -1 &&
	    errno == EINVAL, "a relative root is refused with EINVAL");
}

int
main(int argc, char *argv[])
{
	char	 scratch[PATH_MAX];
	int	 owned = 0;

	if (argc > 2) {
		(void)fprintf(stderr, "usage: btmgr-pathtest [directory]\n");
		return (1);
	}

	if (argc == 2)
		(void)snprintf(scratch, sizeof(scratch), "%s", argv[1]);
	else {
		const char	*tmp = getenv("TMPDIR");

		(void)snprintf(scratch, sizeof(scratch), "%s/btmgr-pathtest.XXXXXX",
		    tmp != NULL ? tmp : "/tmp");
		if (mkdtemp(scratch) == NULL) {
			(void)fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
			return (1);
		}
		owned = 1;
	}

	test_system_paths();
	test_rooted_paths();
	test_sandbox_location();
	test_dry_run();
	test_too_long();
	test_relative_root();
	test_unsafe_root(scratch);
	test_mkdirs(scratch);
	test_mkdirs_dry_run(scratch);

	printf("\n%d checks, %d failures\n", checks, failures);

	if (owned)
		rm_rf(scratch);
	else
		printf("scratch directory left at %s\n", scratch);

	if (btmgr_mc_report() != 0) {
		printf("memcheck: allocations still live\n");
		failures++;
	}

	return (failures == 0 ? 0 : 1);
}
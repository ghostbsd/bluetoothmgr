/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-pairtest - verification for common/pairing.c. SPEC.md A6, A8.
 *
 * A6 is an ordering rule, so what matters is the sequence of steps and the
 * behaviour of every abort path. Both are checkable without a radio: the
 * sequence is asserted against the report's trace, and reload is a fake that
 * can be made to fail on demand. Runs against a scratch directory under a
 * rooted btmgr_paths, so it writes real files but never /etc.
 *
 * What this cannot cover is a real Link_Key_Notification arriving, which is the
 * hardware check in PLAN.md M3b.
 *
 * Exits 0 when every check passes, 1 otherwise.
 */

#include <sys/stat.h>

#include <errno.h>
#include <fts.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "btaddr.h"
#include "pairing.h"
#include "paths.h"
#include "safefile.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"	/* IWYU pragma: keep */

static int	 failures;
static int	 checks;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 eq(const char *got, const char *want, const char *what);
static void	 rm_rf(const char *path);
static char	*slurp(const char *path);

/* A documentation address, in bdaddr_t storage order. */
static const uint8_t	 speaker_addr[6] = { 0x02, 0x22, 0x11, 0xcc, 0xbb, 0xaa };
static const uint8_t	 defaddr[6] = { 0, 0, 0, 0, 0, 0 };

/*
 * The fake service control. reload_fails makes step 4 fail, which is the A6.3
 * path; running = 0 is the A8.2 path. reloads counts the calls so A8.3 can be
 * checked: one reload in begin, a second in complete.
 */
struct fake {
	int	 reloads;
	int	 reload_fails;
	int	 running;
};

static int
fake_reload(void *context)
{
	struct fake	*f = context;

	f->reloads++;

	return (f->reload_fails ? -1 : 0);
}

static int
fake_running(void *context)
{
	struct fake	*f = context;

	return (f->running);
}

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
	int	 same;

	if (got == NULL) {
		ok(0, "%s (got NULL)", what);
		return;
	}
	same = strcmp(got, want) == 0;
	ok(same, "%s%s%s%s", what, same ? "" : " (got \"",
	    same ? "" : got, same ? "" : "\")");
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
		if (ent->fts_info == FTS_DP)
			(void)rmdir(ent->fts_path);
		else if (ent->fts_info != FTS_D)
			(void)unlink(ent->fts_path);
	}

	(void)fts_close(fts);
}

/* Read a file, or "" when it is absent, so comparisons are easy. */
static char *
slurp(const char *path)
{
	char	*text = safefile_read(path, NULL);

	if (text == NULL) {
		text = malloc(1);
		if (text != NULL)
			text[0] = '\0';
	}

	return (text);
}

/*
 * A fresh sandbox per test, with the base system's hosts and hcsecd.conf in it,
 * so each case starts from the same known bytes.
 */
static const char	 hosts_seed[] =
"# Bluetooth Host Database\n"
"0a:bb:cc:11:22:01    headphones\n";

static const char	 secd_seed[] =
"# HCI security daemon configuration file\n"
"device {\n"
"\tbdaddr\t00:00:00:00:00:00;\n"
"\tname\t\"Default entry\";\n"
"\tkey\tnokey;\n"
"\tpin\tnopin;\n"
"}\n";

static int
seed(const char *scratch, const char *label, struct btmgr_paths *paths)
{
	char	 root[PATH_MAX];
	char	 err[SAFEFILE_ERRLEN];

	(void)snprintf(root, sizeof(root), "%s/%s", scratch, label);

	if (btmgr_paths_init(paths, root, 0) != 0 ||
	    btmgr_paths_mkdirs(paths) != 0)
		return (-1);

	if (safefile_write(&paths->sf, paths->hosts, BTMGR_MODE_HOSTS,
	    hosts_seed, strlen(hosts_seed), err, sizeof(err)) ==
	    SAFEFILE_ERROR)
		return (-1);
	if (safefile_write(&paths->sf, paths->hcsecd, BTMGR_MODE_HCSECD,
	    secd_seed, strlen(secd_seed), err, sizeof(err)) ==
	    SAFEFILE_ERROR)
		return (-1);

	return (0);
}

/* A6, the happy path, and the order it happened in. */
static void
test_order(const char *scratch)
{
	struct btmgr_paths	 paths;
	struct pair_state	 state;
	struct pair_report	 report;
	struct fake		 fake = { 0, 0, 1 };
	struct pair_ops		 ops = { fake_reload, fake_running, &fake };
	char			*text;

	printf("\nA6 the ordering, happy path\n");

	if (seed(scratch, "order", &paths) != 0) {
		ok(0, "could not seed the sandbox");
		return;
	}

	ok(pairing_begin(&paths, &ops, speaker_addr, "Soundbar X900", "0000",
	    &state, &report) == PAIR_PARKED, "begin parks the pairing");
	eq(report.trace, "alias,hosts,secd,reload",
	    "and did alias, hosts, hcsecd.conf, reload, in that order");
	ok(fake.reloads == 1, "with exactly one reload before pairing");

	/* A6.1: the block must be on disk before the caller connects. */
	text = slurp(paths.hcsecd);
	ok(strstr(text, "aa:bb:cc:11:22:02") != NULL,
	    "the block is in hcsecd.conf before step 5, which is A6.1");
	ok(strstr(text, "\"Soundbar X900\"") != NULL, "carrying the name");
	ok(strstr(text, "\tpin\t\"0000\";") != NULL, "and the PIN");
	free(text);

	text = slurp(paths.hosts);
	ok(strstr(text, "Soundbar_X900") != NULL,
	    "and the alias is in hosts, sanitised");
	ok(strstr(text, "headphones") != NULL,
	    "while the record that was already there survives");
	free(text);

	/* Steps 6 and 7. */
	ok(pairing_complete(&paths, &ops, &state, "Soundbar X900", "speaker",
	    1000, &report) == PAIR_DONE, "complete finishes the sequence");
	eq(report.trace, "key,flush,store",
	    "doing the A8.3 flush reload, then devices.json");
	ok(fake.reloads == 2, "so two reloads in total, one each side of pairing");

	text = slurp(paths.store);
	ok(strstr(text, "aa:bb:cc:11:22:02") != NULL, "the device is recorded");
	ok(strstr(text, "\"speaker\"") != NULL, "with its type");
	ok(strstr(text, "Soundbar_X900") != NULL,
	    "and the same alias as hosts, so the two files agree");
	ok(strstr(text, "0000") == NULL,
	    "and A4.1 holds: the PIN is not in devices.json");
	free(text);
}

/* A6.3: if the reload fails we MUST NOT pair, and MUST roll back. */
static void
test_reload_failure(const char *scratch)
{
	struct btmgr_paths	 paths;
	struct pair_state	 state;
	struct pair_report	 report;
	struct fake		 fake = { 0, 1, 1 };
	struct pair_ops		 ops = { fake_reload, fake_running, &fake };
	char			*hosts_after, *secd_after;

	printf("\nA6.3 a failed reload aborts and rolls back\n");

	if (seed(scratch, "reloadfail", &paths) != 0) {
		ok(0, "could not seed the sandbox");
		return;
	}

	ok(pairing_begin(&paths, &ops, speaker_addr, "Soundbar X900", "0000",
	    &state, &report) == PAIR_ERROR, "begin reports failure");
	ok(strstr(report.trace, "reload-failed") != NULL,
	    "the trace names the failed reload");
	ok(strstr(report.trace, "rollback") != NULL, "and the rollback");
	ok(report.rolled_back == 1, "which is reported as having happened");

	/* A6.4: both files back to the bytes they had. */
	hosts_after = slurp(paths.hosts);
	secd_after = slurp(paths.hcsecd);
	eq(hosts_after, hosts_seed, "hosts is byte-identical to before");
	eq(secd_after, secd_seed, "and so is hcsecd.conf");
	free(hosts_after);
	free(secd_after);

	ok(!state.active, "and no pairing is left parked");
}

/* A8.2: hcsecd not running is its own condition, and nothing is written. */
static void
test_no_hcsecd(const char *scratch)
{
	struct btmgr_paths	 paths;
	struct pair_state	 state;
	struct pair_report	 report;
	struct fake		 fake = { 0, 0, 0 };
	struct pair_ops		 ops = { fake_reload, fake_running, &fake };
	char			*hosts_after, *secd_after;

	printf("\nA8.2 hcsecd not running\n");

	if (seed(scratch, "nohcsecd", &paths) != 0) {
		ok(0, "could not seed the sandbox");
		return;
	}

	ok(pairing_begin(&paths, &ops, speaker_addr, "Soundbar X900", "0000",
	    &state, &report) == PAIR_NO_HCSECD,
	    "begin reports PAIR_NO_HCSECD, not a generic failure");
	eq(report.trace, "no-hcsecd", "and does nothing else");
	ok(fake.reloads == 0, "no reload is attempted");
	ok(strstr(report.detail, "hcsecd_enable") != NULL,
	    "and the detail says how to fix it");

	hosts_after = slurp(paths.hosts);
	secd_after = slurp(paths.hcsecd);
	eq(hosts_after, hosts_seed, "hosts is untouched");
	eq(secd_after, secd_seed, "and so is hcsecd.conf");
	free(hosts_after);
	free(secd_after);
}

/* A1.2.1: the default entry is never ours, so pairing it is refused. */
static void
test_default_entry(const char *scratch)
{
	struct btmgr_paths	 paths;
	struct pair_state	 state;
	struct pair_report	 report;
	struct fake		 fake = { 0, 0, 1 };
	struct pair_ops		 ops = { fake_reload, fake_running, &fake };
	char			*secd_after;

	printf("\nA1.2.1 the default entry is refused\n");

	if (seed(scratch, "defaddr", &paths) != 0) {
		ok(0, "could not seed the sandbox");
		return;
	}

	ok(pairing_begin(&paths, &ops, defaddr, "Nope", NULL, &state,
	    &report) == PAIR_REFUSED, "begin refuses 00:00:00:00:00:00");
	ok(report.rolled_back == 1, "and rolls back what it had written");

	secd_after = slurp(paths.hcsecd);
	eq(secd_after, secd_seed, "leaving hcsecd.conf as it was");
	free(secd_after);
}

/* The timeout path: a key that never arrives. */
static void
test_abort(const char *scratch)
{
	struct btmgr_paths	 paths;
	struct pair_state	 state;
	struct pair_report	 report;
	struct fake		 fake = { 0, 0, 1 };
	struct pair_ops		 ops = { fake_reload, fake_running, &fake };
	char			*hosts_after, *secd_after;

	printf("\nabort, for a key that never arrives\n");

	if (seed(scratch, "abort", &paths) != 0) {
		ok(0, "could not seed the sandbox");
		return;
	}

	ok(pairing_begin(&paths, &ops, speaker_addr, "Soundbar X900", NULL, &state,
	    &report) == PAIR_PARKED, "a pairing is parked");

	ok(pairing_abort(&paths, &ops, &state, &report) == PAIR_DONE,
	    "abort succeeds");
	eq(report.trace, "abort,rollback", "and says what it did");

	hosts_after = slurp(paths.hosts);
	secd_after = slurp(paths.hcsecd);
	eq(hosts_after, hosts_seed, "hosts is byte-identical to before");
	eq(secd_after, secd_seed, "and so is hcsecd.conf");
	free(hosts_after);
	free(secd_after);

	ok(!state.active, "and the state is released");

	/* Completing or aborting twice must not act on a released state. */
	ok(pairing_abort(&paths, &ops, &state, &report) == PAIR_ERROR,
	    "a second abort is refused");
	ok(pairing_complete(&paths, &ops, &state, "x", NULL, 1,
	    &report) == PAIR_ERROR, "and so is completing afterwards");
}

/* Re-pairing a device we already manage is an update, not an append. */
static void
test_repair(const char *scratch)
{
	struct btmgr_paths	 paths;
	struct pair_state	 state;
	struct pair_report	 report;
	struct fake		 fake = { 0, 0, 1 };
	struct pair_ops		 ops = { fake_reload, fake_running, &fake };
	char			*first, *second, *rolled;

	printf("\nre-pairing a device we already manage\n");

	if (seed(scratch, "repair", &paths) != 0) {
		ok(0, "could not seed the sandbox");
		return;
	}

	ok(pairing_begin(&paths, &ops, speaker_addr, "Soundbar X900", "0000",
	    &state, &report) == PAIR_PARKED, "the first pairing parks");
	ok(pairing_complete(&paths, &ops, &state, "Soundbar X900", "speaker",
	    1000, &report) == PAIR_DONE, "and completes");
	first = slurp(paths.hcsecd);

	/* Now pair again, and abort. Rollback must restore the FIRST state. */
	ok(pairing_begin(&paths, &ops, speaker_addr, "Soundbar X900", "9999",
	    &state, &report) == PAIR_PARKED, "a second pairing parks");
	second = slurp(paths.hcsecd);
	ok(strstr(second, "\"9999\"") != NULL, "with the new PIN written");
	free(second);

	ok(pairing_abort(&paths, &ops, &state, &report) == PAIR_DONE,
	    "aborting it succeeds");
	rolled = slurp(paths.hcsecd);
	eq(rolled, first,
	    "and restores the block as it was, not by deleting it");
	ok(strstr(rolled, "\"0000\"") != NULL, "so the original PIN is back");
	free(rolled);
	free(first);
}

int
main(int argc, char *argv[])
{
	char	 scratch[PATH_MAX];
	int	 owned = 0;

	if (argc > 2) {
		(void)fprintf(stderr, "usage: btmgr-pairtest [directory]\n");
		return (1);
	}

	if (argc == 2)
		(void)snprintf(scratch, sizeof(scratch), "%s", argv[1]);
	else {
		const char	*tmp = getenv("TMPDIR");

		(void)snprintf(scratch, sizeof(scratch),
		    "%s/btmgr-pairtest.XXXXXX", tmp != NULL ? tmp : "/tmp");
		if (mkdtemp(scratch) == NULL) {
			(void)fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
			return (1);
		}
		owned = 1;
	}

	test_order(scratch);
	test_reload_failure(scratch);
	test_no_hcsecd(scratch);
	test_default_entry(scratch);
	test_abort(scratch);
	test_repair(scratch);

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
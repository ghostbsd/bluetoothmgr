/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-sesstest - verification for common/session.c. SPEC.md A5.3, A9.
 *
 * The pid walk runs against this process's own ancestry, which is a real chain
 * with known endpoints. The record predicates run against a struct utmpx built
 * here, because the on-disk format setutxdb() reads is private to libc.
 *
 * Needs no root, no hardware and no daemon.
 */

#include <sys/cdefs.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <utmpx.h>

#include "session.h"

static int	 failures;
static int	 checks;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 gui_record(struct utmpx *ut, const char *line,
		     const char *host);

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
 * A record naming this process as its session leader. The login time is now,
 * which is after this process started, so A9.5 passes.
 */
static void
gui_record(struct utmpx *ut, const char *line, const char *host)
{

	memset(ut, 0, sizeof(*ut));
	ut->ut_type = USER_PROCESS;
	ut->ut_pid = getpid();
	ut->ut_tv.tv_sec = time(NULL);
	(void)strlcpy(ut->ut_line, line, sizeof(ut->ut_line));
	(void)strlcpy(ut->ut_host, host, sizeof(ut->ut_host));
}

static void
test_descent(void)
{
	pid_t	 self = getpid();
	pid_t	 parent = getppid();

	printf("\nA9.4 the pid walk\n");

	ok(btmgr_session_descends_from(self, self),
	    "a process is its own ancestor, so a leader's own peer passes");
	ok(btmgr_session_descends_from(self, parent),
	    "and it descends from its parent");
	ok(btmgr_session_descends_from(self, 1),
	    "and from init, which every process reaches");

	/*
	 * The kernel is pid 0 and is nobody's parent in the table, so the walk
	 * must stop rather than treating 0 as a wildcard.
	 */
	ok(!btmgr_session_descends_from(self, 0),
	    "pid 0 is not an ancestor");
	ok(!btmgr_session_descends_from(self, -1),
	    "a negative ancestor is refused");
	ok(!btmgr_session_descends_from(0, 1),
	    "pid 0 as the peer is refused");
	ok(!btmgr_session_descends_from(-1, 1),
	    "a negative peer is refused");

	/* init does not descend from us, which is the direction that matters. */
	ok(!btmgr_session_descends_from(1, self),
	    "the walk goes upward only, so init does not descend from us");

	/* A pid that cannot exist: the walk must fail, not loop. */
	ok(!btmgr_session_descends_from(self, 999999),
	    "an ancestor that is not in our chain is refused");
}

static void
test_record(void)
{
	struct utmpx	 ut;

	printf("\nA9.1, A9.2 recognising a GUI record\n");

	/* lightdm's shape: the display is in ut_line. */
	gui_record(&ut, ":0", "");
	ok(btmgr_session_record_is_gui(&ut), "a record on line \":0\" is GUI");

	/* mate-session's shape: a tty line, the display in ut_host. */
	gui_record(&ut, "ttyv8", ":0");
	ok(btmgr_session_record_is_gui(&ut),
	    "a tty line with host \":0\" is GUI, which is why A9.2 reads both");

	/* A9.3. */
	gui_record(&ut, "ttyv0", "");
	ok(!btmgr_session_record_is_gui(&ut),
	    "a console login with no host is not GUI");
	gui_record(&ut, "pts/0", "192.0.2.1");
	ok(!btmgr_session_record_is_gui(&ut), "nor is ssh on a pts line");
	gui_record(&ut, "pts/0", "");
	ok(!btmgr_session_record_is_gui(&ut),
	    "nor is a pts line with no host at all");

	/* Only a live login counts, not a boot time or a dead slot. */
	gui_record(&ut, ":0", "");
	ut.ut_type = BOOT_TIME;
	ok(!btmgr_session_record_is_gui(&ut),
	    "a BOOT_TIME record is not a session");
	ut.ut_type = DEAD_PROCESS;
	ok(!btmgr_session_record_is_gui(&ut),
	    "nor is a DEAD_PROCESS record");
	ut.ut_type = EMPTY;
	ok(!btmgr_session_record_is_gui(&ut), "nor is an empty slot");
}

static void
test_leader(void)
{
	struct utmpx	 ut;

	printf("\nA9.5 the leader must be live and ours\n");

	gui_record(&ut, ":0", "");
	ok(btmgr_session_leader_matches(&ut, getuid()),
	    "our own pid, logged in now, matches our uid");

	/* The uid check: a leader owned by somebody else is not our session. */
	ok(!btmgr_session_leader_matches(&ut, getuid() + 1),
	    "a leader running as another user does not match");

	/*
	 * A reused pid. The record claims a login before this process started,
	 * so the pid now belongs to something else.
	 */
	gui_record(&ut, ":0", "");
	ut.ut_tv.tv_sec = 1;
	ok(!btmgr_session_leader_matches(&ut, getuid()),
	    "a leader that started after its own login record is a reused pid");

	/* A record pointing at nothing. */
	gui_record(&ut, ":0", "");
	ut.ut_pid = 999999;
	ok(!btmgr_session_leader_matches(&ut, getuid()),
	    "a record whose leader has gone does not match");
	ut.ut_pid = 0;
	ok(!btmgr_session_leader_matches(&ut, getuid()),
	    "nor does a record with no pid");
}

static void
test_allowed(void)
{
	printf("\nA5.3, A9.6 the decision\n");

	ok(btmgr_session_peer_allowed(0, getpid()),
	    "root is allowed whatever its session");
	ok(btmgr_session_peer_allowed(0, -1),
	    "root is allowed even with no usable pid, since the uid decides");

	/* A9.6: a database we cannot read must refuse, never admit. */
	btmgr_session_set_db("/nonexistent/utx.active");
	ok(!btmgr_session_peer_allowed(getuid(), getpid()),
	    "an unreadable database refuses, per A9.6");

	btmgr_session_set_db("/dev/null");
	ok(!btmgr_session_peer_allowed(getuid(), getpid()),
	    "an empty database refuses, since it holds no GUI session");

	btmgr_session_set_db(NULL);
}

int
main(void)
{

	test_descent();
	test_record();
	test_leader();
	test_allowed();

	printf("\n%d checks, %d failures\n", checks, failures);

	return (failures == 0 ? 0 : 1);
}

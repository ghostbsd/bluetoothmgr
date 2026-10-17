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

/* A record naming this process as its session leader, logged in now. */
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
test_session_walk(void)
{
	pid_t	 self = getpid();
	pid_t	 parent = getppid();

	printf("\nA9.4 the session walk\n");

	ok(btmgr_session_belongs_to(self, self),
	    "a process is its own leader, so a leader's own peer passes");
	ok(btmgr_session_belongs_to(self, parent),
	    "and it belongs to its parent's session");
	ok(btmgr_session_belongs_to(self, 1),
	    "and reaches init, which every process does");

	/* Our own session leader, which is what a GUI record names. */
	ok(btmgr_session_belongs_to(self, getsid(0)),
	    "our own session id is accepted, even though it is not a parent");

	/*
	 * The kernel is pid 0 and leads no session, so the walk must stop
	 * rather than treating 0 as a wildcard.
	 */
	ok(!btmgr_session_belongs_to(self, 0), "pid 0 leads nothing");
	ok(!btmgr_session_belongs_to(self, -1),
	    "a negative leader is refused");
	ok(!btmgr_session_belongs_to(0, 1), "pid 0 as the peer is refused");
	ok(!btmgr_session_belongs_to(-1, 1), "a negative peer is refused");

	/* The walk goes upward, so init is not in our session. */
	ok(!btmgr_session_belongs_to(1, self),
	    "init does not belong to our session");

	/* A pid that cannot exist: the walk must fail, not loop. */
	ok(!btmgr_session_belongs_to(self, 999999),
	    "a leader that is not in our chain is refused");
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

	/*
	 * A colon after the first character must not count. ut_host carries the
	 * client address of an ssh login, and an IPv6 one is full of colons.
	 */
	gui_record(&ut, "pts/0", "::1");
	ok(!btmgr_session_record_is_gui(&ut),
	    "ssh from IPv6 loopback is not a GUI session");
	gui_record(&ut, "pts/0", "2001:db8::1");
	ok(!btmgr_session_record_is_gui(&ut),
	    "nor is ssh from any other IPv6 address");
	gui_record(&ut, "pts/0", "fe80::1%em0");
	ok(!btmgr_session_record_is_gui(&ut),
	    "nor one with a scope id");
	gui_record(&ut, "a:0", "b:0");
	ok(!btmgr_session_record_is_gui(&ut),
	    "a colon in the middle of either field is not a display");

	/* The display number itself has to be a number. */
	gui_record(&ut, ":", "");
	ok(!btmgr_session_record_is_gui(&ut), "a bare colon is not a display");
	gui_record(&ut, ":a", "");
	ok(!btmgr_session_record_is_gui(&ut), "nor is a non-numeric display");
	gui_record(&ut, "::", "");
	ok(!btmgr_session_record_is_gui(&ut), "nor two colons alone");
	gui_record(&ut, ":0:", "");
	ok(!btmgr_session_record_is_gui(&ut), "nor a trailing colon");
	gui_record(&ut, ":0.", "");
	ok(!btmgr_session_record_is_gui(&ut), "nor a screen number left empty");

	/* The forms that are real displays. */
	gui_record(&ut, ":10", "");
	ok(btmgr_session_record_is_gui(&ut), "a two digit display counts");
	gui_record(&ut, ":0.0", "");
	ok(btmgr_session_record_is_gui(&ut), "so does one with a screen number");

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
	 * An old login time must NOT reject a live leader. ki_start is derived
	 * from a boot time that a suspend re-estimates, so on a machine that
	 * has slept every real leader looks younger than its own record.
	 */
	gui_record(&ut, ":0", "");
	ut.ut_tv.tv_sec = 1;
	ok(btmgr_session_leader_matches(&ut, getuid()),
	    "a login record older than the leader is still accepted, per A9.5");

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

	test_session_walk();
	test_record();
	test_leader();
	test_allowed();

	printf("\n%d checks, %d failures\n", checks, failures);

	return (failures == 0 ? 0 : 1);
}

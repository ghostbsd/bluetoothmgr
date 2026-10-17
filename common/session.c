/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * session.c - the A9 GUI session test.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <syslog.h>
#include <utmpx.h>

#include "session.h"

static const char	*utmpx_db;	/* NULL selects the system default */
static int		 db_warned;	/* so one outage logs once */

static int	 proc_info(pid_t pid, struct kinfo_proc *out);
static int	 is_display_spec(const char *field, size_t size);

void
btmgr_session_set_db(const char *path)
{

	utmpx_db = path;
}

static int
proc_info(pid_t pid, struct kinfo_proc *out)
{
	size_t	 len;
	int	 mib[4];

	if (pid <= 0)
		return (-1);

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = (int)pid;

	len = sizeof(*out);
	if (sysctl(mib, 4, out, &len, NULL, 0) < 0)
		return (-1);

	/* A pid that has gone returns success with nothing written. */
	if (len != sizeof(*out))
		return (-1);

	return (0);
}

int
btmgr_session_descends_from(pid_t pid, pid_t ancestor)
{
	struct kinfo_proc	 kp;
	int			 depth;

	if (pid <= 0 || ancestor <= 0)
		return (0);

	for (depth = 0; depth < BTMGR_SESSION_MAX_DEPTH; depth++) {
		if (pid == ancestor)
			return (1);

		/* init and the kernel have no useful parent to follow. */
		if (pid <= 1)
			return (0);

		if (proc_info(pid, &kp) != 0)
			return (0);

		pid = kp.ki_ppid;
	}

	return (0);
}

/*
 * A9.2. ":0" or ":0.0", not merely a leading colon: ut_host carries the client
 * address of an ssh login, and "::1" would otherwise read as a display.
 *
 * size, not strlen: these fields need no terminator when full.
 */
static int
is_display_spec(const char *field, size_t size)
{
	size_t	 i, digits;

	if (size == 0 || field[0] != ':')
		return (0);

	for (i = 1, digits = 0; i < size && field[i] >= '0' &&
	    field[i] <= '9'; i++)
		digits++;

	if (digits == 0)
		return (0);

	if (i < size && field[i] == '.') {
		for (i++, digits = 0; i < size && field[i] >= '0' &&
		    field[i] <= '9'; i++)
			digits++;

		if (digits == 0)
			return (0);
	}

	return (i == size || field[i] == '\0');
}

/* Both fields matter, per A9.1. */
int
btmgr_session_record_is_gui(const struct utmpx *ut)
{

	if (ut->ut_type != USER_PROCESS)
		return (0);

	return (is_display_spec(ut->ut_line, sizeof(ut->ut_line)) ||
	    is_display_spec(ut->ut_host, sizeof(ut->ut_host)));
}

/*
 * A9.5. No comparison against ut_tv: ki_start is derived from a boot time a
 * suspend re-estimates, so every leader on a slept machine looks younger than
 * its own login record.
 */
int
btmgr_session_leader_matches(const struct utmpx *ut, uid_t peer_uid)
{
	struct kinfo_proc	 kp;

	if (proc_info(ut->ut_pid, &kp) != 0)
		return (0);

	return (kp.ki_uid == peer_uid);
}

/* A5.4. */
int
btmgr_session_peer_start(pid_t pid, struct timeval *out)
{
	struct kinfo_proc	 kp;

	if (out == NULL || proc_info(pid, &kp) != 0)
		return (-1);

	*out = kp.ki_start;

	return (0);
}

int
btmgr_session_peer_allowed(uid_t peer_uid, pid_t peer_pid)
{
	struct utmpx	*ut;
	int		 allowed;

	if (peer_uid == 0)
		return (1);

	if (setutxdb(UTXDB_ACTIVE, utmpx_db) != 0) {
		/* Warn once, or an unreadable db just looks like a denial. */
		if (!db_warned) {
			syslog(LOG_ERR, "cannot read the session database: %m");
			db_warned = 1;
		}
		return (0);
	}
	db_warned = 0;

	allowed = 0;
	while ((ut = getutxent()) != NULL) {
		if (!btmgr_session_record_is_gui(ut) ||
		    !btmgr_session_leader_matches(ut, peer_uid))
			continue;

		if (btmgr_session_descends_from(peer_pid, ut->ut_pid)) {
			allowed = 1;
			break;
		}
	}

	endutxent();

	return (allowed);
}

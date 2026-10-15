/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * session.c - the A9 GUI session test.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <utmpx.h>

#include "session.h"

static const char	*utmpx_db;	/* NULL selects the system default */

static int	 proc_info(pid_t pid, struct kinfo_proc *out);

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

/* Both fields matter, per A9.1. */
int
btmgr_session_record_is_gui(const struct utmpx *ut)
{

	if (ut->ut_type != USER_PROCESS)
		return (0);

	return (ut->ut_line[0] == ':' || ut->ut_host[0] == ':');
}

/*
 * A9.5, plus a uid match. A leader that started after its own login record is
 * a different process wearing a reused pid, and a peer running as another user
 * inside the session tree, by su or a setuid binary, is not the GUI user even
 * though it descends from the leader.
 */
int
btmgr_session_leader_matches(const struct utmpx *ut, uid_t peer_uid)
{
	struct kinfo_proc	 kp;

	if (proc_info(ut->ut_pid, &kp) != 0)
		return (0);

	if (kp.ki_start.tv_sec > ut->ut_tv.tv_sec)
		return (0);

	return (kp.ki_uid == peer_uid);
}

int
btmgr_session_peer_allowed(uid_t peer_uid, pid_t peer_pid)
{
	struct utmpx	*ut;
	int		 allowed;

	if (peer_uid == 0)
		return (1);

	if (setutxdb(UTXDB_ACTIVE, utmpx_db) != 0)
		return (0);

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

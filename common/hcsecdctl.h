/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * hcsecdctl.h - controlling the hcsecd *process*. SPEC.md A8.1, A8.1.1, A8.2.
 *
 * Not to be confused with hcsecd.h, which is hcsecd's *config file*. This
 * module never reads a config file; it finds the running daemon and signals it.
 *
 * A6 needs exactly two things from here, and they are the two members of
 * struct pair_ops:
 *
 *	struct pair_ops ops = { hcsecd_ctl_reload, hcsecd_ctl_running, &ctl };
 *
 * Both are the same lookup underneath: find every running hcsecd, then either
 * signal it or report that it is there.
 *
 * Two things that look like the obvious implementation do not work.
 *
 * "service hcsecd reload" is not a real command. /etc/rc.d/hcsecd never sets
 * extra_commands, so reload is not one of its keywords and the call fails with
 * a usage error. Spawning service(8) would be wrong anyway: for a command that
 * rcvar does gate, rc.subr returns status 0 without acting when the service is
 * disabled, so a disabled hcsecd would have read as a successful reload and
 * lost the key exactly as F7 does.
 *
 * There is also no pidfile to read. The rc script declares
 * pidfile=/var/run/hcsecd.pid, but hcsecd only calls daemon(3) and never
 * creates it, so rc.subr falls back to matching the process table. So do we.
 */

#ifndef BTMGR_HCSECDCTL_H_
#define	BTMGR_HCSECDCTL_H_

#include <sys/param.h>
#include <sys/types.h>

#define	HCSECD_PROCNAME		"hcsecd"

/* More than one hcsecd is odd but legal, for instance a debug one by hand. */
#define	HCSECD_MAX_PIDS		8

/*
 * procname and uid are overridable so the tests can match their own process.
 * That is the only way to check the signal is really delivered without a
 * running hcsecd and without root. NULL procname selects HCSECD_PROCNAME.
 *
 * uid exists as a check, not just for testing: a real hcsecd must be root,
 * because opening the raw HCI socket is privileged. Matching on the name alone
 * would let any user park a program called hcsecd in our way.
 *
 * dry_run suppresses the signal, not the lookup. A reload is an effect on
 * another process, so a dry run reports what it would do and returns success.
 * Asking whether hcsecd is running changes nothing and so always answers
 * truthfully: a dry run that claimed hcsecd was up would park a pairing
 * against a daemon that is not there.
 */
struct hcsecd_ctl {
	char	procname[MAXCOMLEN + 1];
	uid_t	uid;
	int	dry_run;
};

/*
 * uid is the uid the process must run as. Pass 0 for the real hcsecd.
 * Returns 0, or -1 with ENAMETOOLONG if procname does not fit.
 */
int	hcsecd_ctl_init(struct hcsecd_ctl *ctl, const char *procname, uid_t uid,
	    int dry_run);

/*
 * A8.1. Send SIGHUP to every matching process. Returns 0 if at least one was
 * signalled, -1 if none was found or none could be signalled. Signature
 * matches pair_ops.reload.
 */
int	hcsecd_ctl_reload(void *context);

/*
 * A8.2. Non-zero when at least one hcsecd is running. Signature matches
 * pair_ops.hcsecd_running. Anything inconclusive answers zero, since that is
 * the direction in which pairing writes nothing.
 */
int	hcsecd_ctl_running(void *context);

/*
 * The shared lookup, exposed for the tests and for callers that want to report
 * the pid. Fills up to maxpids entries and sets *found to how many matched.
 *
 * Returns 0 when at least one matched, or -1 with errno: ESRCH for none,
 * ENOMEM if the process table could not be read, EINVAL for bad arguments.
 * A match beyond maxpids is dropped, and *found never exceeds maxpids.
 */
int	hcsecd_ctl_find(const struct hcsecd_ctl *ctl, pid_t *pids,
	    size_t maxpids, size_t *found);

#endif /* !BTMGR_HCSECDCTL_H_ */

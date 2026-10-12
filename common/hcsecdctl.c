/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * hcsecdctl.c - find the running hcsecd and signal it. See hcsecdctl.h for why
 * this scans the process table rather than reading a pidfile or running
 * service(8).
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "hcsecdctl.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"	/* IWYU pragma: keep */

static struct kinfo_proc	*read_proc_table(size_t *nprocs);

/*
 * Snapshot the process table. The two-call sysctl idiom asks for the size and
 * then for the data, and the table can grow in between, so ask for extra room
 * and retry on ENOMEM rather than trusting the first answer.
 *
 * Returns a malloc'd array the caller frees, with *nprocs set.
 */
static struct kinfo_proc *
read_proc_table(size_t *nprocs)
{
	struct kinfo_proc	*procs;
	size_t			 len;
	int			 mib[3];
	int			 tries;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PROC;

	for (tries = 0; tries < 3; tries++) {
		len = 0;
		if (sysctl(mib, 3, NULL, &len, NULL, 0) < 0)
			return (NULL);
		if (len == 0 || len > SIZE_MAX / 2) {
			errno = ENOMEM;
			return (NULL);
		}

		/* Room for processes that start between the two calls. */
		len += len / 8 + sizeof(*procs) * 8;

		procs = malloc(len);
		if (procs == NULL)
			return (NULL);

		if (sysctl(mib, 3, procs, &len, NULL, 0) == 0) {
			*nprocs = len / sizeof(*procs);
			return (procs);
		}

		free(procs);
		if (errno != ENOMEM)
			return (NULL);
	}

	errno = ENOMEM;

	return (NULL);
}

int
hcsecd_ctl_init(struct hcsecd_ctl *ctl, const char *procname, uid_t uid,
    int dry_run)
{

	if (ctl == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(ctl, 0, sizeof(*ctl));
	ctl->uid = uid;
	ctl->dry_run = dry_run;

	if (procname == NULL)
		procname = HCSECD_PROCNAME;

	/*
	 * An empty name would match every process whose ki_comm is empty, so
	 * refuse it rather than hand a wildcard to kill().
	 */
	if (procname[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}

	if (strlcpy(ctl->procname, procname, sizeof(ctl->procname)) >=
	    sizeof(ctl->procname)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	return (0);
}

int
hcsecd_ctl_find(const struct hcsecd_ctl *ctl, pid_t *pids, size_t maxpids,
    size_t *found)
{
	struct kinfo_proc	*procs;
	size_t			 nprocs, i, n;

	if (ctl == NULL || pids == NULL || maxpids == 0 || found == NULL) {
		errno = EINVAL;
		return (-1);
	}

	*found = 0;

	procs = read_proc_table(&nprocs);
	if (procs == NULL)
		return (-1);

	n = 0;
	for (i = 0; i < nprocs && n < maxpids; i++) {
		/*
		 * A zombie keeps its name but cannot act on a signal, so
		 * counting one as "hcsecd is running" would park a pairing
		 * against a process that has already gone.
		 */
		if (procs[i].ki_stat == SZOMB)
			continue;

		/*
		 * kill(2) reads 0 as "my whole process group" and a negative
		 * pid as a process group too, so a pid that could mean either
		 * must never reach it. 1 is init.
		 */
		if (procs[i].ki_pid <= 1)
			continue;

		/* A real hcsecd is root: the raw HCI socket is privileged. */
		if (procs[i].ki_uid != ctl->uid)
			continue;

		if (strncmp(procs[i].ki_comm, ctl->procname,
		    sizeof(procs[i].ki_comm)) != 0)
			continue;

		pids[n++] = procs[i].ki_pid;
	}

	free(procs);

	*found = n;
	if (n == 0) {
		errno = ESRCH;
		return (-1);
	}

	return (0);
}

int
hcsecd_ctl_reload(void *context)
{
	struct hcsecd_ctl	*ctl = context;
	pid_t			 pids[HCSECD_MAX_PIDS];
	size_t			 found, i, sent;

	if (hcsecd_ctl_find(ctl, pids, HCSECD_MAX_PIDS, &found) != 0) {
		syslog(LOG_ERR, "hcsecd reload: no running %s: %m",
		    ctl->procname);
		return (-1);
	}

	if (found > 1)
		syslog(LOG_WARNING, "hcsecd reload: %zu processes named %s, "
		    "signalling all of them", found, ctl->procname);

	/* The lookup is a read, so it happens even in a dry run. The signal. */
	if (ctl->dry_run) {
		syslog(LOG_INFO, "dry run: would SIGHUP %s, pid %d",
		    ctl->procname, (int)pids[0]);
		return (0);
	}

	sent = 0;
	for (i = 0; i < found; i++) {
		if (kill(pids[i], SIGHUP) == 0)
			sent++;
		else
			syslog(LOG_ERR, "hcsecd reload: SIGHUP pid %d: %m",
			    (int)pids[i]);
	}

	if (sent == 0)
		return (-1);

	return (0);
}

int
hcsecd_ctl_running(void *context)
{
	pid_t	 pids[HCSECD_MAX_PIDS];
	size_t	 found;

	return (hcsecd_ctl_find(context, pids, HCSECD_MAX_PIDS, &found) == 0);
}

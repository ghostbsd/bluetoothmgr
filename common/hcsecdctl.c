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
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "hcsecdctl.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"	/* IWYU pragma: keep */

static struct kinfo_proc	*read_proc_table(size_t *process_count);
static int			 each_hcsecd(const struct hcsecd_ctl *control,
				     int signal_number);

/* A malloc'd snapshot of the process table, with *process_count set. */
static struct kinfo_proc *
read_proc_table(size_t *process_count)
{
	struct kinfo_proc	*processes;
	size_t			 table_size = 0;
	int			 query[3] =
	    { CTL_KERN, KERN_PROC, KERN_PROC_PROC };

	if (sysctl(query, 3, NULL, &table_size, NULL, 0) < 0)
		return (NULL);

	/* Room for processes that start between the two calls. */
	table_size += table_size / 8 + sizeof(*processes) * 8;

	processes = malloc(table_size);
	if (processes == NULL)
		return (NULL);

	if (sysctl(query, 3, processes, &table_size, NULL, 0) < 0) {
		free(processes);
		return (NULL);
	}

	*process_count = table_size / sizeof(*processes);

	return (processes);
}

/* Send signal_number to every running hcsecd, or count them for 0. */
static int
each_hcsecd(const struct hcsecd_ctl *control, int signal_number)
{
	struct kinfo_proc	*processes, *process;
	size_t			 process_count, index;
	int			 matched = 0;

	processes = read_proc_table(&process_count);
	if (processes == NULL)
		return (-1);

	for (index = 0; index < process_count; index++) {
		process = &processes[index];

		/* A8.1.3: kill(2) reads pid 0 as our whole process group. */
		if (process->ki_stat == SZOMB || process->ki_pid <= 1 ||
		    process->ki_uid != control->uid ||
		    strncmp(process->ki_comm, control->procname,
		    sizeof(process->ki_comm)) != 0)
			continue;

		if (signal_number != 0 &&
		    kill(process->ki_pid, signal_number) != 0) {
			syslog(LOG_ERR, "hcsecd reload: SIGHUP pid %d: %m",
			    (int)process->ki_pid);
			continue;
		}
		matched++;
	}

	free(processes);

	return (matched);
}

int
hcsecd_ctl_init(struct hcsecd_ctl *control, const char *procname, uid_t uid,
    int dry_run)
{

	memset(control, 0, sizeof(*control));
	control->uid = uid;
	control->dry_run = dry_run;

	if (procname == NULL)
		procname = HCSECD_PROCNAME;

	if (strlcpy(control->procname, procname, sizeof(control->procname)) >=
	    sizeof(control->procname)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	return (0);
}

int
hcsecd_ctl_reload(void *context)
{
	struct hcsecd_ctl	*control = context;

	/* A dry run still looks, so it fails the same way with no hcsecd. */
	if (each_hcsecd(control, control->dry_run ? 0 : SIGHUP) <= 0) {
		syslog(LOG_ERR, "hcsecd reload: no running %s was signalled",
		    control->procname);
		return (-1);
	}

	if (control->dry_run)
		syslog(LOG_INFO, "dry run: would SIGHUP %s",
		    control->procname);

	return (0);
}

int
hcsecd_ctl_running(void *context)
{

	return (each_hcsecd(context, 0) > 0);
}

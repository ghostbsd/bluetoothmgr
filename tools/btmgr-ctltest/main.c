/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-ctltest - verification for common/hcsecdctl.c. SPEC.md A8.1, A8.1.1,
 * A8.2.
 *
 * Needs no root, no hardware and no running hcsecd. The module matches the
 * process table by name and uid, and both are overridable, so this points it
 * at its own process. A8.1 can then be checked for real: install a SIGHUP
 * handler, ask for a reload, and see the signal arrive.
 *
 * The pid filter in A8.1.1 is the part worth testing hardest, and testing it
 * needs care. kill(2) reads 0 as "my whole process group", so a lookup that
 * returned pid 0 and reached kill() would signal the shell that started this
 * test. The cases that aim at pid 0 and pid 1 therefore only ever call
 * hcsecd_ctl_running(), never hcsecd_ctl_reload().
 *
 * Exits 0 when every check passes, 1 otherwise.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hcsecdctl.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"	/* IWYU pragma: keep */

static int		 failures;
static int		 checks;
static volatile sig_atomic_t hups;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 on_hup(int sig);
static int	 procname_of(pid_t pid, char *out, size_t outlen);

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
on_hup(int sig)
{

	(void)sig;
	hups++;
}

/*
 * A process's name as the kernel records it, rather than argv[0], because that
 * is what hcsecdctl.c compares against and the kernel truncates it.
 */
static int
procname_of(pid_t pid, char *out, size_t outlen)
{
	struct kinfo_proc	 kp;
	size_t			 len;
	int			 mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = (int)pid;

	len = sizeof(kp);
	if (sysctl(mib, 4, &kp, &len, NULL, 0) < 0)
		return (-1);
	if (len != sizeof(kp))
		return (-1);

	if (strlcpy(out, kp.ki_comm, outlen) >= outlen)
		return (-1);

	return (0);
}

static void
test_init(void)
{
	struct hcsecd_ctl	 ctl;
	char			 toolong[MAXCOMLEN + 8];

	printf("\nhcsecd_ctl_init\n");

	ok(hcsecd_ctl_init(&ctl, NULL, 0, 0) == 0, "the defaults are accepted");
	ok(strcmp(ctl.procname, HCSECD_PROCNAME) == 0, "NULL selects hcsecd");
	ok(ctl.uid == 0, "with uid 0, which a real hcsecd must be");
	ok(ctl.dry_run == 0, "and dry run off");

	ok(hcsecd_ctl_init(&ctl, "other", 1001, 1) == 0, "overrides are taken");
	ok(strcmp(ctl.procname, "other") == 0, "the name is the one given");
	ok(ctl.uid == 1001, "so is the uid");
	ok(ctl.dry_run == 1, "and dry run is on");

	memset(toolong, 'a', sizeof(toolong) - 1);
	toolong[sizeof(toolong) - 1] = '\0';
	errno = 0;
	ok(hcsecd_ctl_init(&ctl, toolong, 0, 0) == -1 && errno == ENAMETOOLONG,
	    "a name longer than the kernel keeps is refused");
}

/* A8.2, and the uid check, against names that cannot match. */
static void
test_absent(void)
{
	struct hcsecd_ctl	 ctl;
	char			 name[MAXCOMLEN + 1];

	printf("\nA8.2 nothing matching\n");

	if (hcsecd_ctl_init(&ctl, "no-such-proc-xyz", getuid(), 0) != 0) {
		ok(0, "could not initialise");
		return;
	}
	ok(hcsecd_ctl_running(&ctl) == 0,
	    "a name no process has is not running");

	/*
	 * Our own name but the wrong uid. This is the check that stops any
	 * user parking a program called hcsecd in the daemon's way.
	 */
	if (procname_of(getpid(), name, sizeof(name)) != 0) {
		ok(0, "could not read our own process name");
		return;
	}
	if (getuid() == 0) {
		ok(1, "skipping the uid case, running as root");
		return;
	}
	if (hcsecd_ctl_init(&ctl, name, 0, 0) != 0) {
		ok(0, "could not initialise the uid case");
		return;
	}
	ok(hcsecd_ctl_running(&ctl) == 0,
	    "our own name under uid 0 does not match, since we are not root");
}

/*
 * A8.1.1, the pid filter, in isolation. Each of these names really exists and
 * really is uid 0, so the name and uid checks both pass and the pid bound is
 * the only thing that can reject them. Never reload here: without the bound,
 * pid 0 would reach kill() and signal our whole process group.
 */
static void
test_low_pids(void)
{
	struct hcsecd_ctl	 ctl;
	char			 name[MAXCOMLEN + 1];
	size_t			 index;
	pid_t			 pid;
	static const pid_t	 low_pids[] = { 0, 1 };

	printf("\nA8.1.1 pid 0 and pid 1 are never matched\n");

	for (index = 0; index < nitems(low_pids); index++) {
		pid = low_pids[index];
		if (procname_of(pid, name, sizeof(name)) != 0) {
			ok(1, "pid %d is not visible here, nothing to check",
			    (int)pid);
			continue;
		}
		if (hcsecd_ctl_init(&ctl, name, 0, 0) != 0) {
			ok(0, "could not initialise for pid %d", (int)pid);
			continue;
		}
		ok(hcsecd_ctl_running(&ctl) == 0,
		    "pid %d (\"%s\", uid 0) is not matched", (int)pid, name);
	}
}

/* A8.1 and A8.2 against a process that really is us. */
static void
test_signal(void)
{
	struct hcsecd_ctl	 ctl;
	struct sigaction	 sa, old;
	char			 name[MAXCOMLEN + 1];
	int			 before;

	printf("\nA8.1 the reload is a real SIGHUP\n");

	if (procname_of(getpid(), name, sizeof(name)) != 0) {
		ok(0, "could not read our own process name");
		return;
	}
	if (hcsecd_ctl_init(&ctl, name, getuid(), 0) != 0) {
		ok(0, "could not initialise");
		return;
	}

	ok(hcsecd_ctl_running(&ctl) == 1,
	    "our own process is found by name and uid");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_hup;
	(void)sigemptyset(&sa.sa_mask);
	if (sigaction(SIGHUP, &sa, &old) != 0) {
		ok(0, "could not install a SIGHUP handler");
		return;
	}

	before = (int)hups;
	ok(hcsecd_ctl_reload(&ctl) == 0, "the reload reports success");
	ok((int)hups > before, "and the SIGHUP actually arrived");

	/* A dry run finds the process but must not signal it. */
	if (hcsecd_ctl_init(&ctl, name, getuid(), 1) == 0) {
		before = (int)hups;
		ok(hcsecd_ctl_reload(&ctl) == 0, "a dry run reports success");
		ok((int)hups == before, "and sends no signal");
		ok(hcsecd_ctl_running(&ctl) == 1,
		    "while running still answers truthfully in a dry run");
	} else
		ok(0, "could not set up the dry run case");

	/* Nothing to signal: reload must fail, not succeed quietly. */
	if (hcsecd_ctl_init(&ctl, "no-such-proc-xyz", getuid(), 0) == 0) {
		before = (int)hups;
		ok(hcsecd_ctl_reload(&ctl) == -1,
		    "a reload with no hcsecd fails, it does not report success");
		ok((int)hups == before, "and sends nothing");
	} else
		ok(0, "could not set up the missing-process reload case");

	(void)sigaction(SIGHUP, &old, NULL);
}

int
main(void)
{

	test_init();
	test_absent();
	test_low_pids();
	test_signal();

	if (btmgr_mc_report() != 0) {
		printf("memcheck: allocations still live\n");
		failures++;
	}

	printf("\n%d checks, %d failures\n", checks, failures);

	return (failures != 0);
}

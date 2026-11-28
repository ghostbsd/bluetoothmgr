/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * safefile.h - every config file write, under SPEC.md A0: edited in place
 * (A0.1, A0.6), backed up once per boot (A0.2), skipped when identical (A0.5).
 * A0.3 and A0.4 are the callers' job. Tested by tools/btmgr-filetest.
 */

#ifndef BTMGR_SAFEFILE_H_
#define	BTMGR_SAFEFILE_H_

#include <sys/types.h>

#include <limits.h>
#include <stddef.h>

/*
 * Where the per-boot backup markers live. A0.2 is scoped to a boot, so we need
 * to know whether the .bak on disk was made during this one. We do not compare
 * the .bak's mtime against kern.boottime: an NTP step backwards would make a
 * backup we wrote look older than the boot, and we would then overwrite the
 * user's pristine pre-BluetoothMgr file with our own output. Losing that file
 * is the exact outcome A0.2 exists to prevent, so the marker is a file in a
 * directory the system clears at boot, which depends on no clock at all.
 */
#define	SAFEFILE_RUNDIR		"/var/run/bluetoothmgr"

/* Outcomes of a write. Negative is failure, zero and up are success. */
enum safefile_result {
	SAFEFILE_ERROR	 = -1,
	SAFEFILE_WRITTEN =  0,	/* content differed and was written */
	SAFEFILE_UNCHANGED = 1,	/* A0.5: identical on disk, nothing done */
	SAFEFILE_DRYRUN	 = 2	/* would have written, --dry-run is on */
};

/*
 * Caller-owned configuration, so that tests and --dry-run can redirect
 * everything away from /etc and /var/run without the generators knowing.
 */
struct safefile_ctx {
	char	rundir[PATH_MAX];	/* per-boot markers (A0.2) */
	int	dry_run;		/* report, change nothing */
};

/*
 * Initialise a context. Passing NULL for rundir selects SAFEFILE_RUNDIR.
 * Returns 0, or -1 with errno set to ENAMETOOLONG if rundir does not fit.
 */
int	safefile_init(struct safefile_ctx *context, const char *rundir,
	    int dry_run);

/*
 * Write buf to path in place. mode applies only to a file created here; an
 * existing file keeps its own mode and owner. On SAFEFILE_ERROR the reason is
 * in err, at least SAFEFILE_ERRLEN bytes, and errno is from the failed call.
 */
#define	SAFEFILE_ERRLEN		256

int	safefile_write(const struct safefile_ctx *context, const char *path,
	    mode_t mode, const void *buf, size_t len, char *err, size_t errlen);

/*
 * Slurp a whole file. Returns a malloc'd, NUL terminated buffer the caller
 * frees, with the length (not counting the NUL) in *lenp when lenp is not
 * NULL. Returns NULL on failure with errno set; ENOENT is an ordinary result
 * for a config file that does not exist yet, not an error worth logging.
 *
 * The NUL terminator is what lets the parsers built on top of this use the
 * ordinary string functions on file contents.
 */
char	*safefile_read(const char *path, size_t *lenp);

#endif /* !BTMGR_SAFEFILE_H_ */

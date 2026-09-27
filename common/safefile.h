/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * safefile.h - the A0 write discipline. SPEC.md Part A, section A0.
 *
 * Every configuration file BluetoothMgr writes goes through here. The rules
 * are not stylistic: hcsecd parses its config with a yacc grammar and will
 * refuse to start on a truncated file, and /etc/bluetooth/hosts is read by
 * libbluetooth on behalf of every Bluetooth program on the system. A partial
 * write to either one breaks a working machine.
 *
 * What this file implements, rule by rule:
 *
 *   A0.1  write a temp file in the target's directory, fsync, rename over
 *   A0.2  copy the pre-existing file to <path>.bak once per boot, mode and
 *         ownership preserved
 *   A0.5  do not write at all when the new content matches what is on disk
 *   A0.6  temp files created O_EXCL mode 0600, chmod'ed to the target's mode
 *         before the rename
 *
 * A0.3 (parse into a model, re-emit in full) and A0.4 (preserve content we did
 * not author) are obligations on the callers, not on this layer. This layer
 * only ever sees a finished buffer. It cannot tell a faithful re-emission from
 * a lossy one, which is why each generator owns its own round-trip test.
 *
 * Nothing here needs root, and nothing here is Bluetooth specific, so the
 * whole layer is exercised by tools/btmgr-filetest against a scratch
 * directory. See that program for the verification each rule gets.
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
	SAFEFILE_WRITTEN =  0,	/* content differed, the rename happened */
	SAFEFILE_UNCHANGED,	/* A0.5: identical on disk, nothing done */
	SAFEFILE_DRYRUN		/* would have written, --dry-run is on */
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
int	safefile_init(struct safefile_ctx *ctx, const char *rundir,
	    int dry_run);

/*
 * Write buf to path under the A0 rules.
 *
 * mode applies only when path does not exist yet. A file that is already there
 * keeps its own mode and, where we have the privilege to set it, its own
 * ownership: these files predate us and the system's expectations about them
 * are not ours to change. So hcsecd.conf stays 0600 and hosts stays 0644
 * without this layer needing to know which is which, while a file we create
 * from nothing, such as A4's devices.json, gets the mode the caller names.
 *
 * path SHOULD be absolute. The per-boot marker of A0.2 is derived from the
 * path as given, so reaching one file by two different spellings would give it
 * two markers and therefore two backups.
 *
 * Returns one of enum safefile_result. On SAFEFILE_ERROR a human readable
 * reason is written to err, which must be at least SAFEFILE_ERRLEN bytes, and
 * the target file is left exactly as it was. errno is preserved from the call
 * that failed.
 *
 * The write is all or nothing from any reader's point of view: readers see
 * either the whole old file or the whole new one, never a mixture, because the
 * only mutation of the target is a rename(2) within one filesystem.
 */
#define	SAFEFILE_ERRLEN		256

int	safefile_write(const struct safefile_ctx *ctx, const char *path,
	    const void *buf, size_t len, mode_t mode, char *err, size_t errlen);

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

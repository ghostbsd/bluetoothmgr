/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * pairing.h - the A6 ordering constraint. SPEC.md A6, with A8 service control.
 *
 * A6 is the single most important rule in Part A, and it is an ordering rule:
 * the device's block must exist in hcsecd.conf, and hcsecd must have reloaded,
 * BEFORE pairing starts. Pair first and hcsecd answers the PIN request from the
 * default entry, the device appears to pair, and get_key() then discards the
 * link key because no exact block exists. That is F7.
 *
 * The sequence spans an asynchronous gap, so this is not one function:
 *
 *	1-4  pairing_begin()      alias, hosts, hcsecd.conf, reload
 *	5                         the caller issues Create_Connection
 *	     ...on the air...
 *	6-7  pairing_complete()   called when Link_Key_Notification arrives
 *
 * pairing_abort() is the other exit, for a reload failure (A6.3) or a key that
 * never arrives. It restores both config files to the bytes they had before
 * pairing_begin() touched them (A6.4).
 *
 * A6.2 says no reload may happen between steps 5 and 6. That is not enforced by
 * omitting a call here: the caller must refuse to service any other config
 * write while a pairing is parked, because someone else's reload would drop the
 * in-flight pairing just as surely as ours would.
 */

#ifndef BTMGR_PAIRING_H_
#define	BTMGR_PAIRING_H_

#include <stdint.h>

#include "btaddr.h"
#include "paths.h"

/*
 * What the sequencer cannot do for itself. A8.1 requires "service hcsecd
 * reload", never restart, since a restart tears down the HCI socket and drops
 * in-flight pairing while SIGHUP preserves learned keys.
 *
 * A7.3 forbids building either call with system(3) or popen(3). The daemon's
 * implementation must use posix_spawn() or fork() plus execve() with an
 * argument vector.
 */
struct pair_ops {
	int	 (*reload)(void *context);		/* 0 on success */
	int	 (*hcsecd_running)(void *context);	/* non-zero if running */
	void	  *context;
};

enum pair_result {
	PAIR_ERROR	= -1,	/* internal failure; see report->rolled_back */
	PAIR_PARKED	= 0,	/* 1 to 4 done, the caller may now connect */
	PAIR_DONE	= 1,	/* 6 and 7 done */
	PAIR_NO_HCSECD	= 2,	/* A8.2: not running, a key cannot persist */
	PAIR_REFUSED	= 3	/* the default entry, or an unusable request */
};

#define	PAIR_TRACE_MAX		128
#define	PAIR_DETAIL_MAX		160

/*
 * Where the sequence got to, for the caller to report and for the tests to
 * assert ordering on. trace is a comma separated list of the steps actually
 * taken, so "alias,hosts,secd,reload" is a successful begin and
 * "alias,hosts,secd,reload-failed,rollback" is an A6.3 abort.
 */
struct pair_report {
	char	 trace[PAIR_TRACE_MAX];
	char	 detail[PAIR_DETAIL_MAX];
	int	 rolled_back;
};

/*
 * The parked pairing. Holds the pre-change text of both config files, because
 * rollback has to restore them and removing what we added is only the inverse
 * in the append case: re-pairing a device we already manage is an update, and
 * inverting that would need the previous value.
 *
 * One at a time is deliberate. A6.2 forbids a reload during a pairing, so a
 * second concurrent pairing could not have its step 4 anyway.
 */
struct pair_state {
	uint8_t	 addr[BTMGR_ADDR_LEN];
	char	*hosts_before;		/* NULL when the file was absent */
	char	*hcsecd_before;
	int	 active;
};

/*
 * Steps 1 to 4. name is the remote device's friendly name, which is sanitised
 * here, and pin may be NULL for a device that needs none.
 *
 * On PAIR_PARKED the caller owns state until it calls complete or abort, and
 * MUST NOT write any config file in between (A6.2).
 *
 * Returns PAIR_NO_HCSECD without touching anything when hcsecd is not running,
 * since a key could not persist and A8.2 wants that reported distinctly rather
 * than as an obscure failure. Returns PAIR_REFUSED for the default entry.
 *
 * On PAIR_ERROR the rollback has already been attempted; report->rolled_back
 * says whether it succeeded.
 */
enum pair_result pairing_begin(const struct btmgr_paths *paths,
	    const struct pair_ops *ops, const uint8_t *addr, const char *name,
	    const char *pin, struct pair_state *state,
	    struct pair_report *report);

/*
 * Steps 6 and 7, on Link_Key_Notification. Reloads again so hcsecd's
 * dump_keys_file() flushes the new key to disk (A8.3), then records the device
 * in devices.json. type is the B5.3 vocabulary as a string, or NULL.
 *
 * Releases state on any return.
 */
enum pair_result pairing_complete(const struct btmgr_paths *paths,
	    const struct pair_ops *ops, struct pair_state *state,
	    const char *name, const char *type, int64_t now,
	    struct pair_report *report);

/*
 * A6.4. Restore both config files to their pre-begin bytes and reload, so
 * hcsecd stops honouring a block we are abandoning. Releases state.
 */
enum pair_result pairing_abort(const struct btmgr_paths *paths,
	    const struct pair_ops *ops, struct pair_state *state,
	    struct pair_report *report);

/* Release a state without touching any file, for a caller that is giving up. */
void		 pairing_state_free(struct pair_state *state);

#endif /* !BTMGR_PAIRING_H_ */
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * pairing.c - the A6 ordering constraint. See pairing.h for the sequence and
 * for why it is split across an asynchronous gap.
 */

#include <sys/cdefs.h>

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btaddr.h"
#include "hcsecd.h"
#include "hosts.h"
#include "pairing.h"
#include "paths.h"
#include "safefile.h"
#include "sanitise.h"
#include "store.h"

/*
 * Must come after the system headers: it redefines malloc and friends. The
 * pragma says so to clang-include-cleaner, which sees no direct use of this
 * header because the use is macro replacement of malloc(), not a symbol.
 */
#include "memcheck.h"	/* IWYU pragma: keep */

static void	 trace_step(struct pair_report *report, const char *step);
static void	 set_detail(struct pair_report *report, const char *fmt, ...)
		     __printflike(2, 3);
static int	 write_text(const struct btmgr_paths *paths, const char *path,
		     mode_t mode, const char *text, struct pair_report *report);
static int	 restore(const struct btmgr_paths *paths, const char *path,
		     mode_t mode, const char *before);

/* Append one step to the trace, so ordering is assertable. */
static void
trace_step(struct pair_report *report, const char *step)
{
	size_t	 used;

	if (report == NULL)
		return;

	used = strlen(report->trace);
	(void)snprintf(report->trace + used, sizeof(report->trace) - used,
	    "%s%s", used > 0 ? "," : "", step);
}

static void
set_detail(struct pair_report *report, const char *fmt, ...)
{
	va_list	 ap;
	int	 saved;

	if (report == NULL)
		return;

	saved = errno;
	va_start(ap, fmt);
	(void)vsnprintf(report->detail, sizeof(report->detail), fmt, ap);
	va_end(ap);
	errno = saved;
}

/* One config write under the A0 rules. Returns 0 on success or no-op. */
static int
write_text(const struct btmgr_paths *paths, const char *path, mode_t mode,
    const char *text, struct pair_report *report)
{
	char	 err[SAFEFILE_ERRLEN];
	int	 rc;

	rc = safefile_write(&paths->sf, path, mode, text, strlen(text),
	    err, sizeof(err));
	if (rc == SAFEFILE_ERROR) {
		set_detail(report, "%s: %s", path, err);
		return (-1);
	}

	return (0);
}

/*
 * Put a file back to the bytes it had before. A file that did not exist cannot
 * be un-created by safefile_write(), so this writes it empty; the generators
 * both treat an empty file the same as an absent one.
 */
static int
restore(const struct btmgr_paths *paths, const char *path, mode_t mode,
    const char *before)
{
	char	 err[SAFEFILE_ERRLEN];

	if (safefile_write(&paths->sf, path, mode, before == NULL ? "" : before,
	    before == NULL ? 0 : strlen(before), err, sizeof(err)) ==
	    SAFEFILE_ERROR)
		return (-1);

	return (0);
}

void
pairing_state_free(struct pair_state *state)
{

	if (state == NULL)
		return;

	free(state->hosts_before);
	free(state->hcsecd_before);
	memset(state, 0, sizeof(*state));
}

enum pair_result
pairing_begin(const struct btmgr_paths *paths, const struct pair_ops *ops,
    const uint8_t *addr, const char *name, const char *pin,
    struct pair_state *state, struct pair_report *report)
{
	struct hosts_db		*hosts = NULL;
	struct hcsecd_db	*secd = NULL;
	char			*hosts_text = NULL;
	char			*secd_text = NULL;
	char			 alias[BTMGR_ALIAS_BUFSZ];
	enum pair_result	 result = PAIR_ERROR;

	if (report != NULL)
		memset(report, 0, sizeof(*report));
	memset(state, 0, sizeof(*state));

	/*
	 * A8.2. Without hcsecd there is nobody to answer the PIN request or to
	 * persist the key, so pairing cannot succeed. Say so before touching a
	 * single file, rather than writing a block that will never be used.
	 */
	if (ops->hcsecd_running != NULL && !ops->hcsecd_running(ops->context)) {
		trace_step(report, "no-hcsecd");
		set_detail(report, "hcsecd is not running, so a link key "
		    "cannot be persisted; set hcsecd_enable in rc.conf");
		return (PAIR_NO_HCSECD);
	}

	/* Read both files first, so rollback has something to restore to. */
	state->hosts_before = safefile_read(paths->hosts, NULL);
	state->hcsecd_before = safefile_read(paths->hcsecd, NULL);
	memcpy(state->addr, addr, BTMGR_ADDR_LEN);

	hosts = hosts_parse(state->hosts_before);
	secd = hcsecd_parse(state->hcsecd_before);
	if (hosts == NULL || secd == NULL) {
		set_detail(report, "out of memory parsing the config files");
		goto out;
	}

	/* Step 1. A2 alias, unique against everything already in the file. */
	if (hosts_alloc_alias(hosts, name, addr, alias, sizeof(alias)) != 0) {
		set_detail(report, "no alias available for this device");
		goto out;
	}
	trace_step(report, "alias");

	/* Step 2. The alias into /etc/bluetooth/hosts. */
	if (hosts_set(hosts, addr, alias, 0) == HOSTS_ERROR) {
		set_detail(report, "could not record the alias");
		goto out;
	}
	hosts_text = hosts_emit(hosts, NULL);
	if (hosts_text == NULL)
		goto out;
	if (write_text(paths, paths->hosts, BTMGR_MODE_HOSTS, hosts_text,
	    report) != 0)
		goto rollback;
	trace_step(report, "hosts");

	/*
	 * Step 3. The block in hcsecd.conf, with the PIN. A1.2.4: this must
	 * exist before pairing or get_key() discards the learned key.
	 */
	switch (hcsecd_set(secd, addr,
	    &(struct hcsecd_entry){ .name = name, .pin = pin }, 0)) {
	case HCSECD_REFUSED:
		trace_step(report, "secd-refused");
		set_detail(report, "that address is the hcsecd default entry");
		result = PAIR_REFUSED;
		goto rollback;
	case HCSECD_ERROR:
		set_detail(report, "could not build the hcsecd.conf block");
		goto rollback;
	default:
		break;
	}
	secd_text = hcsecd_emit(secd, NULL);
	if (secd_text == NULL)
		goto rollback;
	if (write_text(paths, paths->hcsecd, BTMGR_MODE_HCSECD, secd_text,
	    report) != 0)
		goto rollback;
	trace_step(report, "secd");

	/*
	 * Step 4. A8.1 reload, and A6.3: if it fails we MUST NOT go on to step
	 * 5, because hcsecd is still answering from its old configuration.
	 */
	if (ops->reload != NULL && ops->reload(ops->context) != 0) {
		trace_step(report, "reload-failed");
		set_detail(report, "service hcsecd reload failed; not pairing");
		goto rollback;
	}
	trace_step(report, "reload");

	state->active = 1;
	result = PAIR_PARKED;
	goto out;

rollback:
	/* A6.4. Both files, in case we got as far as the second one. */
	if (restore(paths, paths->hcsecd, BTMGR_MODE_HCSECD,
	    state->hcsecd_before) == 0 &&
	    restore(paths, paths->hosts, BTMGR_MODE_HOSTS,
	    state->hosts_before) == 0) {
		if (report != NULL)
			report->rolled_back = 1;
		trace_step(report, "rollback");
		if (ops->reload != NULL)
			(void)ops->reload(ops->context);
	} else
		trace_step(report, "rollback-failed");

out:
	free(hosts_text);
	free(secd_text);
	hosts_free(hosts);
	hcsecd_free(secd);

	if (result != PAIR_PARKED)
		pairing_state_free(state);

	return (result);
}

enum pair_result
pairing_complete(const struct btmgr_paths *paths, const struct pair_ops *ops,
    struct pair_state *state, const char *name, const char *type, int64_t now,
    struct pair_report *report)
{
	struct store	*store = NULL;
	char		*text = NULL;
	char		*before = NULL;
	char		 alias_copy[BTMGR_ALIAS_BUFSZ];
	int		 malformed = 0;

	if (report != NULL)
		memset(report, 0, sizeof(*report));

	if (!state->active) {
		set_detail(report, "no pairing is parked for this device");
		return (PAIR_ERROR);
	}

	trace_step(report, "key");

	/*
	 * Step 6. A8.3: hcsecd flushes keys to disk only on SIGHUP and on clean
	 * shutdown, so without this reload a panic loses the key we just
	 * learned. This is the one reload that is correct AFTER step 5.
	 */
	if (ops->reload != NULL && ops->reload(ops->context) != 0) {
		trace_step(report, "flush-failed");
		set_detail(report, "the key was learned but 'service hcsecd "
		    "reload' failed, so it may not be on disk yet");
		/* Not fatal: the key is in hcsecd's memory. Carry on to A4. */
	} else
		trace_step(report, "flush");

	/* Step 7. A4 metadata. The alias we chose is already in hosts. */
	before = safefile_read(paths->store, NULL);
	store = store_parse(before, &malformed, NULL);
	free(before);
	if (store == NULL) {
		set_detail(report, "out of memory reading devices.json");
		pairing_state_free(state);
		return (PAIR_ERROR);
	}
	if (malformed)
		set_detail(report, "devices.json was unreadable and has been "
		    "replaced; the pairing itself succeeded");

	/* Carry the alias across from hosts so both files agree. */
	{
		struct hosts_db	*hosts;
		char		*hosts_text;
		const char	*alias;

		hosts_text = safefile_read(paths->hosts, NULL);
		hosts = hosts_parse(hosts_text);
		free(hosts_text);

		alias_copy[0] = '\0';
		if (hosts != NULL) {
			alias = hosts_alias_for(hosts, state->addr);
			if (alias != NULL)
				(void)snprintf(alias_copy, sizeof(alias_copy),
				    "%s", alias);
			hosts_free(hosts);
		}
	}

	if (store_set(store, state->addr, name,
	    alias_copy[0] != '\0' ? alias_copy : NULL, type, now) ==
	    STORE_ERROR) {
		set_detail(report, "could not record the device");
		store_free(store);
		pairing_state_free(state);
		return (PAIR_ERROR);
	}

	text = store_emit(store, NULL);
	store_free(store);
	if (text == NULL) {
		pairing_state_free(state);
		return (PAIR_ERROR);
	}

	if (btmgr_paths_mkdirs(paths) != 0 ||
	    write_text(paths, paths->store, BTMGR_MODE_STORE, text,
	    report) != 0) {
		free(text);
		pairing_state_free(state);
		return (PAIR_ERROR);
	}
	free(text);
	trace_step(report, "store");

	pairing_state_free(state);

	return (PAIR_DONE);
}

enum pair_result
pairing_abort(const struct btmgr_paths *paths, const struct pair_ops *ops,
    struct pair_state *state, struct pair_report *report)
{
	int	 ok;

	if (report != NULL)
		memset(report, 0, sizeof(*report));

	if (!state->active) {
		set_detail(report, "no pairing is parked for this device");
		return (PAIR_ERROR);
	}

	trace_step(report, "abort");

	/* A6.4, and in this order so hcsecd.conf stops being honoured first. */
	ok = restore(paths, paths->hcsecd, BTMGR_MODE_HCSECD,
	    state->hcsecd_before) == 0 &&
	    restore(paths, paths->hosts, BTMGR_MODE_HOSTS,
	    state->hosts_before) == 0;

	if (ok) {
		if (report != NULL)
			report->rolled_back = 1;
		trace_step(report, "rollback");
		if (ops->reload != NULL)
			(void)ops->reload(ops->context);
	} else {
		trace_step(report, "rollback-failed");
		set_detail(report, "could not restore the config files");
	}

	pairing_state_free(state);

	return (ok ? PAIR_DONE : PAIR_ERROR);
}
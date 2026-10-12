/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * hosts.h - /etc/bluetooth/hosts ownership. SPEC.md A2, under the A0 rules.
 *
 * A parse-modify-emit model, no file I/O: hosts_parse() takes the file's text,
 * the callers mutate the model, hosts_emit() returns the whole file back. The
 * caller hands that to safefile_write(). A0.3 forbids in-place editing and
 * A0.4 requires that anything we did not author survives, so an untouched line
 * is re-emitted byte for byte, whitespace included.
 *
 * Three constraints come from reading bt_gethostent() at
 * lib/libbluetooth/bluetooth.c:99, not from the file's own comments:
 *
 *   1. A record with no trailing newline is skipped entirely, because the
 *      parser requires strpbrk(p, "#\n") to find something. hosts_emit()
 *      therefore always ends the file with '\n'.
 *   2. Name and alias matching is strcasecmp(), so A2.4 uniqueness is
 *      case-insensitive. "Speaker" and "speaker" collide.
 *   3. The line buffer is BUFSIZ, so a record must stay well inside it. Ours
 *      are at most 17 + 1 + 16 characters.
 *
 * Records we author carry a marker comment on the preceding line, the same
 * device A1.3.3 offers for hcsecd.conf. Its absence or a user having moved it
 * is tolerated: it is then simply not ours, and we leave it alone.
 */

#ifndef BTMGR_HOSTS_H_
#define	BTMGR_HOSTS_H_

#include <stddef.h>
#include <stdint.h>

/* Written on the line before a record we own. */
#define	HOSTS_MARKER		"# managed by bluetoothmgr"

struct hosts_db;

/* Outcome of a mutation. Negative is failure. */
enum hosts_result {
	HOSTS_ERROR	= -1,
	HOSTS_CHANGED	= 0,	/* the model now differs from the input */
	HOSTS_UNCHANGED	= 1,	/* already said what we wanted it to say */
	HOSTS_KEPT	= 2	/* a record we do not own; left untouched */
};

/*
 * Parse the file's text. A NULL text, as safefile_read() returns for a file
 * that does not exist, gives a valid empty model. Returns NULL with errno set
 * on allocation failure only: no input is malformed to this parser, since a
 * line it cannot read is a line it must preserve verbatim (A0.4).
 */
struct hosts_db	*hosts_parse(const char *text);
void		 hosts_free(struct hosts_db *db);

/*
 * Re-emit the whole file, NUL terminated, with the length in *lenp when lenp
 * is not NULL. Caller frees. Always ends in '\n' when non-empty.
 */
char		*hosts_emit(const struct hosts_db *db, size_t *lenp);

/* Non-zero if any mutation actually altered the model. */
int		 hosts_dirty(const struct hosts_db *db);

/*
 * The alias currently recorded for addr, or NULL. Points into the model and
 * dies with it. addr is a bdaddr_t's six bytes, b[0] first.
 */
const char	*hosts_alias_for(const struct hosts_db *db,
		     const uint8_t *addr);

/* Non-zero if we authored the record for addr. */
int		 hosts_is_managed(const struct hosts_db *db,
		     const uint8_t *addr);

/*
 * Choose an alias for name that no other record in db already uses, per A2.4.
 * Sanitises through btmgr_alias_from_name(), then appends 2, 3, 4 and so on
 * until it finds one free, comparing case-insensitively against every name and
 * alias in the file. The record for addr itself is not a collision, so asking
 * twice for the same device is stable.
 *
 * out needs BTMGR_ALIAS_BUFSZ. Returns 0, or -1 with errno set, EADDRNOTAVAIL
 * if every variant it is willing to try is taken.
 */
int		 hosts_alloc_alias(const struct hosts_db *db,
		     const char *name, const uint8_t *addr,
		     char *out, size_t outlen);

/*
 * Record alias for addr. alias must satisfy btmgr_alias_is_valid(), so pass
 * what hosts_alloc_alias() gave you.
 *
 * A record we already own is updated. A record we do not own is left alone and
 * HOSTS_KEPT is returned, because A0.4 makes the user's own entry theirs and
 * not ours to rewrite; force takes it over anyway and is for a rename the user
 * explicitly asked for. A new record is appended with its marker.
 */
enum hosts_result hosts_set(struct hosts_db *db, const uint8_t *addr,
		     const char *alias, int force);

/*
 * Drop the record for addr. Only a record we own is removed unless force is
 * set. Returns HOSTS_UNCHANGED when there was nothing there.
 */
enum hosts_result hosts_remove(struct hosts_db *db, const uint8_t *addr,
		     int force);

#endif /* !BTMGR_HOSTS_H_ */

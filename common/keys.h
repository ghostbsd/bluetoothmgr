/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * keys.h - /var/db/hcsecd.keys, read-mostly. SPEC.md A3.
 *
 * This file is hcsecd's, not ours. It rewrites the whole thing from memory on
 * SIGHUP and on clean shutdown, so anything we write races with that (A3.1).
 * The only mutation A3.2 permits is deleting a record, as the recovery for a
 * stale link key, and only while hcsecd is stopped. There is therefore no
 * setter here, by design.
 *
 * A3.3 says key material must never be logged or transmitted. This module
 * never decodes it: a record is kept as its original bytes and only the address
 * is parsed, so the 32 hex characters never reach a variable of ours. Deleting
 * one record and re-emitting the rest needs no more than that.
 *
 * Parse rules mirror read_keys_file() at
 * usr.sbin/bluetooth/hcsecd/parser.y:292, which are stricter than the format
 * line in SPEC.md suggests:
 *
 *   1. A '#' in column 0 is a comment. Anywhere else it is not.
 *   2. The separator is strpbrk(p, " "), a space specifically. A record
 *      separated by a tab is silently ignored by hcsecd.
 *   3. The address goes through bt_aton(), so one or two hex digits per field.
 *      This is the lenient dialect, unlike hcsecd.conf's own lexer.
 *   4. Leading whitespace makes the line unparseable, since the first space
 *      then splits before the address.
 *
 * A3.4: hcsecd loads a record only when an exactly matching bdaddr block exists
 * in hcsecd.conf. Records without one never take effect. keys_addrs() exists so
 * a caller holding an hcsecd_db can find them; the check is not done here,
 * which keeps this module independent of that one.
 */

#ifndef BTMGR_KEYS_H_
#define	BTMGR_KEYS_H_

#include <stddef.h>
#include <stdint.h>

#include "btaddr.h"

struct keys_db;

enum keys_result {
	KEYS_ERROR	= -1,
	KEYS_CHANGED	= 0,
	KEYS_UNCHANGED	= 1	/* no such record; nothing to do */
};

/*
 * Parse. NULL text, as safefile_read() gives for an absent file, yields a valid
 * empty model. hcsecd treats ENOENT as success too. Returns NULL with errno set
 * on allocation failure only.
 */
struct keys_db	*keys_parse(const char *text);
void		 keys_free(struct keys_db *db);

/* Re-emit in full. Caller frees. Ends in '\n' when non-empty. */
char		*keys_emit(const struct keys_db *db, size_t *lenp);

int		 keys_dirty(const struct keys_db *db);

/* Records hcsecd would actually load, so parseable ones only. */
size_t		 keys_count(const struct keys_db *db);

/* A3.3: presence is reportable, the value is not, and has no accessor. */
int		 keys_has(const struct keys_db *db, const uint8_t *addr);

/*
 * Copy up to max record addresses out, in file order. Returns how many records
 * exist, which may exceed max. For A3.4 pruning: check each against
 * hcsecd_has_block() and delete the ones with no block.
 */
size_t		 keys_addrs(const struct keys_db *db,
		     uint8_t (*out)[BTMGR_ADDR_LEN], size_t max);

/*
 * A3.2. Delete the record for addr. The caller MUST have stopped hcsecd, or
 * MUST stop it, call this, write, and start it again; hcsecd rewrites this file
 * from memory on SIGHUP and would otherwise put the record straight back.
 */
enum keys_result keys_remove(struct keys_db *db, const uint8_t *addr);

#endif /* !BTMGR_KEYS_H_ */

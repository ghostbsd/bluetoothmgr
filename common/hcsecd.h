/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * hcsecd.h - /etc/bluetooth/hcsecd.conf ownership. SPEC.md A1, under A0.
 *
 * The file that can stop the machine pairing anything. hcsecd parses it with a
 * yacc grammar and exit(1)s on a parse error, so a malformed write does not
 * degrade, it takes the security daemon out entirely. Same shape as hosts.h:
 * text in, model, text out, no file I/O, so all of A1 is testable unprivileged.
 *
 * Grammar facts taken from lexer.l and parser.y, not from the file's comments:
 *
 *   1. bdaddr wants exactly two hex digits per octet ({hexbyte} is
 *      {hexdigit}{hexdigit}). This is NOT bt_aton(): 1:2:3:4:5:6 is valid in
 *      /etc/bluetooth/hosts and a parse error here.
 *   2. The string token is \".+\", so an empty "" does not lex. A name or pin
 *      must have at least one character.
 *   3. \".+\" is greedy on one line, so two options sharing a line would be
 *      read as a single string. We emit one option per line (A1.3.2).
 *   4. options requires at least one option, so device { } is a parse error.
 *   5. Whitespace, newlines included, is insignificant; # runs to end of line.
 *
 * A block we cannot fully parse is kept verbatim and never becomes ours, which
 * is both A0.4 and self-preservation: if we do not understand it, rewriting it
 * is how we break it.
 */

#ifndef BTMGR_HCSECD_H_
#define	BTMGR_HCSECD_H_

#include <stddef.h>
#include <stdint.h>

/* Written on the line before a block we own. A1.3.3. */
#define	HCSECD_MARKER		"# managed by bluetoothmgr"

/* A1.2.1. get_key() falls back to this entry for any device without one. */
#define	HCSECD_DEFAULT_ADDR	{ 0, 0, 0, 0, 0, 0 }

struct hcsecd_db;

/*
 * What a block says about a device. A struct rather than two adjacent
 * const char * parameters: swapping those silently writes the PIN as the
 * device's display name, and nothing in the type system would object.
 */
struct hcsecd_entry {
	const char	*name;	/* sanitised here; empty becomes address-derived */
	const char	*pin;	/* NULL or empty emits nopin */
};

enum hcsecd_result {
	HCSECD_ERROR	= -1,
	HCSECD_CHANGED	= 0,
	HCSECD_UNCHANGED = 1,	/* already says what we wanted */
	HCSECD_KEPT	= 2,	/* not ours; left alone (A0.4) */
	HCSECD_REFUSED	= 3	/* the default entry (A1.2.1) */
};

/*
 * Parse. A NULL text, as safefile_read() gives for a file that is not there,
 * yields a valid empty model. Returns NULL with errno set on allocation
 * failure only: nothing in the input is fatal to this parser, because anything
 * it cannot read is something it must preserve.
 *
 * Parsing never mutates, so duplicate blocks survive it. See hcsecd_dedupe().
 */
struct hcsecd_db *hcsecd_parse(const char *text);
void		  hcsecd_free(struct hcsecd_db *db);

/* Re-emit in full. Caller frees. Ends in '\n' when non-empty. */
char		 *hcsecd_emit(const struct hcsecd_db *db, size_t *lenp);

int		  hcsecd_dirty(const struct hcsecd_db *db);

/* How many device blocks the model holds, parseable or not. */
size_t		  hcsecd_count(const struct hcsecd_db *db);

/* addr is a bdaddr_t's six bytes, b[0] first. */
int		  hcsecd_has_block(const struct hcsecd_db *db,
		      const uint8_t *addr);
int		  hcsecd_is_managed(const struct hcsecd_db *db,
		      const uint8_t *addr);

/*
 * A3.3: presence of a key is reportable, its value is not. There is
 * deliberately no accessor for the key material. The model keeps the token so
 * it can be re-emitted, and nothing here returns it.
 */
int		  hcsecd_has_key(const struct hcsecd_db *db,
		      const uint8_t *addr);

/* The name as it appears between the quotes, or NULL. Dies with the model. */
const char	 *hcsecd_name_for(const struct hcsecd_db *db,
		      const uint8_t *addr);

/*
 * A1.2.4. Ensure a block exists for addr, carrying name and pin.
 *
 * name and pin are sanitised here through btmgr_sanitise_quoted(), so a caller
 * cannot forget A7.1. A name that sanitises to nothing becomes an address
 * derived one, since fact 2 above forbids an empty string. A NULL or empty pin
 * emits nopin.
 *
 * An existing key is preserved across an update: hcsecd learns keys and we do
 * not get to discard them for a rename.
 *
 * Returns HCSECD_REFUSED for the default entry, HCSECD_KEPT for a block we did
 * not author unless force is set.
 */
enum hcsecd_result hcsecd_set(struct hcsecd_db *db, const uint8_t *addr,
		      const struct hcsecd_entry *e, int force);

/*
 * Drop the block for addr. Refuses the default entry always. Only removes a
 * block we authored unless force is set.
 */
enum hcsecd_result hcsecd_remove(struct hcsecd_db *db, const uint8_t *addr,
		      int force);

/*
 * A1.2.2. hcsecd keeps the first block for an address and discards the rest
 * with a LOG_ERR, so duplicates are not an error but are dead weight. Drops
 * every block after the first for each address, keeping the first, and returns
 * how many it dropped so the caller can report it. Never touches the default
 * entry's position.
 */
int		  hcsecd_dedupe(struct hcsecd_db *db);

#endif /* !BTMGR_HCSECD_H_ */

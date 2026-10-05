/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-keystest - verification for common/keys.c. SPEC.md A3.
 *
 * Needs no privilege and touches no file. The real /var/db/hcsecd.keys is mode
 * 0600, so the fixtures here are written to match dump_keys_file()'s output
 * format at usr.sbin/bluetooth/hcsecd/parser.y:354 rather than copied from it.
 *
 * Exits 0 when every check passes, 1 otherwise.
 */

#include <sys/cdefs.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btaddr.h"
#include "keys.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"

static int	 failures;
static int	 checks;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 eq(const char *got, const char *want, const char *what);

static const uint8_t	 a1[6] = { 0x01, 0x22, 0x11, 0xcc, 0xbb, 0x0a };
static const uint8_t	 a2[6] = { 0x02, 0x22, 0x11, 0xcc, 0xbb, 0xaa };
static const uint8_t	 absent[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };

/* Exactly what dump_keys_file() writes: address, one space, 32 hex, newline. */
static const char	 two[] =
"0a:bb:cc:11:22:01 000102030405060708090a0b0c0d0e0f\n"
"aa:bb:cc:11:22:02 ffeeddccbbaa99887766554433221100\n";

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
eq(const char *got, const char *want, const char *what)
{
	int	 same;

	if (got == NULL) {
		ok(0, "%s (got NULL)", what);
		return;
	}
	same = strcmp(got, want) == 0;
	ok(same, "%s%s", what, same ? "" : " (differs)");
}

static void
test_parse(void)
{
	struct keys_db	*db;
	char		*out;

	printf("\nparsing, mirroring read_keys_file()\n");

	db = keys_parse(two);
	ok(keys_count(db) == 2, "two records are found");
	ok(keys_has(db, a1), "the first address is present");
	ok(keys_has(db, a2), "the second address is present");
	ok(!keys_has(db, absent), "an absent address is not");
	ok(!keys_dirty(db), "parsing alone does not dirty the model");
	out = keys_emit(db, NULL);
	eq(out, two, "and the file round trips byte for byte");
	free(out);
	keys_free(db);

	db = keys_parse(NULL);
	ok(keys_count(db) == 0, "an absent file parses as empty, as hcsecd treats it");
	out = keys_emit(db, NULL);
	eq(out, "", "and emits nothing");
	free(out);
	keys_free(db);

	/* Rule 1: '#' only in column 0. */
	db = keys_parse("# a comment\n0a:bb:cc:11:22:01 00\n");
	ok(keys_count(db) == 1, "a leading # is a comment, not a record");
	ok(keys_has(db, a1), "and the record after it still counts");
	keys_free(db);

	/* Rule 2: the separator is a space. A tab is not. */
	db = keys_parse("0a:bb:cc:11:22:01\t000102030405060708090a0b0c0d0e0f\n");
	ok(keys_count(db) == 0,
	    "a tab separated line is not a record, as hcsecd ignores it");
	keys_free(db);

	/* Rule 3: bt_aton() is lenient, so short fields are valid here. */
	db = keys_parse("a:bb:cc:11:22:01 00\n");
	ok(keys_has(db, a1),
	    "a short-form address parses, unlike in hcsecd.conf");
	keys_free(db);

	/* Rule 4: leading whitespace splits before the address. */
	db = keys_parse(" 0a:bb:cc:11:22:01 00\n");
	ok(keys_count(db) == 0, "a leading space makes the line unparseable");
	keys_free(db);

	db = keys_parse("0a:bb:cc:11:22:01\n");
	ok(keys_count(db) == 0, "an address with no key is not a record");
	keys_free(db);

	db = keys_parse("not an address at all here\n");
	ok(keys_count(db) == 0, "nor is a line that is not an address");
	keys_free(db);

	/* A0.4 still applies: what we do not understand, we keep. */
	db = keys_parse("# comment\nrubbish line\n0a:bb:cc:11:22:01 00\n");
	out = keys_emit(db, NULL);
	eq(out, "# comment\nrubbish line\n0a:bb:cc:11:22:01 00\n",
	    "unparseable lines are preserved, never dropped");
	free(out);
	keys_free(db);

	db = keys_parse("0a:bb:cc:11:22:01 00");
	out = keys_emit(db, NULL);
	eq(out, "0a:bb:cc:11:22:01 00\n",
	    "a missing final newline is added");
	free(out);
	keys_free(db);
}

/* A3.2. The only mutation there is. */
static void
test_remove(void)
{
	struct keys_db	*db;
	char		*out;

	printf("\nA3.2 deletion, the only permitted mutation\n");

	db = keys_parse(two);
	ok(keys_remove(db, absent) == KEYS_UNCHANGED,
	    "removing an absent address changes nothing");
	ok(!keys_dirty(db), "and leaves the model clean");
	out = keys_emit(db, NULL);
	eq(out, two, "so the file is unchanged");
	free(out);

	ok(keys_remove(db, a1) == KEYS_CHANGED, "removing a present address works");
	ok(keys_dirty(db), "and dirties the model");
	ok(!keys_has(db, a1), "the record is gone");
	ok(keys_has(db, a2), "while the other one stays");
	ok(keys_count(db) == 1, "leaving one record");
	out = keys_emit(db, NULL);
	eq(out, "aa:bb:cc:11:22:02 ffeeddccbbaa99887766554433221100\n",
	    "and the survivor keeps its own bytes exactly");
	free(out);
	keys_free(db);

	/* Removing the last record must not leave a stray blank line. */
	db = keys_parse("0a:bb:cc:11:22:01 00\n");
	keys_remove(db, a1);
	out = keys_emit(db, NULL);
	eq(out, "", "removing the only record empties the file");
	free(out);
	keys_free(db);

	/*
	 * A duplicate left behind would become the live key the moment the
	 * first was deleted, since get_key() uses the first match.
	 */
	db = keys_parse("0a:bb:cc:11:22:01 aa\n0a:bb:cc:11:22:01 bb\n");
	ok(keys_count(db) == 2, "duplicates both parse");
	ok(keys_remove(db, a1) == KEYS_CHANGED, "removing the address succeeds");
	ok(keys_count(db) == 0, "and takes every matching record, not just the first");
	keys_free(db);

	/* Comments around a removed record survive it. */
	db = keys_parse("# keep me\n0a:bb:cc:11:22:01 00\n# and me\n");
	keys_remove(db, a1);
	out = keys_emit(db, NULL);
	eq(out, "# keep me\n# and me\n", "comments either side of it survive");
	free(out);
	keys_free(db);
}

/* A3.4. Records with no matching block in hcsecd.conf never take effect. */
static void
test_addrs(void)
{
	struct keys_db	*db;
	uint8_t		 got[4][BTMGR_ADDR_LEN];
	char		 s[BTMGR_ADDR_BUFSZ];

	printf("\nA3.4 finding orphans\n");

	db = keys_parse(two);
	ok(keys_addrs(db, got, 4) == 2, "both addresses are listed");

	btmgr_addr_format(got[0], s, sizeof(s));
	eq(s, "0a:bb:cc:11:22:01", "the first in file order");
	btmgr_addr_format(got[1], s, sizeof(s));
	eq(s, "aa:bb:cc:11:22:02", "then the second");

	ok(keys_addrs(db, NULL, 0) == 2,
	    "a NULL buffer still reports how many there are");
	ok(keys_addrs(db, got, 1) == 2,
	    "and a short buffer reports the true count, not the copied one");
	keys_free(db);
}

int
main(void)
{

	test_parse();
	test_remove();
	test_addrs();

	printf("\n%d checks, %d failures\n", checks, failures);

	if (btmgr_mc_report() != 0) {
		printf("memcheck: allocations still live\n");
		failures++;
	}

	return (failures == 0 ? 0 : 1);
}

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-hoststest - verification for common/hosts.c. SPEC.md A2 and A0.3/A0.4.
 *
 * Needs no privilege and touches no file: hosts.c is a text-in, text-out model
 * and the whole of A2 can be checked on strings. Exits 0 when every check
 * passes, 1 otherwise.
 */

#include <sys/cdefs.h>

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hosts.h"
#include "sanitise.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"

static int	 failures;
static int	 checks;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 eq(const char *got, const char *want, const char *what);
static char	*roundtrip(const char *text);

/* Documentation addresses, in bdaddr_t storage order. */
static const uint8_t	 speaker_addr[6] = { 0x02, 0x22, 0x11, 0xcc, 0xbb, 0xaa };
static const uint8_t	 phones[6] = { 0x01, 0x22, 0x11, 0xcc, 0xbb, 0x0a };
static const uint8_t	 fresh[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };

/* The file as shipped by the base system, plus the two records Eric added. */
static const char	 real_file[] =
"# $Id: hosts,v 1.1 2003/05/21 17:48:40 max Exp $\n"
"#\n"
"# Bluetooth Host Database\n"
"#\n"
"# This file should contain the Bluetooth addresses and aliases for hosts.\n"
"#\n"
"# BD_ADDR               Name [ alias0 alias1 ... ]\n"
"\n"
"# 00:11:22:33:44:55\tphone\n"
"0a:bb:cc:11:22:01    headphones\n"
"aa:bb:cc:11:22:02\tspeaker_addr\n";

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
	ok(same, "%s%s%s%s", what, same ? "" : " (got \"",
	    same ? "" : got, same ? "" : "\")");
}

/* Parse and emit with no mutation. Caller frees. */
static char *
roundtrip(const char *text)
{
	struct hosts_db	*db;
	char		*out;

	db = hosts_parse(text);
	if (db == NULL)
		return (NULL);
	out = hosts_emit(db, NULL);
	hosts_free(db);

	return (out);
}

/*
 * A0.3 and A0.4. The round trip is the foundation everything else rests on: if
 * emitting an unmodified file is not byte-exact then every write corrupts
 * something, and A0.5 can never report "unchanged".
 */
static void
test_roundtrip(void)
{
	char	*out;

	printf("\nA0.3, A0.4 round trip\n");

	out = roundtrip(real_file);
	eq(out, real_file, "the real /etc/bluetooth/hosts survives byte for byte");
	free(out);

	out = roundtrip("");
	eq(out, "", "an empty file stays empty");
	free(out);

	out = roundtrip(NULL);
	eq(out, "", "a file that does not exist parses as empty");
	free(out);

	out = roundtrip("\n\n\n");
	eq(out, "\n\n\n", "blank lines are preserved, not collapsed");
	free(out);

	out = roundtrip("  # indented comment\n\t\n");
	eq(out, "  # indented comment\n\t\n",
	    "leading whitespace and a lone tab are preserved");
	free(out);

	out = roundtrip("0a:bb:cc:11:22:01    headphones   phones2   p3\n");
	eq(out, "0a:bb:cc:11:22:01    headphones   phones2   p3\n",
	    "a record's extra aliases and its spacing are preserved");
	free(out);

	out = roundtrip("aa:bb:cc:11:22:02\tspeaker_addr\t# my speaker\n");
	eq(out, "aa:bb:cc:11:22:02\tspeaker_addr\t# my speaker\n",
	    "a trailing comment on a record is preserved");
	free(out);

	/*
	 * And it must stay OPAQUE, not merely round trip. A modelled record
	 * would be re-emitted canonically once authored, dropping the comment,
	 * which A0.4 forbids. The round trip above passes either way, so this
	 * is the check that actually pins the rule.
	 */
	{
		struct hosts_db	*cdb;

		cdb = hosts_parse("aa:bb:cc:11:22:02\tspeaker_addr\t# my speaker\n");
		ok(hosts_alias_for(cdb, speaker_addr) == NULL,
		    "and is not modelled, so it can never be rewritten");
		hosts_free(cdb);
	}

	out = roundtrip("garbage that is not a record at all\n");
	eq(out, "garbage that is not a record at all\n",
	    "an unparseable line is preserved, never dropped");
	free(out);

	/*
	 * bt_gethostent() needs strpbrk(p, "#\n") to succeed, so a final record
	 * with no newline is invisible to libbluetooth. Emitting one back is a
	 * deliberate repair, the only case where the round trip is not exact.
	 */
	out = roundtrip("aa:bb:cc:11:22:02\tspeaker_addr");
	eq(out, "aa:bb:cc:11:22:02\tspeaker_addr\n",
	    "a missing final newline is added, since libbluetooth needs it");
	free(out);
}

static void
test_lookup(void)
{
	struct hosts_db	*db;

	printf("\nlookup\n");

	db = hosts_parse(real_file);
	if (db == NULL) {
		ok(0, "hosts_parse failed");
		return;
	}

	eq(hosts_alias_for(db, phones), "headphones",
	    "a record separated by spaces is found");
	eq(hosts_alias_for(db, speaker_addr), "speaker_addr",
	    "a record separated by a tab is found");
	ok(hosts_alias_for(db, fresh) == NULL, "an absent address is not found");

	/* The commented-out example must not become a live record. */
	{
		static const uint8_t example[6] =
		    { 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };

		ok(hosts_alias_for(db, example) == NULL,
		    "the commented-out example record is not live");
	}

	ok(!hosts_is_managed(db, phones), "a hand-written record is not ours");
	ok(!hosts_dirty(db), "parsing alone does not dirty the model");

	hosts_free(db);
}

static void
test_alloc_alias(void)
{
	struct hosts_db	*db;
	char		 a[BTMGR_ALIAS_BUFSZ];

	printf("\nA2.4 alias allocation\n");

	db = hosts_parse(real_file);
	if (db == NULL) {
		ok(0, "hosts_parse failed");
		return;
	}

	ok(hosts_alloc_alias(db, "Soundbar X900", fresh, a, sizeof(a)) == 0,
	    "a free name is allocated");
	eq(a, "Soundbar_X900", "and comes back sanitised but unsuffixed");

	/* "headphones" is taken by the hand-written record. */
	ok(hosts_alloc_alias(db, "headphones", fresh, a, sizeof(a)) == 0,
	    "a taken name is allocated");
	eq(a, "headphones2", "and gets the first free numeric suffix");

	/* bt_gethostbyname() uses strcasecmp(), so case cannot disambiguate. */
	ok(hosts_alloc_alias(db, "HeadPhones", fresh, a, sizeof(a)) == 0,
	    "a name taken in another case is allocated");
	eq(a, "HeadPhones2", "and still gets a suffix, since matching is casefold");

	/* Asking for the device's own current alias must be stable. */
	ok(hosts_alloc_alias(db, "headphones", phones, a, sizeof(a)) == 0,
	    "a device may keep the alias it already has");
	eq(a, "headphones", "so no suffix is added for its own record");

	hosts_free(db);

	/* A collision against a further alias, not just against a Name. */
	db = hosts_parse("0a:bb:cc:11:22:01 phones taken1 taken2\n");
	if (db == NULL) {
		ok(0, "hosts_parse failed");
		return;
	}
	ok(hosts_alloc_alias(db, "taken2", fresh, a, sizeof(a)) == 0,
	    "a name colliding with a further alias is allocated");
	eq(a, "taken22", "and is suffixed too, since aliases also resolve");
	hosts_free(db);
}

static void
test_set(void)
{
	struct hosts_db	*db;
	char		*out;

	printf("\nhosts_set\n");

	/* A2.6 and A0.4: a record the user wrote is not ours to rewrite. */
	db = hosts_parse(real_file);
	ok(hosts_set(db, speaker_addr, "Soundbar_X900", 0) == HOSTS_KEPT,
	    "a hand-written record is kept, not overwritten");
	ok(!hosts_dirty(db), "and the model stays clean");
	out = hosts_emit(db, NULL);
	eq(out, real_file, "so the file is unchanged");
	free(out);
	hosts_free(db);

	/* force is the user asking for it explicitly. */
	db = hosts_parse(real_file);
	ok(hosts_set(db, speaker_addr, "Soundbar_X900", 1) == HOSTS_CHANGED,
	    "force takes over a hand-written record");
	out = hosts_emit(db, NULL);
	ok(strstr(out, "aa:bb:cc:11:22:02\tSoundbar_X900\n") != NULL,
	    "and re-emits it canonically, tab separated");
	ok(strstr(out, "speaker_addr\n") == NULL, "with the old alias gone");
	ok(strstr(out, "# Bluetooth Host Database") != NULL,
	    "while every comment is still there");
	ok(strstr(out, "0a:bb:cc:11:22:01    headphones\n") != NULL,
	    "and the other record keeps its own spacing");
	free(out);
	hosts_free(db);

	/* A new device appends a marker and a record. */
	db = hosts_parse(real_file);
	ok(hosts_set(db, fresh, "new_speaker", 0) == HOSTS_CHANGED,
	    "a new address is appended");
	out = hosts_emit(db, NULL);
	ok(strstr(out, HOSTS_MARKER "\n06:05:04:03:02:01\tnew_speaker\n")
	    != NULL, "with the marker on the line before it");
	ok(strncmp(out, real_file, strlen(real_file)) == 0,
	    "and everything that was there is untouched ahead of it");
	free(out);
	hosts_free(db);

	/* A record of ours is updated in place, and is ours on re-parse. */
	db = hosts_parse(real_file);
	hosts_set(db, fresh, "first_name", 0);
	out = hosts_emit(db, NULL);
	hosts_free(db);

	db = hosts_parse(out);
	free(out);
	ok(hosts_is_managed(db, fresh),
	    "the marker survives a round trip, so the record is still ours");
	ok(hosts_set(db, fresh, "first_name", 0) == HOSTS_UNCHANGED,
	    "setting the same alias again reports unchanged (A0.5)");
	ok(hosts_set(db, fresh, "second_name", 0) == HOSTS_CHANGED,
	    "setting a different alias updates it");
	out = hosts_emit(db, NULL);
	ok(strstr(out, "06:05:04:03:02:01\tsecond_name\n") != NULL,
	    "and the new alias is emitted");
	ok(strstr(out, "first_name") == NULL, "with no duplicate left behind");
	free(out);
	hosts_free(db);

	/* An invalid alias is a caller error, not something to write out. */
	db = hosts_parse(real_file);
	errno = 0;
	ok(hosts_set(db, fresh, "has space", 0) == HOSTS_ERROR &&
	    errno == EINVAL, "an alias outside the charset is refused");
	ok(hosts_set(db, fresh, "", 0) == HOSTS_ERROR, "an empty alias is refused");
	ok(hosts_set(db, fresh, "1:2:3:4:5:6", 0) == HOSTS_ERROR,
	    "an address-like alias is refused (A2.5)");
	ok(!hosts_dirty(db), "and none of those dirtied the model");
	hosts_free(db);
}

static void
test_remove(void)
{
	struct hosts_db	*db;
	char		*out;

	printf("\nhosts_remove\n");

	db = hosts_parse(real_file);
	ok(hosts_remove(db, phones, 0) == HOSTS_KEPT,
	    "a hand-written record is not ours to remove");
	ok(hosts_remove(db, fresh, 0) == HOSTS_UNCHANGED,
	    "removing an absent address changes nothing");
	out = hosts_emit(db, NULL);
	eq(out, real_file, "so the file is unchanged");
	free(out);

	ok(hosts_remove(db, phones, 1) == HOSTS_CHANGED,
	    "force removes it anyway");
	out = hosts_emit(db, NULL);
	ok(strstr(out, "headphones") == NULL, "and the record is gone");
	ok(strstr(out, "aa:bb:cc:11:22:02\tspeaker_addr\n") != NULL,
	    "while the neighbouring record stays");
	ok(strstr(out, "# BD_ADDR") != NULL, "and the comments stay");
	free(out);
	hosts_free(db);

	/* Our own record goes without force, and takes its marker with it. */
	db = hosts_parse(real_file);
	hosts_set(db, fresh, "doomed", 0);
	out = hosts_emit(db, NULL);
	hosts_free(db);

	db = hosts_parse(out);
	free(out);
	ok(hosts_remove(db, fresh, 0) == HOSTS_CHANGED,
	    "a record we authored is removed without force");
	out = hosts_emit(db, NULL);
	eq(out, real_file, "and the file returns to exactly what it was");
	free(out);
	hosts_free(db);
}

/*
 * The marker only counts on the line immediately before a record. A0.4 says a
 * user may have moved things; the safe reading of a displaced marker is that
 * the record is not ours.
 */
static void
test_marker_discipline(void)
{
	struct hosts_db	*db;

	printf("\nmarker discipline\n");

	db = hosts_parse(HOSTS_MARKER "\naa:bb:cc:11:22:02\tspeaker_addr\n");
	ok(hosts_is_managed(db, speaker_addr), "a marker on the preceding line claims it");
	hosts_free(db);

	db = hosts_parse(HOSTS_MARKER "\n\naa:bb:cc:11:22:02\tspeaker_addr\n");
	ok(!hosts_is_managed(db, speaker_addr),
	    "a blank line between them means it is not ours");
	hosts_free(db);

	db = hosts_parse("aa:bb:cc:11:22:02\tspeaker_addr\n" HOSTS_MARKER "\n");
	ok(!hosts_is_managed(db, speaker_addr),
	    "a marker after the record does not claim it");
	hosts_free(db);

	db = hosts_parse("  \t" HOSTS_MARKER "\naa:bb:cc:11:22:02\tspeaker_addr\n");
	ok(hosts_is_managed(db, speaker_addr), "an indented marker still claims it");
	hosts_free(db);

	db = hosts_parse("# managed by something else\n"
	    "aa:bb:cc:11:22:02\tspeaker_addr\n");
	ok(!hosts_is_managed(db, speaker_addr), "another comment does not claim it");
	hosts_free(db);
}

static void
test_parse_edges(void)
{
	struct hosts_db	*db;
	char		*out;

	printf("\naddress parsing\n");

	/* bt_aton() accepts short fields, so the file may contain them. */
	db = hosts_parse("1:2:3:4:5:6\tshortform\n");
	{
		static const uint8_t shortaddr[6] =
		    { 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };

		eq(hosts_alias_for(db, shortaddr), "shortform",
		    "a short-form address parses as bt_aton would");
	}
	hosts_free(db);

	/* Things that are not addresses must stay opaque, not become records. */
	out = roundtrip("00:11:22:33:44\tfivefields\n");
	eq(out, "00:11:22:33:44\tfivefields\n",
	    "five fields is not an address, so the line stays opaque");
	free(out);

	out = roundtrip("000:11:22:33:44:55\tthreedigits\n");
	eq(out, "000:11:22:33:44:55\tthreedigits\n",
	    "a three digit field is not an address either");
	free(out);

	out = roundtrip("aa:bb:cc:11:22:02\n");
	eq(out, "aa:bb:cc:11:22:02\n",
	    "an address with no name is not a record");
	free(out);

	out = roundtrip("aa:bb:cc:11:22:0g\tbadhex\n");
	eq(out, "aa:bb:cc:11:22:0g\tbadhex\n", "a non-hex digit is not an address");
	free(out);
}

int
main(void)
{

	test_roundtrip();
	test_lookup();
	test_alloc_alias();
	test_set();
	test_remove();
	test_marker_discipline();
	test_parse_edges();

	printf("\n%d checks, %d failures\n", checks, failures);

	if (btmgr_mc_report() != 0) {
		printf("memcheck: allocations still live\n");
		failures++;
	}

	return (failures == 0 ? 0 : 1);
}

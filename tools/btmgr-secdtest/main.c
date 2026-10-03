/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-secdtest - verification for common/hcsecd.c. SPEC.md A1, A0.3, A0.4.
 *
 * Needs no privilege and touches no file. Unlike the hosts fixture, the
 * fixture here is the base system template from
 * /usr/src/usr.sbin/bluetooth/hcsecd/hcsecd.conf rather than this machine's
 * own file, because that one is mode 0600 and unreadable without root.
 *
 * Exits 0 when every check passes, 1 otherwise.
 */

#include <sys/cdefs.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hcsecd.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"

static int	 failures;
static int	 checks;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 eq(const char *got, const char *want, const char *what);
static char	*roundtrip(const char *text);
static int	 has(const char *hay, const char *needle);

static const uint8_t	 defaddr[6] = { 0, 0, 0, 0, 0, 0 };
static const uint8_t	 dummy1[6] = { 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
static const uint8_t	 dummy2[6] = { 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
static const uint8_t	 speaker_addr[6] = { 0x02, 0x22, 0x11, 0xcc, 0xbb, 0xaa };

/* The base system template, verbatim. */
static const char	 tmpl[] =
"# $Id: hcsecd.conf,v 1.1 2003/05/26 22:50:47 max Exp $\n"
"#\n"
"# HCI security daemon configuration file\n"
"#\n"
"\n"
"# Default entry is applied if no better match found\n"
"# It MUST have 00:00:00:00:00:00 as bdaddr\n"
"device {\n"
"\tbdaddr\t00:00:00:00:00:00;\n"
"\tname\t\"Default entry\";\n"
"\tkey\tnokey;\n"
"\tpin\tnopin;\n"
"}\n"
"\n"
"device {\n"
"\tbdaddr\t00:01:02:03:04:05;\n"
"\tname\t\"Dummy\";\n"
"\tkey\tnokey;\n"
"\tpin\t\"0000\";\n"
"}\n"
"\n"
"device {\n"
"\tbdaddr\t00:11:22:33:44:55;\n"
"\tname\t\"Dummy\";\n"
"\tkey\t0x00112233445566778899aabbccddeeff; # 16 bytes key (hex string)\n"
"\tpin\tnopin;\n"
"}\n";

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

static int
has(const char *hay, const char *needle)
{

	return (hay != NULL && strstr(hay, needle) != NULL);
}

static char *
roundtrip(const char *text)
{
	struct hcsecd_db	*db;
	char			*out;

	db = hcsecd_parse(text);
	if (db == NULL)
		return (NULL);
	out = hcsecd_emit(db, NULL);
	hcsecd_free(db);

	return (out);
}

static void
test_roundtrip(void)
{
	char	*out;

	printf("\nA0.3, A0.4, A1.3.1 round trip\n");

	out = roundtrip(tmpl);
	eq(out, tmpl, "the base system template survives byte for byte");
	free(out);

	out = roundtrip("");
	eq(out, "", "an empty file stays empty");
	free(out);

	out = roundtrip(NULL);
	eq(out, "", "a file that does not exist parses as empty");
	free(out);

	out = roundtrip("# just a comment, no blocks\n");
	eq(out, "# just a comment, no blocks\n", "a file of only comments survives");
	free(out);

	/* A1.3.1: original whitespace and trailing comments, exactly. */
	out = roundtrip("device{bdaddr 00:11:22:33:44:55;pin nopin;}\n");
	eq(out, "device{bdaddr 00:11:22:33:44:55;pin nopin;}\n",
	    "a block crammed onto one line is not reformatted");
	free(out);

	out = roundtrip("device {\n  bdaddr   00:11:22:33:44:55 ;  # why\n"
	    "  pin  nopin ;\n}   # tail\n");
	eq(out, "device {\n  bdaddr   00:11:22:33:44:55 ;  # why\n"
	    "  pin  nopin ;\n}   # tail\n",
	    "odd spacing and comments inside a block are preserved");
	free(out);

	out = roundtrip("device {\n\tbdaddr\t00:11:22:33:44:55;\n\tpin\tnopin;\n}");
	eq(out, "device {\n\tbdaddr\t00:11:22:33:44:55;\n\tpin\tnopin;\n}",
	    "a file with no trailing newline is not gratuitously changed");
	free(out);
}

static void
test_parse(void)
{
	struct hcsecd_db	*db;

	printf("\nparsing\n");

	db = hcsecd_parse(tmpl);
	ok(hcsecd_count(db) == 3, "the template holds three blocks");
	ok(hcsecd_has_block(db, defaddr), "the default entry is found");
	ok(hcsecd_has_block(db, dummy1), "the first Dummy is found");
	ok(hcsecd_has_block(db, dummy2), "the second Dummy is found");
	ok(!hcsecd_has_block(db, speaker_addr), "an absent address is not found");
	eq(hcsecd_name_for(db, defaddr), "Default entry",
	    "the default entry's name is read");

	/* A3.3: presence is reportable, the value is not, and has no accessor. */
	ok(!hcsecd_has_key(db, dummy1), "nokey reads as no key");
	ok(hcsecd_has_key(db, dummy2), "a hex key reads as having a key");

	ok(!hcsecd_is_managed(db, dummy1), "a template block is not ours");
	ok(!hcsecd_dirty(db), "parsing alone does not dirty the model");
	hcsecd_free(db);

	/* Grammar fact 1: bdaddr needs exactly two hex digits per octet. */
	db = hcsecd_parse("device {\n\tbdaddr\t0:1:2:3:4:5;\n\tpin\tnopin;\n}\n");
	ok(hcsecd_count(db) == 1, "a short-form address still makes a block");
	{
		static const uint8_t shortaddr[6] =
		    { 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

		ok(!hcsecd_has_block(db, shortaddr),
		    "but it is unparsed, since hcsecd would reject it too");
	}
	hcsecd_free(db);

	/* An option hcsecd has never heard of leaves the block untouchable. */
	db = hcsecd_parse("device {\n\tbdaddr\t00:11:22:33:44:55;\n"
	    "\tfrobnicate\t1;\n}\n");
	ok(!hcsecd_has_block(db, dummy2),
	    "an unknown option leaves the block unparsed");
	hcsecd_free(db);

	/* Grammar fact 4: device { } does not lex. */
	db = hcsecd_parse("device {\n}\n");
	ok(hcsecd_count(db) == 1 && !hcsecd_has_block(db, defaddr),
	    "an empty block is kept but never modelled");
	hcsecd_free(db);

	/* A brace inside a string or a comment must not end the block early. */
	db = hcsecd_parse("device {\n\tbdaddr\t00:11:22:33:44:55;\n"
	    "\tname\t\"a } brace\";\n\tpin\tnopin;\n}\n");
	eq(hcsecd_name_for(db, dummy2), "a } brace",
	    "a brace inside a quoted name does not end the block");
	hcsecd_free(db);

	db = hcsecd_parse("device {\n\tbdaddr\t00:11:22:33:44:55;\t# } here\n"
	    "\tpin\tnopin;\n}\n");
	ok(hcsecd_has_block(db, dummy2),
	    "a brace inside a comment does not end the block");
	hcsecd_free(db);
}

static void
test_set(void)
{
	struct hcsecd_db	*db;
	char			*out;

	printf("\nhcsecd_set\n");

	/* A1.2.1: the default entry is not ours, at all, ever. */
	db = hcsecd_parse(tmpl);
	ok(hcsecd_set(db, defaddr,
	    &(struct hcsecd_entry){ .name = "Mine", .pin = "1234" }, 0) == HCSECD_REFUSED,
	    "the default entry is refused");
	ok(hcsecd_set(db, defaddr,
	    &(struct hcsecd_entry){ .name = "Mine", .pin = "1234" }, 1) == HCSECD_REFUSED,
	    "and force does not override that");
	ok(!hcsecd_dirty(db), "so the model stays clean");
	hcsecd_free(db);

	/* A1.2.3 and A0.4: the Dummy examples are base system boilerplate. */
	db = hcsecd_parse(tmpl);
	ok(hcsecd_set(db, dummy1,
	    &(struct hcsecd_entry){ .name = "Renamed", .pin = NULL }, 0) == HCSECD_KEPT,
	    "a block we did not author is kept");
	out = hcsecd_emit(db, NULL);
	eq(out, tmpl, "and the file is unchanged");
	free(out);
	hcsecd_free(db);

	/* A1.2.4: a new device gets a block, canonically, with its marker. */
	db = hcsecd_parse(tmpl);
	ok(hcsecd_set(db, speaker_addr,
	    &(struct hcsecd_entry){ .name = "Soundbar X900", .pin = "0000" }, 0) == HCSECD_CHANGED,
	    "a new device is appended");
	out = hcsecd_emit(db, NULL);
	ok(has(out, HCSECD_MARKER "\ndevice {\n"
	    "\tbdaddr\taa:bb:cc:11:22:02;\n"
	    "\tname\t\"Soundbar X900\";\n"
	    "\tkey\tnokey;\n"
	    "\tpin\t\"0000\";\n"
	    "}\n"), "in canonical form, one option per line, after its marker");
	ok(strncmp(out, tmpl, strlen(tmpl)) == 0,
	    "with the whole template untouched ahead of it");
	free(out);
	hcsecd_free(db);

	/* A7.1 cannot be forgotten, because it happens in here. */
	db = hcsecd_parse(tmpl);
	hcsecd_set(db, speaker_addr, &(struct hcsecd_entry){
	    .name = "evil\";\n};\ndevice {\n\tbdaddr 00:00:00:00:00:00",
	    .pin = NULL }, 0);
	out = hcsecd_emit(db, NULL);
	ok(!has(out, "evil\";"), "a name forging a block cannot escape its token");
	ok(has(out, "\tname\t\"evil_;_};_device {__bdaddr 00:00:00:00:00:00\";\n"),
	    "it is sanitised into one harmless string");
	free(out);
	hcsecd_free(db);

	/* Grammar fact 2: "" does not lex, so an empty name needs a fallback. */
	db = hcsecd_parse(tmpl);
	hcsecd_set(db, speaker_addr, &(struct hcsecd_entry){ .name = "", .pin = NULL }, 0);
	out = hcsecd_emit(db, NULL);
	ok(has(out, "\tname\t\"bt-112202\";\n"),
	    "an empty name becomes an address-derived one, never \"\"");
	free(out);
	hcsecd_free(db);

	db = hcsecd_parse(tmpl);
	hcsecd_set(db, speaker_addr,
	    &(struct hcsecd_entry){ .name = NULL, .pin = NULL }, 0);
	out = hcsecd_emit(db, NULL);
	ok(has(out, "\tname\t\"bt-112202\";\n"), "and so does a NULL name");
	ok(has(out, "\tpin\tnopin;\n"), "a NULL pin emits nopin, unquoted");
	free(out);
	hcsecd_free(db);

	db = hcsecd_parse(tmpl);
	hcsecd_set(db, speaker_addr,
	    &(struct hcsecd_entry){ .name = "Speaker", .pin = "" }, 0);
	out = hcsecd_emit(db, NULL);
	ok(has(out, "\tpin\tnopin;\n"), "an empty pin also emits nopin");
	free(out);
	hcsecd_free(db);

	/* A0.5: the same call twice must not dirty anything the second time. */
	db = hcsecd_parse(tmpl);
	hcsecd_set(db, speaker_addr,
	    &(struct hcsecd_entry){ .name = "Speaker", .pin = "0000" }, 0);
	out = hcsecd_emit(db, NULL);
	hcsecd_free(db);

	db = hcsecd_parse(out);
	free(out);
	ok(hcsecd_is_managed(db, speaker_addr),
	    "the marker survives a round trip, so the block is still ours");
	ok(hcsecd_set(db, speaker_addr,
	    &(struct hcsecd_entry){ .name = "Speaker", .pin = "0000" }, 0) == HCSECD_UNCHANGED,
	    "setting the same values again reports unchanged");
	ok(!hcsecd_dirty(db), "and does not dirty the model");
	ok(hcsecd_set(db, speaker_addr,
	    &(struct hcsecd_entry){ .name = "Speaker2", .pin = "0000" }, 0) == HCSECD_CHANGED,
	    "a different name updates it");
	out = hcsecd_emit(db, NULL);
	ok(has(out, "\tname\t\"Speaker2\";\n"), "and the new name is emitted");
	ok(!has(out, "\"Speaker\";"), "with no stale copy left");
	free(out);
	hcsecd_free(db);

	/* force takes over someone else's block. */
	db = hcsecd_parse(tmpl);
	ok(hcsecd_set(db, dummy1,
	    &(struct hcsecd_entry){ .name = "Taken", .pin = NULL }, 1) == HCSECD_CHANGED,
	    "force takes over a block we did not author");
	out = hcsecd_emit(db, NULL);
	ok(has(out, "\tname\t\"Taken\";\n"), "and rewrites it canonically");
	ok(has(out, "\"Default entry\""), "while the default entry is untouched");
	ok(has(out, "0x00112233445566778899aabbccddeeff"),
	    "and the other block keeps its key verbatim");
	free(out);
	hcsecd_free(db);
}

/* A learned key is hcsecd's. Renaming a device must not discard it. */
static void
test_key_preserved(void)
{
	struct hcsecd_db	*db;
	char			*out;
	const char		*mine =
	    HCSECD_MARKER "\n"
	    "device {\n"
	    "\tbdaddr\taa:bb:cc:11:22:02;\n"
	    "\tname\t\"Old\";\n"
	    "\tkey\t0xaabbccddeeff00112233445566778899;\n"
	    "\tpin\tnopin;\n"
	    "}\n";

	printf("\nkey preservation\n");

	db = hcsecd_parse(mine);
	ok(hcsecd_is_managed(db, speaker_addr), "the block is ours");
	ok(hcsecd_has_key(db, speaker_addr), "and it has a key");
	ok(hcsecd_set(db, speaker_addr,
	    &(struct hcsecd_entry){ .name = "New", .pin = NULL }, 0) == HCSECD_CHANGED,
	    "renaming it succeeds");
	out = hcsecd_emit(db, NULL);
	ok(has(out, "\tkey\t0xaabbccddeeff00112233445566778899;\n"),
	    "and the key survives the rename untouched");
	ok(has(out, "\tname\t\"New\";\n"), "with the new name in place");
	free(out);
	hcsecd_free(db);
}

static void
test_remove(void)
{
	struct hcsecd_db	*db;
	char			*out;

	printf("\nhcsecd_remove\n");

	db = hcsecd_parse(tmpl);
	ok(hcsecd_remove(db, defaddr, 0) == HCSECD_REFUSED,
	    "the default entry cannot be removed");
	ok(hcsecd_remove(db, defaddr, 1) == HCSECD_REFUSED,
	    "not even with force");
	ok(hcsecd_remove(db, dummy1, 0) == HCSECD_KEPT,
	    "a block we did not author is not ours to remove");
	ok(hcsecd_remove(db, speaker_addr, 0) == HCSECD_UNCHANGED,
	    "removing an absent address changes nothing");
	out = hcsecd_emit(db, NULL);
	eq(out, tmpl, "so the file is unchanged");
	free(out);
	hcsecd_free(db);

	/* Ours goes without force, and the file returns to its original bytes. */
	db = hcsecd_parse(tmpl);
	hcsecd_set(db, speaker_addr,
	    &(struct hcsecd_entry){ .name = "Doomed", .pin = NULL }, 0);
	out = hcsecd_emit(db, NULL);
	hcsecd_free(db);

	db = hcsecd_parse(out);
	free(out);
	ok(hcsecd_remove(db, speaker_addr, 0) == HCSECD_CHANGED,
	    "a block we authored is removed without force");
	out = hcsecd_emit(db, NULL);
	eq(out, tmpl, "and the file returns to exactly what it was");
	free(out);
	hcsecd_free(db);

	db = hcsecd_parse(tmpl);
	ok(hcsecd_remove(db, dummy2, 1) == HCSECD_CHANGED,
	    "force removes someone else's block");
	out = hcsecd_emit(db, NULL);
	ok(!has(out, "0x00112233445566778899aabbccddeeff"), "and it is gone");
	ok(has(out, "\"Default entry\""), "while the default entry stays");
	ok(has(out, "00:01:02:03:04:05"), "and the other Dummy stays");
	free(out);
	hcsecd_free(db);
}

/*
 * A1.2.2. hcsecd keeps the first block for an address and discards the rest
 * with a LOG_ERR, so duplicates are dead weight rather than an error.
 */
static void
test_dedupe(void)
{
	struct hcsecd_db	*db;
	char			*out;
	const char		*dup =
	    "device {\n\tbdaddr\taa:bb:cc:11:22:02;\n\tname\t\"first\";\n"
	    "\tpin\tnopin;\n}\n"
	    "device {\n\tbdaddr\taa:bb:cc:11:22:02;\n\tname\t\"second\";\n"
	    "\tpin\tnopin;\n}\n";

	printf("\nA1.2.2 duplicate blocks\n");

	db = hcsecd_parse(dup);
	ok(hcsecd_count(db) == 2, "both duplicates are parsed");
	eq(hcsecd_name_for(db, speaker_addr), "first",
	    "and lookup finds the first, as hcsecd does");
	ok(!hcsecd_dirty(db), "parsing does not drop them by itself");

	ok(hcsecd_dedupe(db) == 1, "dedupe reports one dropped");
	ok(hcsecd_count(db) == 1, "leaving one block");
	out = hcsecd_emit(db, NULL);
	ok(has(out, "\"first\""), "the first is the one kept");
	ok(!has(out, "\"second\""), "the later one is gone");
	free(out);
	hcsecd_free(db);

	db = hcsecd_parse(tmpl);
	ok(hcsecd_dedupe(db) == 0, "the template has no duplicates");
	ok(!hcsecd_dirty(db), "so dedupe left it clean");
	hcsecd_free(db);
}

static void
test_marker_discipline(void)
{
	struct hcsecd_db	*db;
	const char		*block =
	    "device {\n\tbdaddr\taa:bb:cc:11:22:02;\n\tpin\tnopin;\n}\n";

	printf("\nmarker discipline\n");

	db = hcsecd_parse(HCSECD_MARKER "\ndevice {\n"
	    "\tbdaddr\taa:bb:cc:11:22:02;\n\tpin\tnopin;\n}\n");
	ok(hcsecd_is_managed(db, speaker_addr), "a marker on the preceding line claims it");
	hcsecd_free(db);

	db = hcsecd_parse(HCSECD_MARKER "\n\ndevice {\n"
	    "\tbdaddr\taa:bb:cc:11:22:02;\n\tpin\tnopin;\n}\n");
	ok(!hcsecd_is_managed(db, speaker_addr),
	    "a blank line between them means it is not ours");
	hcsecd_free(db);

	db = hcsecd_parse("# managed by someone else\ndevice {\n"
	    "\tbdaddr\taa:bb:cc:11:22:02;\n\tpin\tnopin;\n}\n");
	ok(!hcsecd_is_managed(db, speaker_addr), "another comment does not claim it");
	hcsecd_free(db);

	{
		char	 buf[512];

		(void)snprintf(buf, sizeof(buf), "%s%s", block, HCSECD_MARKER "\n");
		db = hcsecd_parse(buf);
		ok(!hcsecd_is_managed(db, speaker_addr),
		    "a marker after the block does not claim it");
		hcsecd_free(db);
	}
}

int
main(void)
{

	test_roundtrip();
	test_parse();
	test_set();
	test_key_preserved();
	test_remove();
	test_dedupe();
	test_marker_discipline();

	printf("\n%d checks, %d failures\n", checks, failures);

	if (btmgr_mc_report() != 0) {
		printf("memcheck: allocations still live\n");
		failures++;
	}

	return (failures == 0 ? 0 : 1);
}

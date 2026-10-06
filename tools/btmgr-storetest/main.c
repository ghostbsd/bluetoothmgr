/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-storetest - verification for common/store.c. SPEC.md A4.
 *
 * Needs no privilege and touches no file. Exits 0 when every check passes.
 */

#include <sys/cdefs.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btaddr.h"
#include "store.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"

static int	 failures;
static int	 checks;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 eq(const char *got, const char *want, const char *what);
static int	 has(const char *hay, const char *needle);

static const uint8_t	 speaker_addr[6] = { 0x02, 0x22, 0x11, 0xcc, 0xbb, 0xaa };
static const uint8_t	 phones[6] = { 0x01, 0x22, 0x11, 0xcc, 0xbb, 0x0a };
static const uint8_t	 absent[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };

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

static void
test_empty(void)
{
	struct store	*st;
	char		*out;
	int		 bad;

	printf("\nempty and absent\n");

	st = store_new();
	ok(store_count(st) == 0, "a new store holds nothing");
	ok(!store_dirty(st), "and is clean");
	out = store_emit(st, NULL);
	eq(out, "{\n  \"devices\": [],\n  \"version\": 1\n}\n",
	    "and renders as version 1 with an empty device list");
	free(out);
	store_free(st);

	st = store_parse(NULL, &bad, NULL);
	ok(st != NULL && store_count(st) == 0 && bad == 0,
	    "an absent file is an empty store, not a failure");
	store_free(st);

	st = store_parse("", &bad, NULL);
	ok(st != NULL && store_count(st) == 0 && bad == 0,
	    "and so is an empty one");
	store_free(st);
}

static void
test_set_and_roundtrip(void)
{
	struct store	*st;
	char		*out, *again;

	printf("\nA4.1 metadata, and a stable round trip\n");

	st = store_new();
	ok(store_set(st, speaker_addr, "Soundbar X900", "Soundbar_X900", "speaker",
	    1000) == STORE_CHANGED, "a new device is added");
	ok(store_dirty(st), "which dirties the store");
	ok(store_count(st) == 1, "and there is one device");
	eq(store_name(st, speaker_addr), "Soundbar X900", "the name is kept");
	eq(store_alias(st, speaker_addr), "Soundbar_X900", "the alias is kept");
	eq(store_type(st, speaker_addr), "speaker", "the type is kept");
	ok(store_first_seen(st, speaker_addr) == 1000, "first_seen is set to now");
	ok(store_last_connected(st, speaker_addr) == 0, "last_connected starts at never");
	ok(!store_auto_connect(st, speaker_addr), "auto_connect starts off");

	/* A0.5 needs byte-stable rendering from one model. */
	out = store_emit(st, NULL);
	again = store_emit(st, NULL);
	eq(again, out, "the same model renders to the same bytes twice");
	free(again);

	/* Re-parsing what we wrote must give the same model back. */
	store_free(st);
	st = store_parse(out, NULL, NULL);
	free(out);
	eq(store_name(st, speaker_addr), "Soundbar X900", "the name survives a round trip");
	eq(store_alias(st, speaker_addr), "Soundbar_X900", "so does the alias");
	eq(store_type(st, speaker_addr), "speaker", "so does the type");
	ok(store_first_seen(st, speaker_addr) == 1000, "so does first_seen");
	ok(!store_dirty(st), "and parsing does not dirty the store");

	/* A0.5: setting the same values again must not dirty anything. */
	ok(store_set(st, speaker_addr, "Soundbar X900", "Soundbar_X900", "speaker",
	    9999) == STORE_UNCHANGED, "setting identical values reports unchanged");
	ok(!store_dirty(st), "and leaves the store clean");
	ok(store_first_seen(st, speaker_addr) == 1000,
	    "with first_seen untouched, since the device is not new");

	ok(store_set(st, speaker_addr, "Renamed", NULL, NULL, 0) == STORE_CHANGED,
	    "a changed name updates");
	eq(store_name(st, speaker_addr), "Renamed", "to the new value");
	eq(store_alias(st, speaker_addr), "Soundbar_X900",
	    "while a NULL field leaves the old value alone");
	store_free(st);
}

static void
test_mutators(void)
{
	struct store	*st;

	printf("\nconnection time and auto-connect\n");

	st = store_new();
	ok(store_touch_connected(st, absent, 5) == STORE_ABSENT,
	    "touching an unknown device reports absent");
	ok(store_set_auto_connect(st, absent, 1) == STORE_ABSENT,
	    "so does setting auto-connect on one");
	ok(store_remove(st, absent) == STORE_ABSENT, "so does removing one");
	ok(!store_dirty(st), "and none of those dirtied the store");

	store_set(st, speaker_addr, "Z", "z", "speaker", 100);
	ok(store_touch_connected(st, speaker_addr, 200) == STORE_CHANGED,
	    "a connection time is recorded");
	ok(store_last_connected(st, speaker_addr) == 200, "and read back");
	ok(store_touch_connected(st, speaker_addr, 200) == STORE_UNCHANGED,
	    "recording the same time again is unchanged");

	ok(store_set_auto_connect(st, speaker_addr, 1) == STORE_CHANGED,
	    "auto-connect is turned on");
	ok(store_auto_connect(st, speaker_addr), "and reads back on");
	ok(store_set_auto_connect(st, speaker_addr, 1) == STORE_UNCHANGED,
	    "turning it on again is unchanged");
	ok(store_set_auto_connect(st, speaker_addr, 0) == STORE_CHANGED,
	    "and it can be turned off");

	ok(store_remove(st, speaker_addr) == STORE_CHANGED, "the device is removed");
	ok(store_count(st) == 0, "leaving none");
	ok(!store_has(st, speaker_addr), "and it is no longer found");
	store_free(st);
}

/* A4.1. There is no setter for a secret, and one on disk does not survive. */
static void
test_no_secrets(void)
{
	struct store	*st;
	char		*out;

	printf("\nA4.1 no PINs, no link keys\n");

	st = store_parse("{\"version\":1,\"devices\":[{"
	    "\"addr\":\"aa:bb:cc:11:22:02\",\"name\":\"Z\","
	    "\"pin\":\"1234\",\"key\":\"00112233445566778899aabbccddeeff\","
	    "\"link_key\":\"deadbeef\"}]}", NULL, NULL);

	ok(store_count(st) == 1, "a device carrying secrets still parses");
	eq(store_name(st, speaker_addr), "Z", "and its real metadata is read");

	out = store_emit(st, NULL);
	ok(!has(out, "1234"), "but the pin is gone from the next write");
	ok(!has(out, "00112233445566778899aabbccddeeff"),
	    "and so is the key");
	ok(!has(out, "deadbeef"), "and so is the link_key");
	ok(!has(out, "\"pin\""), "with no pin field at all");
	ok(!has(out, "\"key\""), "and no key field");
	free(out);
	store_free(st);
}

/* A4.3. A bad file must cost the cache, never the daemon. */
static void
test_malformed(void)
{
	struct store	*st;
	int		 bad;
	size_t		 skip;

	printf("\nA4.3 a parse failure is not fatal\n");

	st = store_parse("this is not json at all", &bad, NULL);
	ok(st != NULL && bad == 1 && store_count(st) == 0,
	    "garbage gives an empty store and reports malformed");
	store_free(st);

	st = store_parse("[1,2,3]", &bad, NULL);
	ok(st != NULL && bad == 1, "a top level array is malformed");
	store_free(st);

	st = store_parse("{\"devices\":[]}", &bad, NULL);
	ok(st != NULL && bad == 1, "a missing version is malformed (A4.2)");
	store_free(st);

	st = store_parse("{\"version\":\"1\",\"devices\":[]}", &bad, NULL);
	ok(st != NULL && bad == 1, "a non-integer version is malformed");
	store_free(st);

	/*
	 * A newer version is someone else's future format, not garbage, which
	 * is why A4.3 says rename aside rather than delete.
	 */
	st = store_parse("{\"version\":99,\"devices\":[]}", &bad, NULL);
	ok(st != NULL && bad == 1, "a newer version is refused, not rewritten");
	store_free(st);

	st = store_parse("{\"version\":1,\"devices\":{}}", &bad, NULL);
	ok(st != NULL && bad == 1, "a devices field that is not an array is malformed");
	store_free(st);

	st = store_parse("{\"version\":1}", &bad, NULL);
	ok(st != NULL && bad == 0 && store_count(st) == 0,
	    "but no devices field at all is simply empty");
	store_free(st);

	/* One bad entry must not cost the good ones. */
	st = store_parse("{\"version\":1,\"devices\":["
	    "{\"addr\":\"aa:bb:cc:11:22:02\",\"name\":\"good\"},"
	    "{\"addr\":\"not an address\"},"
	    "{\"name\":\"no addr\"},"
	    "\"not even an object\","
	    "{\"addr\":\"0a:bb:cc:11:22:01\",\"name\":\"also good\"}"
	    "]}", &bad, &skip);
	ok(bad == 0, "a file with some bad entries is not itself malformed");
	ok(skip == 3, "the three unusable entries are counted");
	ok(store_count(st) == 2, "and the two good ones are kept");
	eq(store_name(st, speaker_addr), "good", "the first good one is there");
	eq(store_name(st, phones), "also good", "and so is the last");
	store_free(st);

	/* Two records for one device would be ambiguous. */
	st = store_parse("{\"version\":1,\"devices\":["
	    "{\"addr\":\"aa:bb:cc:11:22:02\",\"name\":\"first\"},"
	    "{\"addr\":\"aa:bb:cc:11:22:02\",\"name\":\"second\"}]}",
	    &bad, &skip);
	ok(store_count(st) == 1 && skip == 1,
	    "a duplicate address is skipped, not stored twice");
	eq(store_name(st, speaker_addr), "first", "keeping the first");
	store_free(st);

	/* A wrong field type is ignored rather than taken as a value. */
	st = store_parse("{\"version\":1,\"devices\":[{"
	    "\"addr\":\"aa:bb:cc:11:22:02\",\"name\":42,"
	    "\"first_seen\":\"soon\",\"auto_connect\":\"yes\"}]}", &bad, &skip);
	ok(store_count(st) == 1 && skip == 0, "the entry is still usable");
	ok(store_name(st, speaker_addr) == NULL, "a non-string name is ignored");
	ok(store_first_seen(st, speaker_addr) == 0, "a non-integer time is ignored");
	ok(!store_auto_connect(st, speaker_addr), "a non-boolean flag is ignored");
	store_free(st);
}

static void
test_order(void)
{
	struct store	*st;
	uint8_t		 got[4][BTMGR_ADDR_LEN];
	char		 s[BTMGR_ADDR_BUFSZ];

	printf("\ndevice order\n");

	st = store_new();
	store_set(st, speaker_addr, "Z", NULL, NULL, 1);
	store_set(st, phones, "P", NULL, NULL, 2);

	ok(store_addrs(st, got, 4) == 2, "both devices are listed");
	btmgr_addr_format(got[0], s, sizeof(s));
	eq(s, "aa:bb:cc:11:22:02", "in insertion order, not sorted");
	btmgr_addr_format(got[1], s, sizeof(s));
	eq(s, "0a:bb:cc:11:22:01", "with the second one second");
	ok(store_addrs(st, NULL, 0) == 2, "a NULL buffer still counts them");
	store_free(st);
}

int
main(void)
{

	test_empty();
	test_set_and_roundtrip();
	test_mutators();
	test_no_secrets();
	test_malformed();
	test_order();

	printf("\n%d checks, %d failures\n", checks, failures);

	if (btmgr_mc_report() != 0) {
		printf("memcheck: allocations still live\n");
		failures++;
	}

	return (failures == 0 ? 0 : 1);
}

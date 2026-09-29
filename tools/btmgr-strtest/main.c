/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-strtest - verification for common/sanitise.c. SPEC.md A7, A2.2 to A2.5.
 *
 * Needs no privilege, no hardware and no daemon. Exits 0 when every check
 * passes, 1 otherwise.
 */

#include <sys/cdefs.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitise.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"

static int	 failures;
static int	 checks;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 eq(const char *got, const char *want, const char *what);
static void	 poison(char *buf, size_t len);
static void	 quoted_eq(const char *in, const char *want, const char *what);
static void	 alias_eq(const char *name, const char *want, const char *what);
static void	 suffix_eq(const char *stem, unsigned int n, const char *want,
		     const char *what);

static void
ok(int cond, const char *fmt, ...)
{
	va_list	 ap;

	checks++;
	va_start(ap, fmt);
	if (cond) {
		fputs("ok   ", stdout);
	} else {
		fputs("FAIL ", stdout);
		failures++;
	}
	vprintf(fmt, ap);
	putchar('\n');
	va_end(ap);
}

static void
eq(const char *got, const char *want, const char *what)
{
	int	 same = strcmp(got, want) == 0;

	ok(same, "%s%s%s%s", what, same ? "" : " (got \"",
	    same ? "" : got, same ? "" : "\")");
}

/* The address behind bt-d2d788, in bdaddr_t storage order. */
static const uint8_t	 addr[6] = { 0x88, 0xd7, 0xd2, 0x33, 0x22, 0x11 };

/*
 * Fill a buffer with a non-NUL pattern, NUL terminated so a comparison on it
 * is defined. A call that returns success but writes nothing is then a visible
 * failure rather than a pass on whatever was there before.
 */
static void
poison(char *buf, size_t len)
{

	memset(buf, 0xa5, len - 1);
	buf[len - 1] = '\0';
}

/*
 * The three wrappers below exist so that no test can inspect an output buffer
 * without the call's return value having been checked first. Each performs
 * exactly one check, so the totals stay readable.
 */
static void
quoted_eq(const char *in, const char *want, const char *what)
{
	char	 out[512];

	poison(out, sizeof(out));

	if (btmgr_sanitise_quoted(in, out, sizeof(out)) != 0) {
		ok(0, "%s (call failed: %s)", what, strerror(errno));
		return;
	}
	eq(out, want, what);
}

static void
alias_eq(const char *name, const char *want, const char *what)
{
	char	 out[BTMGR_ALIAS_BUFSZ];

	poison(out, sizeof(out));

	if (btmgr_alias_from_name(name, addr, out, sizeof(out)) != 0) {
		ok(0, "%s (call failed: %s)", what, strerror(errno));
		return;
	}
	/* Every generated alias must be usable, whatever the name was. */
	if (!btmgr_alias_is_valid(out)) {
		ok(0, "%s (\"%s\" is not a valid alias)", what, out);
		return;
	}
	eq(out, want, what);
}

static void
suffix_eq(const char *stem, unsigned int n, const char *want, const char *what)
{
	char	 out[BTMGR_ALIAS_BUFSZ];

	poison(out, sizeof(out));

	if (btmgr_alias_with_suffix(stem, n, out, sizeof(out)) != 0) {
		ok(0, "%s (call failed: %s)", what, strerror(errno));
		return;
	}
	if (!btmgr_alias_is_valid(out)) {
		ok(0, "%s (\"%s\" is not a valid alias)", what, out);
		return;
	}
	eq(out, want, what);
}

static void
test_quoted(void)
{
	char	 out[512];

	printf("\nA7.1 hcsecd quoted strings\n");

	quoted_eq("Logitech Z337", "Logitech Z337",
	    "spaces are kept, a quoted string may hold them");
	quoted_eq("say \"hi\"", "say _hi_",
	    "the double quote that would end the token is replaced");
	quoted_eq("back\\slash", "back_slash", "the backslash is replaced");
	quoted_eq("two\nlines", "two_lines",
	    "the newline that would end the line is replaced");
	quoted_eq("bell\ahere\x7f", "bell_here_",
	    "other controls and DEL are replaced");
	quoted_eq("caf\xc3\xa9", "caf\xc3\xa9",
	    "UTF-8 passes through, the lexer accepts it");
	quoted_eq("", "", "the empty name is legal here, A7.4 is an alias rule");

	/* The attack A7.1 exists for: closing the block and opening another. */
	poison(out, sizeof(out));
	ok(btmgr_sanitise_quoted("x\";\n};\ndevice {\n\tbdaddr 0:0:0:0:0:0;",
	    out, sizeof(out)) == 0, "a forged config block is accepted as a name");
	ok(strchr(out, '"') == NULL && strchr(out, '\n') == NULL,
	    "and cannot escape its token");
	eq(out, "x_;_};_device {__bdaddr 0:0:0:0:0:0;",
	    "while the rest of it survives, tab included as a control");

	errno = 0;
	ok(btmgr_sanitise_quoted("abcd", out, 4) == -1 && errno == ENAMETOOLONG,
	    "a buffer one byte short is refused, not truncated");

	errno = 0;
	ok(btmgr_sanitise_quoted(NULL, out, sizeof(out)) == -1 &&
	    errno == EINVAL, "a NULL input is refused");
}

static void
test_alias(void)
{
	char	 out[BTMGR_ALIAS_BUFSZ];

	printf("\nA7.2, A7.4, A2.3 aliases\n");

	alias_eq("Logitech Z337", "Logitech_Z337", "a space becomes an underscore");
	alias_eq("My/Device:1", "My_Device_1",
	    "slash and colon are outside the charset");
	alias_eq("a.b-c_d", "a.b-c_d", "dot, dash and underscore are inside it");
	alias_eq("My   Bluetooth   Speaker", "My_Bluetooth_Spe",
	    "runs collapse, then A2.3 truncates at 16");
	alias_eq("  leading", "leading",
	    "a leading separator is dropped, not collapsed");
	alias_eq("trailing  ", "trailing", "a trailing separator is dropped");
	alias_eq("SoundCore Mini2", "SoundCore_Mini2",
	    "a 15 character name is untouched");

	/* Character 16 is the separator, so the cut leaves it dangling. */
	alias_eq("SoundCoreXMiniZ ABC", "SoundCoreXMiniZ",
	    "a cut landing on a separator trims it");
	alias_eq("0123456789abcdefghij", "0123456789abcdef",
	    "a long name is cut at the budget");

	printf("\nA7.4 fallback\n");

	alias_eq("", "bt-d2d788", "an empty name falls back to the address");
	alias_eq(NULL, "bt-d2d788", "so does a NULL name");
	alias_eq("___", "bt-d2d788", "so does a name that is only separators");

	/* Not empty after transliteration, but equally useless. */
	alias_eq("\xf0\x9f\x8e\xa7", "bt-d2d788", "so does a name of only emoji");
	alias_eq("...", "bt-d2d788", "so does a name of only dots");
	alias_eq("7", "7", "one digit is usable, so no fallback");

	/*
	 * The refusals, which need a buffer with a known prior value so that
	 * "left untouched" is a claim the check can actually see.
	 */
	poison(out, sizeof(out));
	ok(btmgr_alias_from_name("speaker", addr, out, sizeof(out)) == 0,
	    "a call that will be followed by refusals succeeds");
	eq(out, "speaker", "and leaves its result");

	errno = 0;
	ok(btmgr_alias_from_name("", NULL, out, sizeof(out)) == -1 &&
	    errno == EINVAL, "the fallback without an address is refused");
	eq(out, "speaker", "and that refusal leaves out as it was");

	errno = 0;
	ok(btmgr_alias_from_name("x", addr, out, BTMGR_ALIAS_MAX) == -1 &&
	    errno == ENAMETOOLONG, "a buffer without room for the NUL is refused");
	eq(out, "speaker", "and so does that one");
}

static void
test_suffix(void)
{
	char	 out[BTMGR_ALIAS_BUFSZ];
	unsigned int n;

	printf("\nA2.4 collision suffixes\n");

	btmgr_alias_with_suffix("speaker", 2, out, sizeof(out));
	suffix_eq("speaker", 2, "speaker2", "a short stem keeps all of itself");
	suffix_eq("0123456789abcdef", 2, "0123456789abcde2",
	    "a full stem gives up one character to stay in budget");
	suffix_eq("0123456789abcdef", 10, "0123456789abcd10",
	    "a two digit suffix gives up two");
	suffix_eq("Logitech_Z337abc", 12, "Logitech_Z337a12",
	    "the cut lands mid-stem");
	suffix_eq("Logitech_Zxxxxx", 123456, "Logitech_Z123456",
	    "a trailing separator after the cut is dropped");

	/*
	 * UINT_MAX is 10 digits, so the guard against a suffix crowding out the
	 * stem cannot fire at this budget. Check the outcome it protects.
	 */
	suffix_eq("MySpeaker", 4294967295u, "MySpea4294967295",
	    "the widest suffix an unsigned int can give still leaves a stem");

	/* Every variant the caller's search can produce must be usable. */
	for (n = 2; n < 500; n++) {
		poison(out, sizeof(out));
		if (btmgr_alias_with_suffix("My_Speaker", n, out,
		    sizeof(out)) != 0)
			break;
		if (!btmgr_alias_is_valid(out))
			break;
	}
	ok(n == 500, "variants 2 through 499 are all valid aliases");
	eq(out, "My_Speaker499", "and the last of them is the expected one");

	errno = 0;
	ok(btmgr_alias_with_suffix("", 2, out, sizeof(out)) == -1 &&
	    errno == EINVAL, "an empty stem is refused");
	eq(out, "My_Speaker499", "and that refusal leaves out as it was");

	errno = 0;
	ok(btmgr_alias_with_suffix("__", 2, out, sizeof(out)) == -1 &&
	    errno == EINVAL, "a stem that trims to nothing is refused");
	eq(out, "My_Speaker499", "and so does that one");
}

static void
test_addrlike(void)
{

	printf("\nA2.5 aliases that bt_aton would eat\n");

	ok(btmgr_alias_is_addrlike("00:11:22:33:44:55"),
	    "a full address is address-like");
	ok(btmgr_alias_is_addrlike("1:2:3:4:5:6"),
	    "so is the short form, which bt_aton also accepts");
	ok(btmgr_alias_is_addrlike("aB:cD:eF:01:23:45"),
	    "hex case does not matter");

	ok(!btmgr_alias_is_addrlike("00:11:22:33:44"),
	    "five fields are not");
	ok(!btmgr_alias_is_addrlike("00:11:22:33:44:55:66"),
	    "seven fields are not");
	ok(!btmgr_alias_is_addrlike("000:11:22:33:44:55"),
	    "a three digit field is not");
	ok(!btmgr_alias_is_addrlike("00:11:22:33:44:5g"),
	    "a non-hex digit is not");
	ok(!btmgr_alias_is_addrlike("00:11:22:33:44:55 "),
	    "trailing text is not");
	ok(!btmgr_alias_is_addrlike("speaker"), "an ordinary alias is not");
	ok(!btmgr_alias_is_addrlike(""), "the empty string is not");
	ok(!btmgr_alias_is_addrlike(NULL), "NULL is not");

	/* The reason A2.5 is belt and braces rather than the only guard. */
	alias_eq("00:11:22:33:44:55", "00_11_22_33_44_5",
	    "A7.2 alone already makes an address-like alias impossible");
}

static void
test_valid(void)
{
	char	 toolong[BTMGR_ALIAS_MAX + 2];

	printf("\nalias validation\n");

	ok(btmgr_alias_is_valid("speaker"), "an ordinary alias is valid");
	ok(btmgr_alias_is_valid("a.b-c_d"), "the full charset is valid");
	ok(btmgr_alias_is_valid("0123456789abcdef"), "16 characters is valid");

	memset(toolong, 'a', sizeof(toolong) - 1);
	toolong[sizeof(toolong) - 1] = '\0';
	ok(!btmgr_alias_is_valid(toolong), "17 characters is not");

	ok(!btmgr_alias_is_valid(""), "the empty alias is not");
	ok(!btmgr_alias_is_valid(NULL), "NULL is not");
	ok(!btmgr_alias_is_valid("has space"), "a space is not");
	ok(!btmgr_alias_is_valid("has/slash"), "a slash is not");
	ok(!btmgr_alias_is_valid("___"), "separators with no alnum are not");
	ok(!btmgr_alias_is_valid("1:2:3:4:5:6"), "an address-like alias is not");
}

int
main(void)
{

	test_quoted();
	test_alias();
	test_suffix();
	test_addrlike();
	test_valid();

	printf("\n%d checks, %d failures\n", checks, failures);

	if (btmgr_mc_report() != 0) {
		printf("memcheck: allocations still live\n");
		failures++;
	}

	return (failures == 0 ? 0 : 1);
}
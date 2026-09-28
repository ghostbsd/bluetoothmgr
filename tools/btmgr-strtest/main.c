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

static void
test_quoted(void)
{
	char	 out[512];

	printf("\nA7.1 hcsecd quoted strings\n");

	ok(btmgr_sanitise_quoted("Logitech Z337", out, sizeof(out)) == 0,
	    "an ordinary name is accepted");
	eq(out, "Logitech Z337", "spaces are kept, a quoted string may hold them");

	btmgr_sanitise_quoted("say \"hi\"", out, sizeof(out));
	eq(out, "say _hi_", "the double quote that would end the token is replaced");

	btmgr_sanitise_quoted("back\\slash", out, sizeof(out));
	eq(out, "back_slash", "the backslash is replaced");

	btmgr_sanitise_quoted("two\nlines", out, sizeof(out));
	eq(out, "two_lines", "the newline that would end the line is replaced");

	btmgr_sanitise_quoted("bell\ahere\x7f", out, sizeof(out));
	eq(out, "bell_here_", "other controls and DEL are replaced");

	btmgr_sanitise_quoted("caf\xc3\xa9", out, sizeof(out));
	eq(out, "caf\xc3\xa9", "UTF-8 passes through, the lexer accepts it");

	/* The attack A7.1 exists for: closing the block and opening another. */
	btmgr_sanitise_quoted("x\";\n};\ndevice {\n\tbdaddr 0:0:0:0:0:0;",
	    out, sizeof(out));
	ok(strchr(out, '"') == NULL && strchr(out, '\n') == NULL,
	    "a name forging a config block cannot escape its token");

	eq(out, "x_;_};_device {__bdaddr 0:0:0:0:0:0;",
	    "and the rest of it survives, tab included as a control");

	btmgr_sanitise_quoted("", out, sizeof(out));
	eq(out, "", "the empty name is legal here, A7.4 is an alias rule");

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

	btmgr_alias_from_name("Logitech Z337", addr, out, sizeof(out));
	eq(out, "Logitech_Z337", "a space becomes an underscore");

	btmgr_alias_from_name("My/Device:1", addr, out, sizeof(out));
	eq(out, "My_Device_1", "slash and colon are outside the charset");

	btmgr_alias_from_name("a.b-c_d", addr, out, sizeof(out));
	eq(out, "a.b-c_d", "dot, dash and underscore are inside it");

	btmgr_alias_from_name("My   Bluetooth   Speaker", addr, out,
	    sizeof(out));
	eq(out, "My_Bluetooth_Spe", "runs collapse, then A2.3 truncates at 16");
	ok(strlen(out) == BTMGR_ALIAS_MAX, "and the budget is exactly spent");

	btmgr_alias_from_name("  leading", addr, out, sizeof(out));
	eq(out, "leading", "a leading separator is dropped, not collapsed");

	btmgr_alias_from_name("trailing  ", addr, out, sizeof(out));
	eq(out, "trailing", "a trailing separator is dropped");

	/* Truncation landing on a separator must not leave a dangling one. */
	btmgr_alias_from_name("SoundCore Mini2", addr, out, sizeof(out));
	eq(out, "SoundCore_Mini2", "a 15 character name is untouched");

	/* Character 16 is the separator, so the cut leaves it dangling. */
	btmgr_alias_from_name("SoundCoreXMiniZ ABC", addr, out, sizeof(out));
	eq(out, "SoundCoreXMiniZ", "a cut landing on a separator trims it");

	btmgr_alias_from_name("0123456789abcdefghij", addr, out, sizeof(out));
	eq(out, "0123456789abcdef", "a long name is cut at the budget");

	printf("\nA7.4 fallback\n");

	btmgr_alias_from_name("", addr, out, sizeof(out));
	eq(out, "bt-d2d788", "an empty name falls back to the address");

	btmgr_alias_from_name(NULL, addr, out, sizeof(out));
	eq(out, "bt-d2d788", "so does a NULL name");

	btmgr_alias_from_name("___", addr, out, sizeof(out));
	eq(out, "bt-d2d788", "so does a name that is only separators");

	/* Not empty after transliteration, but equally useless. */
	btmgr_alias_from_name("\xf0\x9f\x8e\xa7", addr, out, sizeof(out));
	eq(out, "bt-d2d788", "so does a name of only emoji");

	btmgr_alias_from_name("...", addr, out, sizeof(out));
	eq(out, "bt-d2d788", "so does a name of only dots");

	btmgr_alias_from_name("7", addr, out, sizeof(out));
	eq(out, "7", "one digit is usable, so no fallback");

	errno = 0;
	ok(btmgr_alias_from_name("", NULL, out, sizeof(out)) == -1 &&
	    errno == EINVAL, "the fallback without an address is refused");
	eq(out, "7", "and that refusal leaves out as it was");

	errno = 0;
	ok(btmgr_alias_from_name("x", addr, out, BTMGR_ALIAS_MAX) == -1 &&
	    errno == ENAMETOOLONG, "a buffer without room for the NUL is refused");
	eq(out, "7", "and so does that one");
}

static void
test_suffix(void)
{
	char	 out[BTMGR_ALIAS_BUFSZ];
	unsigned int n;

	printf("\nA2.4 collision suffixes\n");

	btmgr_alias_with_suffix("speaker", 2, out, sizeof(out));
	eq(out, "speaker2", "a short stem keeps all of itself");

	btmgr_alias_with_suffix("0123456789abcdef", 2, out, sizeof(out));
	eq(out, "0123456789abcde2", "a full stem gives up one character");
	ok(strlen(out) == BTMGR_ALIAS_MAX, "and still fits the budget");

	btmgr_alias_with_suffix("0123456789abcdef", 10, out, sizeof(out));
	eq(out, "0123456789abcd10", "a two digit suffix gives up two");

	btmgr_alias_with_suffix("Logitech_Z337abc", 12, out, sizeof(out));
	eq(out, "Logitech_Z337a12", "the cut lands mid-stem");

	btmgr_alias_with_suffix("Logitech_Zxxxxx", 123456, out, sizeof(out));
	eq(out, "Logitech_Z123456", "a trailing separator after the cut is dropped");

	/* Every variant the search can produce must still be a valid alias. */
	for (n = 2; n < 500; n++) {
		btmgr_alias_with_suffix("My_Speaker", n, out, sizeof(out));
		if (!btmgr_alias_is_valid(out))
			break;
	}
	ok(n == 500, "variants 2 through 499 are all valid aliases");

	errno = 0;
	ok(btmgr_alias_with_suffix("", 2, out, sizeof(out)) == -1 &&
	    errno == EINVAL, "an empty stem is refused");

	errno = 0;
	ok(btmgr_alias_with_suffix("__", 2, out, sizeof(out)) == -1 &&
	    errno == EINVAL, "a stem that trims to nothing is refused");

	eq(out, "My_Speaker499", "and the loop left the last of them");

	/*
	 * UINT_MAX is 10 digits, so the guard against a suffix crowding out the
	 * stem cannot fire at this budget. Check the outcome it protects.
	 */
	btmgr_alias_with_suffix("MySpeaker", 4294967295u, out, sizeof(out));
	eq(out, "MySpea4294967295", "the widest suffix still leaves a stem");
	ok(btmgr_alias_is_valid(out) != 0, "and that is still a valid alias");
}

static void
test_addrlike(void)
{
	char	 out[BTMGR_ALIAS_BUFSZ];

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
	btmgr_alias_from_name("00:11:22:33:44:55", addr, out, sizeof(out));
	eq(out, "00_11_22_33_44_5",
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
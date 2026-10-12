/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-prototest - verification for common/proto.c. SPEC.md Part B.
 *
 * proto_parse_cmd() is the daemon's only reader of untrusted client input, and
 * it had no test of its own, so this covers the whole of it rather than only
 * the newest field.
 *
 * The PIN rules get the most attention. A PIN is the one string in the
 * protocol that must survive byte for byte: hcsecd_set() runs it through the
 * A7.1 sanitiser, which transliterates, so a PIN containing a quote would be
 * silently rewritten into a secret that no longer matches the device. These
 * checks pin down that such a PIN is refused rather than altered.
 *
 * Needs no root, no hardware and no daemon. Exits 0 when every check passes.
 */

#include <sys/cdefs.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proto.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"	/* IWYU pragma: keep */

static int	 failures;
static int	 checks;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static void	 eq(const char *got, const char *want, const char *what);
static int	 parse(const char *line, struct proto_cmd *cmd, char *code,
		     size_t codelen);
static void	 rejects(const char *line, const char *wantcode,
		     const char *what);

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
	ok(same, "%s%s%s%s", what, same ? "" : " (got \"", same ? "" : got,
	    same ? "" : "\")");
}

static int
parse(const char *line, struct proto_cmd *cmd, char *code, size_t codelen)
{

	code[0] = '\0';

	return (proto_parse_cmd(line, strlen(line), cmd, code, codelen));
}

/* Assert a line is refused, and refused with the code SPEC.md B6 names. */
static void
rejects(const char *line, const char *wantcode, const char *what)
{
	struct proto_cmd	 cmd;
	char			 code[32];

	if (parse(line, &cmd, code, sizeof(code)) == 0) {
		ok(0, "%s (was accepted)", what);
		return;
	}
	ok(strcmp(code, wantcode) == 0, "%s%s%s%s", what,
	    strcmp(code, wantcode) == 0 ? "" : " (code \"",
	    strcmp(code, wantcode) == 0 ? "" : code,
	    strcmp(code, wantcode) == 0 ? "" : "\")");
}

static void
test_envelope(void)
{
	struct proto_cmd	 cmd;
	char			 code[32];

	printf("\nB3 the envelope\n");

	ok(parse("{\"id\":1,\"cmd\":\"get_state\"}", &cmd, code,
	    sizeof(code)) == 0, "a minimal command parses");
	ok(cmd.id == 1, "the id is read");
	eq(cmd.name, "get_state", "and the command name");
	ok(!cmd.has_addr && !cmd.has_pin && !cmd.has_on && !cmd.has_timeout,
	    "with every optional field absent");

	rejects("", "bad_json", "an empty line is bad_json");
	rejects("not json", "bad_json", "rubbish is bad_json");
	rejects("[1,2,3]", "bad_json", "a JSON array is not an envelope");
	rejects("\"a string\"", "bad_json", "nor is a bare string");
	rejects("{\"cmd\":\"get_state\"}", "missing_id", "no id is missing_id");
	rejects("{\"id\":\"1\",\"cmd\":\"get_state\"}", "missing_id",
	    "a string id is missing_id, not coerced");
	rejects("{\"id\":-1,\"cmd\":\"get_state\"}", "missing_id",
	    "a negative id is refused");
	rejects("{\"id\":1}", "missing_cmd", "no cmd is missing_cmd");
	rejects("{\"id\":1,\"cmd\":42}", "missing_cmd", "a non-string cmd too");

	/*
	 * B3.1 wants the error addressed to the request that caused it, so the
	 * id has to survive a failure further down the message.
	 */
	ok(parse("{\"id\":77,\"cmd\":\"connect\",\"addr\":42}", &cmd, code,
	    sizeof(code)) == -1 && cmd.id == 77,
	    "a later failure still recovers the id, per B3.1");

	/* A command name longer than the buffer must not be truncated in. */
	rejects("{\"id\":1,\"cmd\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
	    "not_found", "an over-long command name is refused");
}

static void
test_addr(void)
{
	struct proto_cmd	 cmd;
	char			 code[32];

	printf("\naddr\n");

	ok(parse("{\"id\":2,\"cmd\":\"connect\",\"addr\":\"aa:bb:cc:11:22:02\"}",
	    &cmd, code, sizeof(code)) == 0, "an address parses");
	ok(cmd.has_addr, "and is marked present");

	/* bt_aton is the lenient dialect, so one digit per octet is valid. */
	ok(parse("{\"id\":2,\"cmd\":\"connect\",\"addr\":\"1:2:3:4:5:6\"}",
	    &cmd, code, sizeof(code)) == 0 && cmd.has_addr,
	    "a short-form address parses, as bt_aton accepts it");

	rejects("{\"id\":2,\"cmd\":\"connect\",\"addr\":42}", "bad_addr",
	    "a non-string addr is bad_addr");
	rejects("{\"id\":2,\"cmd\":\"connect\",\"addr\":\"nonsense\"}",
	    "bad_addr", "an unparseable addr is bad_addr");
	rejects("{\"id\":2,\"cmd\":\"connect\",\"addr\":\"\"}", "bad_addr",
	    "an empty addr is bad_addr");
	rejects("{\"id\":2,\"cmd\":\"connect\",\"addr\":null}", "bad_addr",
	    "an explicit null addr is an error, not an omission");
}

static void
test_scalars(void)
{
	struct proto_cmd	 cmd;
	char			 code[32];

	printf("\ntimeout and on\n");

	ok(parse("{\"id\":3,\"cmd\":\"set_discoverable\",\"timeout\":60}",
	    &cmd, code, sizeof(code)) == 0 && cmd.has_timeout &&
	    cmd.timeout == 60, "a timeout parses");
	ok(parse("{\"id\":3,\"cmd\":\"set_discoverable\",\"on\":true}",
	    &cmd, code, sizeof(code)) == 0 && cmd.has_on && cmd.on == 1,
	    "on true parses");
	ok(parse("{\"id\":3,\"cmd\":\"set_discoverable\",\"on\":false}",
	    &cmd, code, sizeof(code)) == 0 && cmd.has_on && cmd.on == 0,
	    "on false parses and is distinguishable from absent");

	rejects("{\"id\":3,\"cmd\":\"set_discoverable\",\"timeout\":\"60\"}",
	    "bad_json", "a string timeout is not coerced");
	rejects("{\"id\":3,\"cmd\":\"set_discoverable\",\"timeout\":1.5}",
	    "bad_json", "nor is a fractional one");
	rejects("{\"id\":3,\"cmd\":\"set_discoverable\",\"on\":1}",
	    "bad_json", "on must be a boolean, not 1");

	/*
	 * The range check lives in the handler, not here, because the limit is
	 * about Write_Scan_Enable rather than about the wire format. Parsing a
	 * huge value must therefore still succeed.
	 */
	ok(parse("{\"id\":3,\"cmd\":\"set_discoverable\",\"timeout\":999999}",
	    &cmd, code, sizeof(code)) == 0,
	    "an out-of-range timeout parses; the handler range checks it");
}

/* B4 pair. The PIN is a secret, so it is never transliterated. */
static void
test_pin(void)
{
	struct proto_cmd	 cmd;
	char			 code[32];
	char			 line[128];
	size_t			 i;
	static const struct {
		const char	*pin;
		const char	*what;
	} bad[] = {
		{ "",		"an empty PIN" },
		{ "12345678901234567", "a 17 byte PIN, one over NG_HCI_PIN_SIZE" },
		{ "12\\\\34",	"a PIN containing a backslash" },
		{ "12\\u000134",	"a PIN containing a control character" },
		{ "12\\u007f34",	"a PIN containing DEL" },
	};

	printf("\nB4 the pair PIN\n");

	ok(parse("{\"id\":4,\"cmd\":\"pair\",\"addr\":\"1:2:3:4:5:6\","
	    "\"pin\":\"0000\"}", &cmd, code, sizeof(code)) == 0,
	    "the ordinary numeric PIN parses");
	ok(cmd.has_pin, "and is marked present");
	eq(cmd.pin, "0000", "and is carried byte for byte");

	/* Absent is how "this device needs no PIN" is spelled. */
	ok(parse("{\"id\":4,\"cmd\":\"pair\",\"addr\":\"1:2:3:4:5:6\"}",
	    &cmd, code, sizeof(code)) == 0 && !cmd.has_pin,
	    "an absent PIN parses and is distinguishable from any value");

	/* Exactly at the limit must be accepted, since 16 is legal. */
	ok(parse("{\"id\":4,\"cmd\":\"pair\",\"pin\":\"1234567890123456\"}",
	    &cmd, code, sizeof(code)) == 0 && cmd.has_pin,
	    "a 16 byte PIN is accepted, the limit being inclusive");
	eq(cmd.pin, "1234567890123456", "and kept whole");

	/* Letters are unusual but legal, and must not be mangled. */
	ok(parse("{\"id\":4,\"cmd\":\"pair\",\"pin\":\"ab-CD_ef\"}",
	    &cmd, code, sizeof(code)) == 0, "a non-numeric PIN is accepted");
	eq(cmd.pin, "ab-CD_ef", "unchanged");

	rejects("{\"id\":4,\"cmd\":\"pair\",\"pin\":42}", "bad_json",
	    "a non-string PIN is bad_json");

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		char	 what[96];

		(void)snprintf(line, sizeof(line),
		    "{\"id\":4,\"cmd\":\"pair\",\"pin\":\"%s\"}", bad[i].pin);
		(void)snprintf(what, sizeof(what), "%s is refused",
		    bad[i].what);
		rejects(line, "bad_json", what);
	}

	/*
	 * The quote case needs its own line, since embedding it in the format
	 * above would end the JSON string early and test the parser instead.
	 */
	rejects("{\"id\":4,\"cmd\":\"pair\",\"pin\":\"12\\\"34\"}", "bad_json",
	    "a PIN containing a double quote is refused, not transliterated");
}

/* B4 pair's name. Unlike the PIN this is cosmetic, so A7.1 may rewrite it. */
static void
test_name(void)
{
	struct proto_cmd	 cmd;
	char			 code[32];
	char			 line[BTMGR_NAME_SIZE + 64];
	char			 toolong[BTMGR_NAME_SIZE + 8];

	printf("\nB4 the pair name\n");

	ok(parse("{\"id\":5,\"cmd\":\"pair\",\"name\":\"Soundbar X900\"}", &cmd,
	    code, sizeof(code)) == 0, "a name parses");
	ok(cmd.has_device_name, "and is marked present");
	eq(cmd.device_name, "Soundbar X900", "and is carried through");

	ok(parse("{\"id\":5,\"cmd\":\"pair\"}", &cmd, code, sizeof(code)) == 0 &&
	    !cmd.has_device_name, "an absent name is distinguishable from any value");

	/* A quote or a control character is the sanitiser's problem, not ours. */
	ok(parse("{\"id\":5,\"cmd\":\"pair\",\"name\":\"a \\\" quote\"}", &cmd,
	    code, sizeof(code)) == 0, "a name containing a quote is accepted");
	eq(cmd.device_name, "a \" quote",
	    "unchanged, for A7.1 to transliterate later");

	rejects("{\"id\":5,\"cmd\":\"pair\",\"name\":42}", "bad_json",
	    "a non-string name is bad_json");
	rejects("{\"id\":5,\"cmd\":\"pair\",\"name\":\"\"}", "bad_json",
	    "an empty name is refused, keeping one spelling for absent");

	memset(toolong, 'a', sizeof(toolong) - 1);
	toolong[sizeof(toolong) - 1] = '\0';
	(void)snprintf(line, sizeof(line),
	    "{\"id\":5,\"cmd\":\"pair\",\"name\":\"%s\"}", toolong);
	rejects(line, "bad_json", "a name over BTMGR_NAME_SIZE is refused");
}

int
main(void)
{

	test_envelope();
	test_addr();
	test_scalars();
	test_pin();
	test_name();

	if (btmgr_mc_report() != 0) {
		printf("memcheck: allocations still live\n");
		failures++;
	}

	printf("\n%d checks, %d failures\n", checks, failures);

	return (failures != 0);
}
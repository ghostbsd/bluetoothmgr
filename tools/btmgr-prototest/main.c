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
#include "state.h"

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

static int
decode(const char *line, struct proto_msg *msg)
{
	return (proto_parse_msg(line, strlen(line), msg));
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

/*
 * The encoder is the parser's inverse, so encoding then parsing must give back
 * what went in. That is the only check that actually enforces proto.h's claim
 * that the two cannot disagree.
 */
static void
round_trip(const struct proto_cmd *sent, const char *what)
{
	struct proto_cmd	 got;
	char			*line;
	char			 code[32];
	int			 same;

	line = proto_encode_cmd(sent);
	if (line == NULL) {
		ok(0, "%s (encode returned NULL)", what);
		return;
	}

	if (proto_parse_cmd(line, strlen(line), &got, code, sizeof(code)) != 0) {
		ok(0, "%s (its own output failed to parse: %s)", what, code);
		free(line);
		return;
	}

	same = got.id == sent->id &&
	    strcmp(got.name, sent->name) == 0 &&
	    got.has_addr == sent->has_addr &&
	    got.has_timeout == sent->has_timeout &&
	    got.timeout == sent->timeout &&
	    got.has_on == sent->has_on &&
	    got.on == sent->on &&
	    got.has_pin == sent->has_pin &&
	    got.has_device_name == sent->has_device_name &&
	    (!sent->has_addr ||
	    memcmp(&got.addr, &sent->addr, sizeof(got.addr)) == 0) &&
	    (!sent->has_pin || strcmp(got.pin, sent->pin) == 0) &&
	    (!sent->has_device_name ||
	    strcmp(got.device_name, sent->device_name) == 0);

	ok(same, "%s%s%s", what, same ? "" : " via ", same ? "" : line);
	free(line);
}

static void
test_encode(void)
{
	struct proto_cmd	 cmd;
	char			*line;

	printf("\nencoding commands\n");

	/* The shape of every line: one object, newline terminated, per B1.2. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.id = 1;
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	line = proto_encode_cmd(&cmd);
	ok(line != NULL, "a bare command encodes");
	if (line != NULL) {
		eq(line, "{\"id\":1,\"cmd\":\"get_state\"}\n",
		    "with no absent field emitted");
		free(line);
	}

	/* Refusals, so a malformed struct cannot reach the daemon. */
	ok(proto_encode_cmd(NULL) == NULL, "a NULL command is refused");

	memset(&cmd, 0, sizeof(cmd));
	cmd.id = -1;
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	ok(proto_encode_cmd(&cmd) == NULL, "a negative id is refused, per B3.1");

	memset(&cmd, 0, sizeof(cmd));
	cmd.id = 2;
	ok(proto_encode_cmd(&cmd) == NULL, "an empty command name is refused");

	printf("\nencode then parse\n");

	memset(&cmd, 0, sizeof(cmd));
	cmd.id = 3;
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));
	round_trip(&cmd, "get_state survives a round trip");

	memset(&cmd, 0, sizeof(cmd));
	cmd.id = 4;
	(void)strlcpy(cmd.name, "connect", sizeof(cmd.name));
	cmd.has_addr = 1;
	(void)bt_aton("aa:bb:cc:11:22:02", &cmd.addr);
	round_trip(&cmd, "connect with an address");

	memset(&cmd, 0, sizeof(cmd));
	cmd.id = 5;
	(void)strlcpy(cmd.name, "pair", sizeof(cmd.name));
	cmd.has_addr = 1;
	(void)bt_aton("aa:bb:cc:11:22:02", &cmd.addr);
	cmd.has_pin = 1;
	(void)strlcpy(cmd.pin, "0000", sizeof(cmd.pin));
	cmd.has_device_name = 1;
	(void)strlcpy(cmd.device_name, "Soundbar X900",
	    sizeof(cmd.device_name));
	round_trip(&cmd, "pair with addr, pin and name");

	/* on = false must survive, not be mistaken for absent. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.id = 6;
	(void)strlcpy(cmd.name, "set_discoverable", sizeof(cmd.name));
	cmd.has_on = 1;
	cmd.on = 0;
	round_trip(&cmd, "set_discoverable with on false, not absent");

	memset(&cmd, 0, sizeof(cmd));
	cmd.id = 7;
	(void)strlcpy(cmd.name, "set_discoverable", sizeof(cmd.name));
	cmd.has_timeout = 1;
	cmd.timeout = 0;
	round_trip(&cmd, "set_discoverable with timeout zero, not absent");

	/*
	 * The encoder refuses every PIN the parser refuses, so a frontend
	 * finds out before the round trip rather than after it.
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.id = 8;
	(void)strlcpy(cmd.name, "pair", sizeof(cmd.name));
	cmd.has_pin = 1;
	(void)strlcpy(cmd.pin, "12\"34", sizeof(cmd.pin));
	ok(proto_encode_cmd(&cmd) == NULL, "a PIN with a quote is not encodable");

	cmd.pin[0] = '\0';
	ok(proto_encode_cmd(&cmd) == NULL, "nor is an empty one");

	/* Same asymmetry for the name: the parser refuses empty, so do we. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.id = 10;
	(void)strlcpy(cmd.name, "pair", sizeof(cmd.name));
	cmd.has_device_name = 1;
	ok(proto_encode_cmd(&cmd) == NULL,
	    "an empty device name is not encodable either");

	/*
	 * An over-long PIN is unrepresentable here: cmd.pin is
	 * BTMGR_PIN_MAX + 1 bytes, so one cannot be built to encode. The
	 * parser covers that case, where the string arrives from the wire.
	 */

	/* A name with a quote is legal and must survive JSON escaping. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.id = 9;
	(void)strlcpy(cmd.name, "pair", sizeof(cmd.name));
	cmd.has_device_name = 1;
	(void)strlcpy(cmd.device_name, "a \" quote", sizeof(cmd.device_name));
	round_trip(&cmd, "a device name containing a quote survives escaping");
}

/*
 * Decoding. The strongest cases feed proto_parse_msg() the daemon's own
 * emitters rather than hand-written JSON, so the two cannot drift apart.
 */
static void
test_decode(void)
{
	struct proto_msg	 msg;
	struct state		 st;
	char			*line;

	printf("\nB3.3 decoding replies and events\n");

	/* Straight from proto_ok(), which is what the daemon really sends. */
	line = proto_ok(7);
	if (line == NULL) {
		ok(0, "proto_ok returned NULL");
		return;
	}
	ok(proto_parse_msg(line, strlen(line), &msg) == 0,
	    "the daemon's own ok reply decodes");
	ok(msg.kind == PROTO_MSG_REPLY, "as a reply");
	ok(msg.request_id == 7, "with the id it was addressed to");
	ok(msg.succeeded == 1, "and succeeded set");
	free(line);

	line = proto_error(8, "busy", "a pairing is in progress");
	if (line == NULL) {
		ok(0, "proto_error returned NULL");
		return;
	}
	ok(proto_parse_msg(line, strlen(line), &msg) == 0,
	    "the daemon's own error reply decodes");
	ok(msg.kind == PROTO_MSG_REPLY, "also as a reply");
	ok(msg.request_id == 8, "with its id");
	ok(msg.succeeded == 0, "and succeeded clear");
	eq(msg.error_code, "busy", "carrying the B6 code");
	eq(msg.error_detail, "a pairing is in progress", "and the detail");
	free(line);

	/* B2.1 needs the proto number, so hello must expose it. */
	line = proto_hello();
	if (line == NULL) {
		ok(0, "proto_hello returned NULL");
		return;
	}
	ok(proto_parse_msg(line, strlen(line), &msg) == 0, "hello decodes");
	ok(msg.kind == PROTO_MSG_EVENT, "as an event");
	eq(msg.event_name, "hello", "named hello");
	ok(msg.has_proto_version && msg.proto_version == BTMGR_PROTO_VERSION,
	    "exposing the proto version B2.1 makes the client check");
	free(line);

	printf("\nthe state event\n");

	memset(&st, 0, sizeof(st));
	st.adapter_present = 1;
	st.powered = 1;
	st.discoverable = 0;
	st.scanning = 1;
	st.config_readable = 1;
	st.nconns = 0;

	line = proto_state_event(&st);
	if (line == NULL) {
		ok(0, "proto_state_event returned NULL");
		return;
	}
	ok(proto_parse_msg(line, strlen(line), &msg) == 0, "a state event decodes");
	ok(msg.has_state, "and is marked as carrying state");
	ok(msg.state.adapter_present == 1, "adapter_present survives");
	ok(msg.state.powered == 1, "powered survives");
	ok(msg.state.discoverable == 0,
	    "discoverable false survives, not defaulted true");
	ok(msg.state.scanning == 1, "scanning survives");
	ok(msg.state.connection_count == 0, "an empty connection list counts 0");
	free(line);

	/* One connection is what flips the applet to its connected icon. */
	st.nconns = 1;
	st.conns[0].handle = 72;
	st.conns[0].acl = 1;
	line = proto_state_event(&st);
	if (line != NULL) {
		ok(proto_parse_msg(line, strlen(line), &msg) == 0,
		    "a state event with a connection decodes");
		ok(msg.state.connection_count == 1, "and counts it");
		free(line);
	}

	printf("\nmalformed and unknown\n");

	ok(decode("", &msg) == -1, "an empty line is refused");
	ok(decode("not json", &msg) == -1, "rubbish is refused");
	ok(decode("[1,2]", &msg) == -1, "an array is not a message");
	ok(decode("{\"ok\":true}", &msg) == -1,
	    "an object with neither id nor event is refused, per B3.3");

	/* An id that narrows to a pending one must not complete it. */
	ok(decode("{\"id\":4294967296,\"ok\":true}", &msg) == -1,
	    "an id past INT_MAX is refused, not truncated");
	ok(decode("{\"id\":-5,\"ok\":true}", &msg) == -1,
	    "a negative id is refused");
	ok(decode("{\"id\":2147483647,\"ok\":true}", &msg) == 0 &&
	    msg.request_id == 2147483647, "INT_MAX itself is still accepted");

	/* B3.3 makes reply and event exclusive, so both at once is malformed. */
	ok(decode("{\"id\":3,\"event\":\"state\",\"ok\":true}", &msg) == -1,
	    "a message carrying both id and event is refused");

	/* B7 will grow. An unknown event must decode, not fail. */
	ok(decode("{\"event\":\"device_found\",\"addr\":\"1:2:3:4:5:6\"}",
	    &msg) == 0, "an event this build does not know still decodes");
	ok(msg.kind == PROTO_MSG_EVENT, "as an event");
	eq(msg.event_name, "device_found", "with its name available");
	ok(msg.has_state == 0, "and no state claimed");
}

int
main(void)
{

	test_envelope();
	test_addr();
	test_scalars();
	test_pin();
	test_name();
	test_encode();
	test_decode();

	if (btmgr_mc_report() != 0) {
		printf("memcheck: allocations still live\n");
		failures++;
	}

	printf("\n%d checks, %d failures\n", checks, failures);

	return (failures != 0);
}

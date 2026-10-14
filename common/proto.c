/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * proto.c - encode and decode the IPC wire format. SPEC.md Part B.
 *
 * Built on jansson. Chosen over json-glib because it is plain C with no GLib
 * dependency, which lets this file link into the GLib-free daemon and the GTK
 * clients alike. See PLAN.md, dependencies.
 *
 * A note on jansson's reference counting, since it is the one thing that
 * surprises people. json_object_set_new() and json_array_append_new() steal
 * the reference you pass them, so the value is freed when its parent is. The
 * plain set()/append() variants do not steal, leaving you to decref yourself.
 * Everything below uses the _new() forms, so exactly one json_decref() on the
 * root frees the whole tree.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "btmgr.h"
#include "proto.h"
#include "sanitise.h"
#include "state.h"

/*
 * Must come after the system headers: it redefines malloc and friends. The
 * pragma says so to clang-include-cleaner, which sees no direct use of this
 * header because the use is macro replacement of malloc(), not a symbol.
 */
#include "memcheck.h"	/* IWYU pragma: keep */

static int	 pin_is_sendable(const char *pin);
static int	 set_string(json_t *obj, const char *key, const char *value);
static int	 read_boolean(json_t *obj, const char *key, int *out);
static char	*render(json_t *root);
static json_t	*adapter_json(const struct btmgr_adapter *a);
static json_t	*conn_json(const struct btmgr_conn *c);

/*
 * A name is cosmetic, so A7.1 transliterates it. A PIN is an exact secret and
 * hcsecd_set() runs it through the same sanitiser, so anything A7.1 would
 * rewrite is refused. Shared by both directions, so a frontend learns at once
 * rather than after a round trip.
 */
static int
pin_is_sendable(const char *pin)
{
	size_t	 i, len;

	len = strlen(pin);
	if (len == 0 || len > BTMGR_PIN_MAX)
		return (0);

	for (i = 0; i < len; i++) {
		unsigned char ch = (unsigned char)pin[i];

		if (ch == '"' || ch == '\\' || ch < 0x20 || ch == 0x7f)
			return (0);
	}

	return (1);
}

/*
 * Serialise a tree to one line, append the newline, and free the tree.
 *
 * Takes ownership of root, so callers never have to think about the failure
 * paths. Returns a malloc'd string the caller frees, or NULL.
 */
static char *
render(json_t *root)
{
	char	*body, *line;
	size_t	 len;

	if (root == NULL)
		return (NULL);

	/* JSON_COMPACT keeps lines short; the format is machine facing. */
	body = json_dumps(root, JSON_COMPACT);
	json_decref(root);
	if (body == NULL)
		return (NULL);

	len = strlen(body);

	/* +2 for the '\n' and the NUL. */
	line = malloc(len + 2);
	if (line == NULL) {
		free(body);
		return (NULL);
	}

	memcpy(line, body, len);
	line[len] = '\n';
	line[len + 1] = '\0';

	free(body);

	return (line);
}

static json_t *
adapter_json(const struct btmgr_adapter *a)
{
	char	addr[BTMGR_ADDR_STRSIZE];
	char	name[BTMGR_NAME_SIZE];
	json_t	*o;

	o = json_object();
	if (o == NULL)
		return (NULL);

	/*
	 * B1.4. a->name is whatever the controller reported. Replacing here
	 * rather than at the caller means no future filler of this struct can
	 * reintroduce a name that json_string() refuses, which would discard
	 * the whole state event and silently stop every client's updates.
	 */
	if (btmgr_sanitise_utf8(a->name, name, sizeof(name)) != 0)
		name[0] = '\0';

	if (set_string(o, "addr", bt_ntoa(&a->bdaddr, addr)) != 0 ||
	    set_string(o, "name", name) != 0 ||
	    set_string(o, "node", a->node) != 0) {
		json_decref(o);
		return (NULL);
	}

	return (o);
}

static json_t *
conn_json(const struct btmgr_conn *c)
{
	char	addr[BTMGR_ADDR_STRSIZE];
	json_t	*o;

	o = json_object();
	if (o == NULL)
		return (NULL);

	if (set_string(o, "addr", bt_ntoa(&c->bdaddr, addr)) != 0 ||
	    json_object_set_new(o, "handle", json_integer(c->handle)) != 0 ||
	    set_string(o, "link", c->acl ? "acl" : "sco") != 0 ||
	    json_object_set_new(o, "encrypted",
	    json_boolean(c->encrypted)) != 0 ||
	    set_string(o, "role", c->master ? "master" : "slave") != 0) {
		json_decref(o);
		return (NULL);
	}

	return (o);
}

/* A missing or non-boolean key is a malformed message, not a false. */
static int
read_boolean(json_t *obj, const char *key, int *out)
{
	json_t	*value = json_object_get(obj, key);

	if (!json_is_boolean(value))
		return (-1);

	*out = json_is_true(value) ? 1 : 0;

	return (0);
}

int
proto_parse_msg(const char *line, size_t len, struct proto_msg *out)
{
	json_error_t	 err;
	json_t		*root, *value;

	memset(out, 0, sizeof(*out));

	root = json_loadb(line, len, 0, &err);
	if (root == NULL)
		return (-1);
	if (!json_is_object(root)) {
		json_decref(root);
		return (-1);
	}

	value = json_object_get(root, "id");
	if (json_is_integer(value)) {
		json_int_t	 id = json_integer_value(value);

		/* B3.3 makes the two kinds exclusive. */
		if (json_is_string(json_object_get(root, "event"))) {
			json_decref(root);
			return (-1);
		}

		/*
		 * Narrowing without this check lets id 4294967296 arrive as 0
		 * and complete whichever request holds that id.
		 */
		if (id < 0 || id > INT_MAX) {
			json_decref(root);
			return (-1);
		}

		out->kind = PROTO_MSG_REPLY;
		out->request_id = (int)id;

		/* B3's envelope: a reply without ok is malformed. */
		if (read_boolean(root, "ok", &out->succeeded) != 0) {
			json_decref(root);
			return (-1);
		}

		value = json_object_get(root, "error");
		if (json_is_string(value))
			strlcpy(out->error_code, json_string_value(value),
			    sizeof(out->error_code));

		value = json_object_get(root, "detail");
		if (json_is_string(value))
			strlcpy(out->error_detail, json_string_value(value),
			    sizeof(out->error_detail));

		json_decref(root);

		return (0);
	}

	value = json_object_get(root, "event");
	if (!json_is_string(value)) {
		json_decref(root);		/* neither a reply nor an event */
		return (-1);
	}

	out->kind = PROTO_MSG_EVENT;
	strlcpy(out->event_name, json_string_value(value),
	    sizeof(out->event_name));

	value = json_object_get(root, "proto");
	if (json_is_integer(value)) {
		out->has_proto_version = 1;
		out->proto_version = (int)json_integer_value(value);
	}

	/*
	 * Every field is required. Letting a missing adapter_present default
	 * to false would make a truncated event indistinguishable from an
	 * unplugged dongle, which is what the applet hides itself for.
	 */
	if (strcmp(out->event_name, "state") == 0) {
		value = json_object_get(root, "connections");
		if (!json_is_array(value) ||
		    read_boolean(root, "adapter_present",
		    &out->state.adapter_present) != 0 ||
		    read_boolean(root, "powered", &out->state.powered) != 0 ||
		    read_boolean(root, "discoverable",
		    &out->state.discoverable) != 0 ||
		    read_boolean(root, "scanning", &out->state.scanning) != 0 ||
		    read_boolean(root, "config_readable",
		    &out->state.config_readable) != 0) {
			json_decref(root);
			return (-1);
		}

		out->state.connection_count = (int)json_array_size(value);
		out->has_state = 1;
	}

	json_decref(root);

	return (0);
}

/*
 * json_string() returns NULL for invalid UTF-8 as well as for allocation
 * failure, and set_new() then leaves the key out, so an unchecked insertion
 * renders a command with a field silently missing.
 */
static int
set_string(json_t *obj, const char *key, const char *value)
{
	json_t	*str = json_string(value);

	if (str == NULL)
		return (-1);

	/* Steals the reference even when it fails, so there is no leak. */
	return (json_object_set_new(obj, key, str));
}

char *
proto_encode_cmd(const struct proto_cmd *cmd)
{
	char	 addr[BTMGR_ADDR_STRSIZE];
	json_t	*obj;

	if (cmd == NULL || cmd->id < 0 || cmd->name[0] == '\0')
		return (NULL);
	if (cmd->has_pin && !pin_is_sendable(cmd->pin))
		return (NULL);
	/* The parser refuses an empty name, so emitting one is a doomed send. */
	if (cmd->has_device_name && cmd->device_name[0] == '\0')
		return (NULL);

	obj = json_object();
	if (obj == NULL)
		return (NULL);

	if (json_object_set_new(obj, "id", json_integer(cmd->id)) != 0 ||
	    set_string(obj, "cmd", cmd->name) != 0)
		goto fail;

	if (cmd->has_addr &&
	    set_string(obj, "addr", bt_ntoa(&cmd->addr, addr)) != 0)
		goto fail;
	if (cmd->has_timeout &&
	    json_object_set_new(obj, "timeout",
	    json_integer(cmd->timeout)) != 0)
		goto fail;
	if (cmd->has_on &&
	    json_object_set_new(obj, "on", json_boolean(cmd->on)) != 0)
		goto fail;
	if (cmd->has_pin && set_string(obj, "pin", cmd->pin) != 0)
		goto fail;
	if (cmd->has_device_name &&
	    set_string(obj, "name", cmd->device_name) != 0)
		goto fail;

	return (render(obj));

fail:
	json_decref(obj);

	return (NULL);
}

char *
proto_hello(void)
{
	json_t	*o;

	o = json_object();
	if (o == NULL)
		return (NULL);

	if (set_string(o, "event", "hello") != 0 ||
	    json_object_set_new(o, "proto",
	    json_integer(BTMGR_PROTO_VERSION)) != 0 ||
	    set_string(o, "daemon", "bluetoothmgr/0.1.0") != 0) {
		json_decref(o);
		return (NULL);
	}

	return (render(o));
}

/*
 * The state event. SPEC.md B5.
 *
 * The devices array is empty in M2 and grows in M3, when the daemon can read
 * hcsecd.conf and merge paired devices with live connections. Until then
 * config_readable tells clients why it is empty.
 */
char *
proto_state_event(const struct state *st)
{
	json_t	*o, *devices, *conns, *adapter, *one;
	int	 i;

	o = json_object();
	if (o == NULL)
		return (NULL);

	if (set_string(o, "event", "state") != 0 ||
	    json_object_set_new(o, "adapter_present",
	    json_boolean(st->adapter_present)) != 0 ||
	    json_object_set_new(o, "powered",
	    json_boolean(st->powered)) != 0 ||
	    json_object_set_new(o, "discoverable",
	    json_boolean(st->discoverable)) != 0 ||
	    json_object_set_new(o, "scanning",
	    json_boolean(st->scanning)) != 0 ||
	    json_object_set_new(o, "config_readable",
	    json_boolean(st->config_readable)) != 0)
		goto fail;

	adapter = st->adapter_present ? adapter_json(&st->adapter) :
	    json_null();
	if (adapter == NULL || json_object_set_new(o, "adapter", adapter) != 0)
		goto fail;

	/* Inserted before filling, so the array is owned by o on any failure. */
	conns = json_array();
	if (conns == NULL || json_object_set_new(o, "connections", conns) != 0)
		goto fail;
	for (i = 0; i < st->nconns; i++) {
		one = conn_json(&st->conns[i]);
		if (one == NULL || json_array_append_new(conns, one) != 0)
			goto fail;
	}

	devices = json_array();
	if (devices == NULL ||
	    json_object_set_new(o, "devices", devices) != 0)
		goto fail;

	return (render(o));

fail:
	json_decref(o);

	return (NULL);
}

char *
proto_ok(int id)
{
	json_t	*o;

	o = json_object();
	if (o == NULL)
		return (NULL);

	if (json_object_set_new(o, "id", json_integer(id)) != 0 ||
	    json_object_set_new(o, "ok", json_true()) != 0) {
		json_decref(o);
		return (NULL);
	}

	return (render(o));
}

char *
proto_error(int id, const char *code, const char *detail)
{
	json_t	*o;

	o = json_object();
	if (o == NULL)
		return (NULL);

	if (json_object_set_new(o, "id", json_integer(id)) != 0 ||
	    json_object_set_new(o, "ok", json_false()) != 0 ||
	    set_string(o, "error", code) != 0 ||
	    (detail != NULL && set_string(o, "detail", detail) != 0)) {
		json_decref(o);
		return (NULL);
	}

	return (render(o));
}

/*
 * Parse one line into a command.
 *
 * The line is not NUL terminated, so we use json_loadb() which takes a length.
 * That matters: the caller hands us a slice of its input buffer, and copying
 * it just to append a NUL would be wasted work on every command.
 */
int
proto_parse_cmd(const char *line, size_t len, struct proto_cmd *out,
    char *code, size_t codelen)
{
	json_error_t	 err;
	json_t		*root, *v;
	const char	*name;

	memset(out, 0, sizeof(*out));
	out->id = -1;

	root = json_loadb(line, len, 0, &err);
	if (root == NULL) {
		strlcpy(code, "bad_json", codelen);
		return (-1);
	}

	if (!json_is_object(root)) {
		strlcpy(code, "bad_json", codelen);
		json_decref(root);
		return (-1);
	}

	/*
	 * Recover the id first, even if the rest is malformed, so the error
	 * reply can be matched to the request that caused it. SPEC.md B3.1.
	 */
	v = json_object_get(root, "id");
	if (json_is_integer(v))
		out->id = (int)json_integer_value(v);

	if (out->id < 0) {
		strlcpy(code, "missing_id", codelen);
		json_decref(root);
		return (-1);
	}

	v = json_object_get(root, "cmd");
	if (!json_is_string(v)) {
		strlcpy(code, "missing_cmd", codelen);
		json_decref(root);
		return (-1);
	}

	name = json_string_value(v);
	if (strlcpy(out->name, name, sizeof(out->name)) >=
	    sizeof(out->name)) {
		strlcpy(code, "not_found", codelen);
		json_decref(root);
		return (-1);
	}

	/*
	 * Optional fields. A malformed one is an error rather than something
	 * to ignore: silently treating {"addr": 42} as absent would connect
	 * to whatever the caller last mentioned, or to nothing, with no
	 * explanation.
	 */
	v = json_object_get(root, "addr");
	if (v != NULL) {
		if (!json_is_string(v) ||
		    !bt_aton(json_string_value(v), &out->addr)) {
			strlcpy(code, "bad_addr", codelen);
			json_decref(root);
			return (-1);
		}
		out->has_addr = 1;
	}

	v = json_object_get(root, "timeout");
	if (v != NULL) {
		if (!json_is_integer(v)) {
			strlcpy(code, "bad_json", codelen);
			json_decref(root);
			return (-1);
		}
		out->timeout = (int)json_integer_value(v);
		out->has_timeout = 1;
	}

	v = json_object_get(root, "on");
	if (v != NULL) {
		if (!json_is_boolean(v)) {
			strlcpy(code, "bad_json", codelen);
			json_decref(root);
			return (-1);
		}
		out->on = json_is_true(v) ? 1 : 0;
		out->has_on = 1;
	}

	/*
	 * A name is cosmetic, so A7.1 transliterates it. A PIN is an exact
	 * secret, and hcsecd_set() runs it through the same sanitiser, so
	 * anything A7.1 would rewrite is refused here instead.
	 */
	v = json_object_get(root, "pin");
	if (v != NULL) {
		const char	*pin;
		size_t		 len;

		if (!json_is_string(v)) {
			strlcpy(code, "bad_json", codelen);
			json_decref(root);
			return (-1);
		}

		pin = json_string_value(v);

		/* Absent is how "this device needs no PIN" is spelled. */
		if (!pin_is_sendable(pin)) {
			strlcpy(code, "bad_json", codelen);
			json_decref(root);
			return (-1);
		}

		len = strlen(pin);
		memcpy(out->pin, pin, len + 1);
		out->has_pin = 1;
	}

	/* jansson rejects invalid UTF-8, so B1.4 is settled before we see it. */
	v = json_object_get(root, "name");
	if (v != NULL) {
		const char	*nm;

		if (!json_is_string(v)) {
			strlcpy(code, "bad_json", codelen);
			json_decref(root);
			return (-1);
		}

		nm = json_string_value(v);

		/* Absent is how "no name" is spelled, as with pin. */
		if (nm[0] == '\0' ||
		    strlcpy(out->device_name, nm, sizeof(out->device_name)) >=
		    sizeof(out->device_name)) {
			strlcpy(code, "bad_json", codelen);
			json_decref(root);
			return (-1);
		}
		out->has_device_name = 1;
	}

	json_decref(root);

	return (0);
}

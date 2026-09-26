/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * proto.c - encode and decode the IPC wire format. SPEC.md Part B.
 *
 * Built on jansson. Chosen over json-glib because it is plain C with no GLib
 * dependency, which lets this file link into the GLib-free daemon and the GTK
 * clients alike. See PLAN.md section 7.
 *
 * A note on jansson's reference counting, since it is the one thing that
 * surprises people. json_object_set_new() and json_array_append_new() steal
 * the reference you pass them, so the value is freed when its parent is. The
 * plain set()/append() variants do not steal, leaving you to decref yourself.
 * Everything below uses the _new() forms, so exactly one json_decref() on the
 * root frees the whole tree.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "proto.h"

static char	*render(json_t *root);
static json_t	*adapter_json(const struct btmgr_adapter *a);
static json_t	*conn_json(const struct btmgr_conn *c);

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
	json_t	*o;

	o = json_object();
	if (o == NULL)
		return (NULL);

	json_object_set_new(o, "addr",
	    json_string(bt_ntoa(&a->bdaddr, addr)));
	json_object_set_new(o, "name", json_string(a->name));
	json_object_set_new(o, "node", json_string(a->node));

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

	json_object_set_new(o, "addr",
	    json_string(bt_ntoa(&c->bdaddr, addr)));
	json_object_set_new(o, "handle", json_integer(c->handle));
	json_object_set_new(o, "link", json_string(c->acl ? "acl" : "sco"));
	json_object_set_new(o, "encrypted", json_boolean(c->encrypted));
	json_object_set_new(o, "role",
	    json_string(c->master ? "master" : "slave"));

	return (o);
}

char *
proto_hello(void)
{
	json_t	*o;

	o = json_object();
	if (o == NULL)
		return (NULL);

	json_object_set_new(o, "event", json_string("hello"));
	json_object_set_new(o, "proto", json_integer(BTMGR_PROTO_VERSION));
	json_object_set_new(o, "daemon", json_string("bluetoothmgr/0.1.0"));

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
	json_t	*o, *devices, *conns;
	int	 i;

	o = json_object();
	if (o == NULL)
		return (NULL);

	json_object_set_new(o, "event", json_string("state"));
	json_object_set_new(o, "adapter_present",
	    json_boolean(st->adapter_present));
	json_object_set_new(o, "powered", json_boolean(st->powered));
	json_object_set_new(o, "discoverable",
	    json_boolean(st->discoverable));
	json_object_set_new(o, "scanning", json_boolean(st->scanning));
	json_object_set_new(o, "config_readable",
	    json_boolean(st->config_readable));

	if (st->adapter_present)
		json_object_set_new(o, "adapter", adapter_json(&st->adapter));
	else
		json_object_set_new(o, "adapter", json_null());

	conns = json_array();
	for (i = 0; i < st->nconns; i++)
		json_array_append_new(conns, conn_json(&st->conns[i]));
	json_object_set_new(o, "connections", conns);

	devices = json_array();
	json_object_set_new(o, "devices", devices);

	return (render(o));
}

char *
proto_ok(int id)
{
	json_t	*o;

	o = json_object();
	if (o == NULL)
		return (NULL);

	json_object_set_new(o, "id", json_integer(id));
	json_object_set_new(o, "ok", json_true());

	return (render(o));
}

char *
proto_error(int id, const char *code, const char *detail)
{
	json_t	*o;

	o = json_object();
	if (o == NULL)
		return (NULL);

	json_object_set_new(o, "id", json_integer(id));
	json_object_set_new(o, "ok", json_false());
	json_object_set_new(o, "error", json_string(code));
	if (detail != NULL)
		json_object_set_new(o, "detail", json_string(detail));

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

	json_decref(root);

	return (0);
}
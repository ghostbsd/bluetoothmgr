/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * store.c - /var/db/bluetoothmgr/devices.json. SPEC.md A4.
 *
 * See store.h for why A0.4 does not apply to this one file.
 *
 * jansson conventions follow common/proto.c: the _new() setters steal the
 * reference they are given, so exactly one json_decref() on the root releases
 * the lot.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "btaddr.h"
#include "store.h"

/*
 * Must come after the system headers: it redefines malloc and friends. The
 * pragma says so to clang-include-cleaner, which sees no direct use of this
 * header because the use is macro replacement of malloc(), not a symbol.
 */
#include "memcheck.h"	/* IWYU pragma: keep */

struct dev {
	uint8_t		 addr[BTMGR_ADDR_LEN];
	char		*name;
	char		*alias;
	char		*type;
	int64_t		 first_seen;
	int64_t		 last_connected;
	int		 auto_connect;
	int		 deleted;
};

struct store {
	struct dev	*d;
	size_t		 n;
	size_t		 cap;
	int		 dirty;
};

static struct dev *find_dev(const struct store *st, const uint8_t *addr);
static struct dev *push_dev(struct store *st);
static int	 set_str(char **slot, const char *val, int *changed);

struct store *
store_new(void)
{

	return (calloc(1, sizeof(struct store)));
}

static struct dev *
push_dev(struct store *st)
{
	struct dev	*p;
	size_t		 cap;

	if (st->n == st->cap) {
		cap = st->cap == 0 ? 8 : st->cap * 2;
		p = realloc(st->d, cap * sizeof(*p));
		if (p == NULL)
			return (NULL);
		st->d = p;
		st->cap = cap;
	}

	p = &st->d[st->n++];
	memset(p, 0, sizeof(*p));

	return (p);
}

static struct dev *
find_dev(const struct store *st, const uint8_t *addr)
{
	size_t	 i;

	for (i = 0; i < st->n; i++)
		if (!st->d[i].deleted &&
		    memcmp(st->d[i].addr, addr, BTMGR_ADDR_LEN) == 0)
			return (&st->d[i]);

	return (NULL);
}

/* Replace *slot with a copy of val, noting whether anything actually moved. */
static int
set_str(char **slot, const char *val, int *changed)
{
	char	*dup;

	if (val == NULL)
		return (0);
	if (*slot != NULL && strcmp(*slot, val) == 0)
		return (0);

	dup = strdup(val);
	if (dup == NULL)
		return (-1);

	free(*slot);
	*slot = dup;
	*changed = 1;

	return (0);
}

struct store *
store_parse(const char *text, int *malformed, size_t *skipped)
{
	struct store	*st;
	json_t		*root, *ver, *devs;
	json_error_t	 err;
	size_t		 i, nskip = 0;

	if (malformed != NULL)
		*malformed = 0;
	if (skipped != NULL)
		*skipped = 0;

	st = store_new();
	if (st == NULL)
		return (NULL);

	if (text == NULL || *text == '\0')
		return (st);

	root = json_loads(text, 0, &err);
	if (root == NULL || !json_is_object(root))
		goto bad;

	/* A4.2. A version we do not know how to read is not ours to rewrite. */
	ver = json_object_get(root, "version");
	if (!json_is_integer(ver) ||
	    json_integer_value(ver) > STORE_VERSION ||
	    json_integer_value(ver) < 1)
		goto bad;

	devs = json_object_get(root, "devices");
	if (devs == NULL) {
		/* A file with no devices at all is empty, not malformed. */
		json_decref(root);
		return (st);
	}
	if (!json_is_array(devs))
		goto bad;

	for (i = 0; i < json_array_size(devs); i++) {
		json_t		*o = json_array_get(devs, i);
		json_t		*f;
		const char	*as;
		struct dev	*d;
		uint8_t		 addr[BTMGR_ADDR_LEN];

		if (!json_is_object(o)) {
			nskip++;
			continue;
		}

		f = json_object_get(o, "addr");
		if (!json_is_string(f)) {
			nskip++;
			continue;
		}
		as = json_string_value(f);
		if (btmgr_addr_parse(as, strlen(as), addr) != 0) {
			nskip++;
			continue;
		}

		/* A duplicate address would give two records for one device. */
		if (find_dev(st, addr) != NULL) {
			nskip++;
			continue;
		}

		d = push_dev(st);
		if (d == NULL) {
			json_decref(root);
			store_free(st);
			return (NULL);
		}
		memcpy(d->addr, addr, BTMGR_ADDR_LEN);

		/*
		 * Only these fields are read. A4.1: a "pin" or "key" that
		 * somehow reached the file is ignored here and therefore gone
		 * from the next write.
		 */
		f = json_object_get(o, "name");
		if (json_is_string(f))
			d->name = strdup(json_string_value(f));
		f = json_object_get(o, "alias");
		if (json_is_string(f))
			d->alias = strdup(json_string_value(f));
		f = json_object_get(o, "type");
		if (json_is_string(f))
			d->type = strdup(json_string_value(f));
		f = json_object_get(o, "first_seen");
		if (json_is_integer(f))
			d->first_seen = json_integer_value(f);
		f = json_object_get(o, "last_connected");
		if (json_is_integer(f))
			d->last_connected = json_integer_value(f);
		f = json_object_get(o, "auto_connect");
		if (json_is_boolean(f))
			d->auto_connect = json_is_true(f);
	}

	json_decref(root);

	if (skipped != NULL)
		*skipped = nskip;

	return (st);

bad:
	if (root != NULL)
		json_decref(root);
	if (malformed != NULL)
		*malformed = 1;

	/* A4.3: an empty store, so the daemon carries on. */
	store_free(st);

	return (store_new());
}

void
store_free(struct store *st)
{
	size_t	 i;

	if (st == NULL)
		return;

	for (i = 0; i < st->n; i++) {
		free(st->d[i].name);
		free(st->d[i].alias);
		free(st->d[i].type);
	}

	free(st->d);
	free(st);
}

int
store_dirty(const struct store *st)
{

	return (st->dirty);
}

size_t
store_count(const struct store *st)
{
	size_t	 i, n = 0;

	for (i = 0; i < st->n; i++)
		if (!st->d[i].deleted)
			n++;

	return (n);
}

int
store_has(const struct store *st, const uint8_t *addr)
{

	return (find_dev(st, addr) != NULL);
}

const char *
store_name(const struct store *st, const uint8_t *addr)
{
	struct dev	*d = find_dev(st, addr);

	return (d == NULL ? NULL : d->name);
}

const char *
store_alias(const struct store *st, const uint8_t *addr)
{
	struct dev	*d = find_dev(st, addr);

	return (d == NULL ? NULL : d->alias);
}

const char *
store_type(const struct store *st, const uint8_t *addr)
{
	struct dev	*d = find_dev(st, addr);

	return (d == NULL ? NULL : d->type);
}

int64_t
store_first_seen(const struct store *st, const uint8_t *addr)
{
	struct dev	*d = find_dev(st, addr);

	return (d == NULL ? 0 : d->first_seen);
}

int64_t
store_last_connected(const struct store *st, const uint8_t *addr)
{
	struct dev	*d = find_dev(st, addr);

	return (d == NULL ? 0 : d->last_connected);
}

int
store_auto_connect(const struct store *st, const uint8_t *addr)
{
	struct dev	*d = find_dev(st, addr);

	return (d == NULL ? 0 : d->auto_connect);
}

size_t
store_addrs(const struct store *st, uint8_t (*out)[BTMGR_ADDR_LEN], size_t max)
{
	size_t	 i, n = 0;

	for (i = 0; i < st->n; i++) {
		if (st->d[i].deleted)
			continue;
		if (out != NULL && n < max)
			memcpy(out[n], st->d[i].addr, BTMGR_ADDR_LEN);
		n++;
	}

	return (n);
}

enum store_result
store_set(struct store *st, const uint8_t *addr, const char *name,
    const char *alias, const char *type, int64_t now)
{
	struct dev	*d;
	int		 changed = 0;

	d = find_dev(st, addr);
	if (d == NULL) {
		d = push_dev(st);
		if (d == NULL)
			return (STORE_ERROR);
		memcpy(d->addr, addr, BTMGR_ADDR_LEN);
		d->first_seen = now;
		changed = 1;
	}

	if (set_str(&d->name, name, &changed) != 0 ||
	    set_str(&d->alias, alias, &changed) != 0 ||
	    set_str(&d->type, type, &changed) != 0)
		return (STORE_ERROR);

	if (!changed)
		return (STORE_UNCHANGED);

	st->dirty = 1;

	return (STORE_CHANGED);
}

enum store_result
store_touch_connected(struct store *st, const uint8_t *addr, int64_t when)
{
	struct dev	*d = find_dev(st, addr);

	if (d == NULL)
		return (STORE_ABSENT);
	if (d->last_connected == when)
		return (STORE_UNCHANGED);

	d->last_connected = when;
	st->dirty = 1;

	return (STORE_CHANGED);
}

enum store_result
store_set_auto_connect(struct store *st, const uint8_t *addr, int on)
{
	struct dev	*d = find_dev(st, addr);

	if (d == NULL)
		return (STORE_ABSENT);
	if (d->auto_connect == !!on)
		return (STORE_UNCHANGED);

	d->auto_connect = !!on;
	st->dirty = 1;

	return (STORE_CHANGED);
}

enum store_result
store_remove(struct store *st, const uint8_t *addr)
{
	struct dev	*d = find_dev(st, addr);

	if (d == NULL)
		return (STORE_ABSENT);

	d->deleted = 1;
	st->dirty = 1;

	return (STORE_CHANGED);
}

char *
store_emit(const struct store *st, size_t *lenp)
{
	json_t	*root, *devs;
	char	*body, *out;
	size_t	 i, len;

	root = json_object();
	devs = json_array();
	if (root == NULL || devs == NULL) {
		json_decref(root);
		json_decref(devs);
		return (NULL);
	}

	json_object_set_new(root, "version", json_integer(STORE_VERSION));
	json_object_set_new(root, "devices", devs);

	for (i = 0; i < st->n; i++) {
		struct dev	*d = &st->d[i];
		json_t		*o;
		char		 as[BTMGR_ADDR_BUFSZ];

		if (d->deleted)
			continue;

		o = json_object();
		if (o == NULL) {
			json_decref(root);
			return (NULL);
		}

		btmgr_addr_format(d->addr, as, sizeof(as));
		json_object_set_new(o, "addr", json_string(as));
		json_object_set_new(o, "name",
		    d->name == NULL ? json_null() : json_string(d->name));
		json_object_set_new(o, "alias",
		    d->alias == NULL ? json_null() : json_string(d->alias));
		json_object_set_new(o, "type",
		    d->type == NULL ? json_null() : json_string(d->type));
		json_object_set_new(o, "first_seen",
		    json_integer(d->first_seen));
		json_object_set_new(o, "last_connected",
		    json_integer(d->last_connected));
		json_object_set_new(o, "auto_connect",
		    json_boolean(d->auto_connect));

		json_array_append_new(devs, o);
	}

	/*
	 * Sorted keys and a fixed indent, so one model always renders to the
	 * same bytes. Without that, A0.5 could never report "unchanged" and
	 * every run would rewrite the file and trigger a reload.
	 */
	body = json_dumps(root, JSON_INDENT(2) | JSON_SORT_KEYS);
	json_decref(root);

	if (body == NULL)
		return (NULL);

	/* json_dumps() omits the trailing newline. */
	len = strlen(body);
	out = malloc(len + 2);
	if (out == NULL) {
		free(body);
		return (NULL);
	}
	memcpy(out, body, len);
	out[len] = '\n';
	out[len + 1] = '\0';
	free(body);

	if (lenp != NULL)
		*lenp = len + 1;

	return (out);
}

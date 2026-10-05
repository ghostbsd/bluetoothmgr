/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * keys.c - /var/db/hcsecd.keys, read-mostly. SPEC.md A3.
 *
 * See keys.h for the four parse rules and for why there is no setter.
 *
 * A record is a line, kept as its original bytes. Only the address is parsed,
 * so the key material is never decoded here and cannot leak through this
 * module. Deleting one record is then just dropping one line.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "btaddr.h"
#include "keys.h"

/*
 * Must come after the system headers: it redefines malloc and friends. The
 * pragma says so to clang-include-cleaner, which sees no direct use of this
 * header because the use is macro replacement of malloc(), not a symbol.
 */
#include "memcheck.h"	/* IWYU pragma: keep */

struct line {
	char		*raw;		/* original bytes, no newline */
	int		 is_record;
	int		 deleted;
	uint8_t		 addr[BTMGR_ADDR_LEN];
};

struct keys_db {
	struct line	*lines;
	size_t		 n;
	size_t		 cap;
	int		 dirty;
};

static char	*dupn(const char *s, size_t n);
static struct line *push_line(struct keys_db *db);
static int	 split_record(const char *raw, struct line *out);

/* strndup() with malloc(), so memcheck.h can see it. */
static char *
dupn(const char *s, size_t n)
{
	char	*p;

	p = malloc(n + 1);
	if (p == NULL)
		return (NULL);

	memcpy(p, s, n);
	p[n] = '\0';

	return (p);
}

static struct line *
push_line(struct keys_db *db)
{
	struct line	*p;
	size_t		 cap;

	if (db->n == db->cap) {
		cap = db->cap == 0 ? 16 : db->cap * 2;
		p = realloc(db->lines, cap * sizeof(*p));
		if (p == NULL)
			return (NULL);
		db->lines = p;
		db->cap = cap;
	}

	p = &db->lines[db->n++];
	memset(p, 0, sizeof(*p));

	return (p);
}

/*
 * Is this line a record hcsecd would load? Rules 1 to 4 from keys.h, in the
 * order read_keys_file() applies them.
 */
static int
split_record(const char *raw, struct line *out)
{
	const char	*sp;

	if (raw[0] == '#')
		return (-1);

	sp = strchr(raw, ' ');
	if (sp == NULL)
		return (-1);

	if (btmgr_addr_parse(raw, (size_t)(sp - raw), out->addr) != 0)
		return (-1);

	out->is_record = 1;

	return (0);
}

struct keys_db *
keys_parse(const char *text)
{
	struct keys_db	*db;
	const char	*p, *nl;

	db = calloc(1, sizeof(*db));
	if (db == NULL)
		return (NULL);

	for (p = text; p != NULL && *p != '\0';
	    p = (nl == NULL ? NULL : nl + 1)) {
		struct line	*l;

		nl = strchr(p, '\n');

		l = push_line(db);
		if (l == NULL)
			goto fail;

		l->raw = nl == NULL ? strdup(p) : dupn(p, (size_t)(nl - p));
		if (l->raw == NULL)
			goto fail;

		(void)split_record(l->raw, l);
	}

	return (db);

fail:
	keys_free(db);

	return (NULL);
}

void
keys_free(struct keys_db *db)
{
	size_t	 i;

	if (db == NULL)
		return;

	for (i = 0; i < db->n; i++)
		free(db->lines[i].raw);

	free(db->lines);
	free(db);
}

int
keys_dirty(const struct keys_db *db)
{

	return (db->dirty);
}

size_t
keys_count(const struct keys_db *db)
{
	size_t	 i, n = 0;

	for (i = 0; i < db->n; i++)
		if (db->lines[i].is_record && !db->lines[i].deleted)
			n++;

	return (n);
}

int
keys_has(const struct keys_db *db, const uint8_t *addr)
{
	size_t	 i;

	for (i = 0; i < db->n; i++) {
		struct line	*l = &db->lines[i];

		if (l->is_record && !l->deleted &&
		    memcmp(l->addr, addr, BTMGR_ADDR_LEN) == 0)
			return (1);
	}

	return (0);
}

size_t
keys_addrs(const struct keys_db *db, uint8_t (*out)[BTMGR_ADDR_LEN], size_t max)
{
	size_t	 i, n = 0;

	for (i = 0; i < db->n; i++) {
		struct line	*l = &db->lines[i];

		if (!l->is_record || l->deleted)
			continue;
		if (out != NULL && n < max)
			memcpy(out[n], l->addr, BTMGR_ADDR_LEN);
		n++;
	}

	return (n);
}

enum keys_result
keys_remove(struct keys_db *db, const uint8_t *addr)
{
	size_t	 i;
	int	 found = 0;

	for (i = 0; i < db->n; i++) {
		struct line	*l = &db->lines[i];

		if (!l->is_record || l->deleted)
			continue;
		if (memcmp(l->addr, addr, BTMGR_ADDR_LEN) != 0)
			continue;

		/*
		 * Every matching record goes. hcsecd's get_key() would use only
		 * the first, so a duplicate left behind would silently become
		 * the live key the moment the first was removed.
		 */
		l->deleted = 1;
		db->dirty = 1;
		found = 1;
	}

	return (found ? KEYS_CHANGED : KEYS_UNCHANGED);
}

char *
keys_emit(const struct keys_db *db, size_t *lenp)
{
	char	*buf, *p;
	size_t	 i, cap, len;

	cap = 1;
	for (i = 0; i < db->n; i++)
		if (!db->lines[i].deleted)
			cap += strlen(db->lines[i].raw) + 1;

	buf = malloc(cap);
	if (buf == NULL)
		return (NULL);

	p = buf;
	for (i = 0; i < db->n; i++) {
		struct line	*l = &db->lines[i];

		if (l->deleted)
			continue;

		len = strlen(l->raw);
		memcpy(p, l->raw, len);
		p += len;
		*p++ = '\n';
	}
	*p = '\0';

	if (lenp != NULL)
		*lenp = (size_t)(p - buf);

	return (buf);
}

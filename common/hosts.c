/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * hosts.c - /etc/bluetooth/hosts ownership. SPEC.md A2, under the A0 rules.
 *
 * See hosts.h for the model and for the three bt_gethostent() constraints the
 * emitter has to respect.
 *
 * The model is the file's lines in order. A line we have not touched keeps its
 * original bytes, which is both A0.4 and what makes A0.5 reachable: on a run
 * that changes nothing the emitted file is identical and safefile_write() does
 * not write at all.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "btaddr.h"
#include "hosts.h"
#include "sanitise.h"

/*
 * Must come after the system headers: it redefines malloc and friends. The
 * pragma says so to clang-include-cleaner, which sees no direct use of this
 * header because the use is macro replacement of malloc(), not a symbol.
 */
#include "memcheck.h"	/* IWYU pragma: keep */

/* How far the A2.4 search goes before giving up. */
#define	ALIAS_MAX_TRIES		1000

struct line {
	char		*raw;		/* original bytes, no newline */
	int		 is_record;
	int		 managed;	/* our marker was on the line before */
	int		 authored;	/* we wrote or rewrote it; emit canonical */
	int		 deleted;
	uint8_t		 addr[6];
	char		*alias;		/* the Name field */
	char		*extra;		/* further aliases, verbatim, or NULL */
};

struct hosts_db {
	struct line	*lines;
	size_t		 n;
	size_t		 cap;
	int		 dirty;
};

static char	*dupn(const char *s, size_t n);
static int	 split_record(const char *raw, struct line *out);
static struct line *push_line(struct hosts_db *db);
static struct line *find_addr(const struct hosts_db *db, const uint8_t *addr);
static int	 alias_taken(const struct hosts_db *db, const char *alias,
		     const uint8_t *except);
static int	 is_marker(const char *raw);
static void	 free_line(struct line *l);

/*
 * strndup() with malloc(), so that memcheck.h sees it. memcheck intercepts
 * malloc and strdup but not strndup, and an allocation it cannot see is an
 * allocation whose leak it cannot report.
 */
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

/* Is this line our ownership marker? Leading whitespace is tolerated. */
static int
is_marker(const char *raw)
{

	while (*raw == ' ' || *raw == '\t')
		raw++;

	return (strcmp(raw, HOSTS_MARKER) == 0);
}

/*
 * Split one line into address, Name and any further aliases. Returns 0 if it
 * is a record, -1 if it is anything else, in which case it stays opaque.
 *
 * A '#' anywhere ends the record, matching bt_gethostent(), so a trailing
 * comment does not become part of an alias. Such a line is left opaque rather
 * than modelled, since re-emitting it canonically would drop the comment and
 * A0.4 forbids that.
 */
static int
split_record(const char *raw, struct line *out)
{
	const char	*p, *addr_start, *alias_start;
	size_t		 addr_len, alias_len;

	if (strchr(raw, '#') != NULL)
		return (-1);

	p = raw;
	while (*p == ' ' || *p == '\t')
		p++;

	addr_start = p;
	while (*p != '\0' && *p != ' ' && *p != '\t')
		p++;
	addr_len = (size_t)(p - addr_start);

	if (addr_len == 0 || btmgr_addr_parse(addr_start, addr_len, out->addr) != 0)
		return (-1);

	while (*p == ' ' || *p == '\t')
		p++;

	alias_start = p;
	while (*p != '\0' && *p != ' ' && *p != '\t')
		p++;
	alias_len = (size_t)(p - alias_start);

	if (alias_len == 0)
		return (-1);	/* an address with no name is not a record */

	out->alias = dupn(alias_start, alias_len);
	if (out->alias == NULL)
		return (-1);

	while (*p == ' ' || *p == '\t')
		p++;

	if (*p != '\0') {
		out->extra = strdup(p);
		if (out->extra == NULL) {
			free(out->alias);
			out->alias = NULL;
			return (-1);
		}
	}

	out->is_record = 1;

	return (0);
}

static void
free_line(struct line *l)
{

	free(l->raw);
	free(l->alias);
	free(l->extra);
}

static struct line *
push_line(struct hosts_db *db)
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

struct hosts_db *
hosts_parse(const char *text)
{
	struct hosts_db	*db;
	struct line	*l;
	const char	*p, *nl;
	int		 pending_marker;

	db = calloc(1, sizeof(*db));
	if (db == NULL)
		return (NULL);

	pending_marker = 0;

	for (p = text; p != NULL && *p != '\0'; p = (nl == NULL ? NULL : nl + 1)) {
		nl = strchr(p, '\n');

		l = push_line(db);
		if (l == NULL) {
			hosts_free(db);
			return (NULL);
		}

		l->raw = nl == NULL ? strdup(p) : dupn(p, (size_t)(nl - p));
		if (l->raw == NULL) {
			hosts_free(db);
			return (NULL);
		}

		if (split_record(l->raw, l) == 0) {
			l->managed = pending_marker;
			pending_marker = 0;
		} else
			pending_marker = is_marker(l->raw);
	}

	return (db);
}

void
hosts_free(struct hosts_db *db)
{
	size_t	 i;

	if (db == NULL)
		return;

	for (i = 0; i < db->n; i++)
		free_line(&db->lines[i]);

	free(db->lines);
	free(db);
}

int
hosts_dirty(const struct hosts_db *db)
{

	return (db->dirty);
}

static struct line *
find_addr(const struct hosts_db *db, const uint8_t *addr)
{
	size_t	 i;

	for (i = 0; i < db->n; i++) {
		struct line *l = &db->lines[i];

		if (l->is_record && !l->deleted &&
		    memcmp(l->addr, addr, 6) == 0)
			return (l);
	}

	return (NULL);
}

const char *
hosts_alias_for(const struct hosts_db *db, const uint8_t *addr)
{
	struct line	*l = find_addr(db, addr);

	return (l == NULL ? NULL : l->alias);
}

int
hosts_is_managed(const struct hosts_db *db, const uint8_t *addr)
{
	struct line	*l = find_addr(db, addr);

	return (l != NULL && l->managed);
}

/*
 * Is alias already used by some other record? Case-insensitively, because
 * bt_gethostbyname() compares with strcasecmp(), and across the further
 * aliases too, since those are equally resolvable.
 */
static int
alias_taken(const struct hosts_db *db, const char *alias, const uint8_t *except)
{
	size_t	 i;

	for (i = 0; i < db->n; i++) {
		struct line	*l = &db->lines[i];
		const char	*p;

		if (!l->is_record || l->deleted)
			continue;
		if (except != NULL && memcmp(l->addr, except, 6) == 0)
			continue;
		if (strcasecmp(l->alias, alias) == 0)
			return (1);

		for (p = l->extra; p != NULL && *p != '\0'; ) {
			const char	*start = p;
			size_t		 len;

			while (*p != '\0' && *p != ' ' && *p != '\t')
				p++;
			len = (size_t)(p - start);

			if (len == strlen(alias) &&
			    strncasecmp(start, alias, len) == 0)
				return (1);

			while (*p == ' ' || *p == '\t')
				p++;
		}
	}

	return (0);
}

int
hosts_alloc_alias(const struct hosts_db *db, const char *name,
    const uint8_t *addr, char *out, size_t outlen)
{
	char		 stem[BTMGR_ALIAS_BUFSZ];
	unsigned int	 n;

	if (btmgr_alias_from_name(name, addr, stem, sizeof(stem)) != 0)
		return (-1);

	if (outlen < BTMGR_ALIAS_BUFSZ) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	if (!alias_taken(db, stem, addr)) {
		memcpy(out, stem, strlen(stem) + 1);
		return (0);
	}

	for (n = 2; n < ALIAS_MAX_TRIES; n++) {
		char	 cand[BTMGR_ALIAS_BUFSZ];

		if (btmgr_alias_with_suffix(stem, n, cand, sizeof(cand)) != 0)
			return (-1);
		if (!alias_taken(db, cand, addr)) {
			memcpy(out, cand, strlen(cand) + 1);
			return (0);
		}
	}

	errno = EADDRNOTAVAIL;

	return (-1);
}

enum hosts_result
hosts_set(struct hosts_db *db, const uint8_t *addr, const char *alias,
    int force)
{
	struct line	*l, *rec;
	char		*dup;
	size_t		 at;

	if (!btmgr_alias_is_valid(alias)) {
		errno = EINVAL;
		return (HOSTS_ERROR);
	}

	l = find_addr(db, addr);
	if (l != NULL) {
		if (!l->managed && !force)
			return (HOSTS_KEPT);
		if (strcmp(l->alias, alias) == 0 && l->extra == NULL &&
		    l->managed)
			return (HOSTS_UNCHANGED);

		dup = strdup(alias);
		if (dup == NULL)
			return (HOSTS_ERROR);

		free(l->alias);
		l->alias = dup;

		/*
		 * Taking over a record the user wrote drops any further
		 * aliases it carried, since we are now the author of the line
		 * and cannot promise they stay unique. force means the user
		 * asked for exactly that.
		 */
		free(l->extra);
		l->extra = NULL;

		l->authored = 1;
		l->managed = 1;
		db->dirty = 1;

		return (HOSTS_CHANGED);
	}

	/*
	 * Append the marker and the record. push_line() may realloc the array,
	 * so the first line is held by index rather than by pointer: a pointer
	 * taken before the second push can dangle.
	 */
	if (push_line(db) == NULL)
		return (HOSTS_ERROR);
	at = db->n - 1;

	db->lines[at].raw = strdup(HOSTS_MARKER);
	if (db->lines[at].raw == NULL) {
		db->n--;
		return (HOSTS_ERROR);
	}

	if (push_line(db) == NULL) {
		free_line(&db->lines[at]);
		db->n--;
		return (HOSTS_ERROR);
	}

	rec = &db->lines[at + 1];
	rec->alias = strdup(alias);
	if (rec->alias == NULL) {
		free_line(&db->lines[at]);
		db->n -= 2;
		return (HOSTS_ERROR);
	}

	memcpy(rec->addr, addr, 6);
	rec->is_record = 1;
	rec->managed = 1;
	rec->authored = 1;
	db->dirty = 1;

	return (HOSTS_CHANGED);
}

enum hosts_result
hosts_remove(struct hosts_db *db, const uint8_t *addr, int force)
{
	struct line	*l;
	size_t		 i;

	l = find_addr(db, addr);
	if (l == NULL)
		return (HOSTS_UNCHANGED);
	if (!l->managed && !force)
		return (HOSTS_KEPT);

	l->deleted = 1;
	db->dirty = 1;

	/* Take our marker with it, so the file does not collect orphans. */
	for (i = 1; i < db->n; i++) {
		if (&db->lines[i] != l)
			continue;
		if (db->lines[i - 1].is_record || db->lines[i - 1].deleted ||
		    db->lines[i - 1].raw == NULL)
			break;
		if (is_marker(db->lines[i - 1].raw))
			db->lines[i - 1].deleted = 1;
		break;
	}

	return (HOSTS_CHANGED);
}

char *
hosts_emit(const struct hosts_db *db, size_t *lenp)
{
	char	*buf, *p;
	size_t	 i, cap, len;

	/* 17 for the address, a tab, the alias, a newline, and slack. */
	cap = 1;
	for (i = 0; i < db->n; i++) {
		struct line *l = &db->lines[i];

		if (l->deleted)
			continue;
		if (l->authored)
			cap += BTMGR_ADDR_STRLEN + 1 +
			    strlen(l->alias) + 1;
		else
			cap += strlen(l->raw) + 1;
	}

	buf = malloc(cap);
	if (buf == NULL)
		return (NULL);

	p = buf;
	for (i = 0; i < db->n; i++) {
		struct line *l = &db->lines[i];

		if (l->deleted)
			continue;

		if (l->authored) {
			char	 as[BTMGR_ADDR_BUFSZ];

			btmgr_addr_format(l->addr, as, sizeof(as));
			p += snprintf(p, cap - (size_t)(p - buf), "%s\t%s\n",
			    as, l->alias);
		} else {
			len = strlen(l->raw);
			memcpy(p, l->raw, len);
			p += len;
			*p++ = '\n';
		}
	}
	*p = '\0';

	if (lenp != NULL)
		*lenp = (size_t)(p - buf);

	return (buf);
}

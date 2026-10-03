/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * hcsecd.c - /etc/bluetooth/hcsecd.conf ownership. SPEC.md A1, under A0.
 *
 * See hcsecd.h for the five grammar facts this has to respect.
 *
 * The model is a list of chunks in file order: opaque text, or a device block.
 * A chunk we did not author is re-emitted byte for byte, which is A0.4 and
 * A1.3.1 at once, and is what lets A0.5 report "unchanged".
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btaddr.h"
#include "hcsecd.h"
#include "sanitise.h"

/*
 * Must come after the system headers: it redefines malloc and friends. The
 * pragma says so to clang-include-cleaner, which sees no direct use of this
 * header because the use is macro replacement of malloc(), not a symbol.
 */
#include "memcheck.h"	/* IWYU pragma: keep */

enum chunk_kind {
	CHUNK_TEXT,		/* comments, blank space, anything not a block */
	CHUNK_BLOCK
};

struct chunk {
	enum chunk_kind	 kind;
	char		*raw;		/* original bytes; NULL once authored */
	int		 deleted;
	int		 is_marker;	/* TEXT holding exactly our marker line */

	/* CHUNK_BLOCK only. */
	int		 parsed;	/* we understood every option */
	int		 managed;	/* our marker was immediately before */
	int		 authored;	/* emit canonically, not from raw */
	int		 has_addr;
	uint8_t		 addr[6];
	char		*name;		/* between the quotes, or NULL */
	char		*key_tok;	/* "nokey" or "0x..."; never exposed */
	char		*pin_tok;	/* "nopin" or between the quotes */
	int		 pin_quoted;	/* pin_tok is a string, not nopin */
};

struct hcsecd_db {
	struct chunk	*c;
	size_t		 n;
	size_t		 cap;
	int		 dirty;
};

/* A token, as the lexer would see it. */
enum tok_kind {
	TOK_END,
	TOK_WORD,
	TOK_STRING,		/* start/len cover the quotes */
	TOK_PUNCT
};

struct tok {
	enum tok_kind	 kind;
	size_t		 start;
	size_t		 len;
	char		 ch;		/* TOK_PUNCT */
};

static const uint8_t	 default_addr[6] = HCSECD_DEFAULT_ADDR;

static char	*dupn(const char *s, size_t n);
static int	 is_space(char c);
static int	 is_word_byte(char c);
static void	 next_tok(const char *s, size_t *pos, struct tok *t);
static struct chunk *push_chunk(struct hcsecd_db *db, enum chunk_kind kind);
static struct chunk *find_block(const struct hcsecd_db *db,
		     const uint8_t *addr);
static int	 parse_block_body(const char *text, size_t body,
		     size_t end, struct chunk *bl);
static int	 split_marker(struct hcsecd_db *db);
static void	 free_chunk(struct chunk *c);
static char	*quoted_or_fallback(const char *in, const uint8_t *addr);

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

static int
is_space(char c)
{

	return (c == ' ' || c == '\t' || c == '\n' || c == '\r');
}

/*
 * A word byte is anything that is not whitespace, a comment start, a quote or
 * one of the three punctuation characters. ':' is deliberately a word byte so
 * that a bdaddr arrives as one token, which is how the lexer's longest-match
 * rule treats it.
 */
static int
is_word_byte(char c)
{

	return (!is_space(c) && c != '#' && c != '"' && c != '{' &&
	    c != '}' && c != ';');
}

/* Skip whitespace and comments, then read one token. */
static void
next_tok(const char *s, size_t *pos, struct tok *t)
{
	size_t	 i = *pos;

	for (;;) {
		while (s[i] != '\0' && is_space(s[i]))
			i++;
		if (s[i] == '#') {
			while (s[i] != '\0' && s[i] != '\n')
				i++;
			continue;
		}
		break;
	}

	t->start = i;

	if (s[i] == '\0') {
		t->kind = TOK_END;
		t->len = 0;
		*pos = i;
		return;
	}

	if (s[i] == '{' || s[i] == '}' || s[i] == ';') {
		t->kind = TOK_PUNCT;
		t->ch = s[i];
		t->len = 1;
		*pos = i + 1;
		return;
	}

	if (s[i] == '"') {
		size_t	 j = i + 1;

		/*
		 * \".+\" cannot span a newline, and needs at least one
		 * character. An unterminated quote is not a string token to the
		 * lexer either, so it falls through as a word and the block
		 * ends up unparsed, which is the safe outcome.
		 */
		while (s[j] != '\0' && s[j] != '\n' && s[j] != '"')
			j++;
		if (s[j] == '"' && j > i + 1) {
			t->kind = TOK_STRING;
			t->len = j + 1 - i;
			*pos = j + 1;
			return;
		}

		t->kind = TOK_WORD;
		t->len = 1;
		*pos = i + 1;
		return;
	}

	{
		size_t	 j = i;

		while (s[j] != '\0' && is_word_byte(s[j]))
			j++;
		t->kind = TOK_WORD;
		t->len = j - i;
		*pos = j;
	}
}

static void
free_chunk(struct chunk *c)
{

	free(c->raw);
	free(c->name);
	free(c->key_tok);
	free(c->pin_tok);
}

static struct chunk *
push_chunk(struct hcsecd_db *db, enum chunk_kind kind)
{
	struct chunk	*p;
	size_t		 cap;

	if (db->n == db->cap) {
		cap = db->cap == 0 ? 8 : db->cap * 2;
		p = realloc(db->c, cap * sizeof(*p));
		if (p == NULL)
			return (NULL);
		db->c = p;
		db->cap = cap;
	}

	p = &db->c[db->n++];
	memset(p, 0, sizeof(*p));
	p->kind = kind;

	return (p);
}

/*
 * Read the options between '{' and '}'. Returns 0 when every option was
 * understood, -1 otherwise, in which case the caller keeps the block verbatim
 * and never authors it.
 */
static int
parse_block_body(const char *text, size_t body, size_t end, struct chunk *bl)
{
	size_t	 pos = body;
	int	 nopt = 0;

	for (;;) {
		struct tok	 kw, val, semi;

		if (pos >= end)
			return (-1);

		next_tok(text, &pos, &kw);
		if (kw.kind == TOK_PUNCT && kw.ch == '}')
			break;
		if (kw.kind != TOK_WORD)
			return (-1);

		next_tok(text, &pos, &val);
		next_tok(text, &pos, &semi);
		if (semi.kind != TOK_PUNCT || semi.ch != ';')
			return (-1);

		if (kw.len == 6 && memcmp(text + kw.start, "bdaddr", 6) == 0) {
			if (val.kind != TOK_WORD ||
			    btmgr_addr_parse_strict(text + val.start,
			    val.len, bl->addr) != 0)
				return (-1);
			bl->has_addr = 1;
		} else if (kw.len == 4 &&
		    memcmp(text + kw.start, "name", 4) == 0) {
			if (val.kind != TOK_STRING)
				return (-1);
			free(bl->name);
			bl->name = dupn(text + val.start + 1, val.len - 2);
			if (bl->name == NULL)
				return (-1);
		} else if (kw.len == 3 &&
		    memcmp(text + kw.start, "key", 3) == 0) {
			if (val.kind != TOK_WORD)
				return (-1);
			free(bl->key_tok);
			bl->key_tok = dupn(text + val.start, val.len);
			if (bl->key_tok == NULL)
				return (-1);
		} else if (kw.len == 3 &&
		    memcmp(text + kw.start, "pin", 3) == 0) {
			free(bl->pin_tok);
			if (val.kind == TOK_STRING) {
				bl->pin_tok = dupn(text + val.start + 1,
				    val.len - 2);
				bl->pin_quoted = 1;
			} else if (val.kind == TOK_WORD) {
				bl->pin_tok = dupn(text + val.start, val.len);
				bl->pin_quoted = 0;
			} else
				return (-1);
			if (bl->pin_tok == NULL)
				return (-1);
		} else
			return (-1);	/* an option hcsecd would reject too */

		nopt++;
	}

	/* options requires at least one, and a block with no bdaddr is no use. */
	if (nopt == 0 || !bl->has_addr)
		return (-1);

	return (0);
}

/*
 * A1.3.3. Where a TEXT chunk ends with our marker on its own final line, split
 * that line off as its own chunk and claim the block that follows. Adjacency is
 * strict: a blank line in between means the block is not ours.
 */
static int
split_marker(struct hcsecd_db *db)
{
	size_t	 i;

	for (i = 1; i < db->n; i++) {
		struct chunk	*txt = &db->c[i - 1];
		struct chunk	*bl = &db->c[i];
		size_t		 len, mlen, line;
		const char	*p;

		if (bl->kind != CHUNK_BLOCK || txt->kind != CHUNK_TEXT ||
		    txt->raw == NULL)
			continue;

		len = strlen(txt->raw);
		if (len == 0 || txt->raw[len - 1] != '\n')
			continue;

		/* Start of the final line, the one ending at len - 1. */
		line = 0;
		for (p = txt->raw; p < txt->raw + len - 1; p++)
			if (*p == '\n')
				line = (size_t)(p - txt->raw) + 1;

		mlen = len - 1 - line;
		{
			const char	*s = txt->raw + line;
			size_t		 k = 0;

			while (k < mlen && (s[k] == ' ' || s[k] == '\t'))
				k++;
			if (mlen - k != strlen(HCSECD_MARKER) ||
			    memcmp(s + k, HCSECD_MARKER,
			    strlen(HCSECD_MARKER)) != 0)
				continue;
		}

		/*
		 * Keep the marker as its own chunk so removing the block can
		 * remove it too. Insert before the block.
		 */
		if (push_chunk(db, CHUNK_TEXT) == NULL)
			return (-1);

		/*
		 * push_chunk may have grown the array, so re-take txt. bl is
		 * deliberately not re-taken: the memmove below shifts the block
		 * to i + 1, and it is reached by index from there on.
		 */
		txt = &db->c[i - 1];

		memmove(&db->c[i + 1], &db->c[i],
		    (db->n - 1 - i) * sizeof(*db->c));

		{
			struct chunk	*mk = &db->c[i];
			char		*head, *marker;

			head = dupn(txt->raw, line);
			marker = dupn(txt->raw + line, mlen + 1);
			if (head == NULL || marker == NULL) {
				free(head);
				free(marker);
				return (-1);
			}

			free(txt->raw);
			txt->raw = head;

			memset(mk, 0, sizeof(*mk));
			mk->kind = CHUNK_TEXT;
			mk->raw = marker;
			mk->is_marker = 1;
		}

		db->c[i + 1].managed = 1;
		i++;		/* skip past the block we just claimed */
	}

	return (0);
}

struct hcsecd_db *
hcsecd_parse(const char *text)
{
	struct hcsecd_db	*db;
	size_t			 pos, chunk_start;

	db = calloc(1, sizeof(*db));
	if (db == NULL)
		return (NULL);

	if (text == NULL)
		return (db);

	pos = 0;
	chunk_start = 0;

	for (;;) {
		struct tok	 t, brace;
		size_t		 body, depth, scan;
		struct chunk	*c;

		next_tok(text, &pos, &t);

		if (t.kind == TOK_END)
			break;

		if (t.kind != TOK_WORD || t.len != 6 ||
		    memcmp(text + t.start, "device", 6) != 0)
			continue;

		/* Must be followed by '{' to be a block we can model. */
		scan = pos;
		next_tok(text, &scan, &brace);
		if (brace.kind != TOK_PUNCT || brace.ch != '{') {
			pos = scan;
			continue;
		}

		/*
		 * Find the matching '}'. next_tok() already steps over strings
		 * and comments, so a brace inside either cannot mislead us.
		 */
		body = scan;
		depth = 1;
		while (depth > 0) {
			struct tok	 u;

			next_tok(text, &scan, &u);
			if (u.kind == TOK_END)
				break;
			if (u.kind != TOK_PUNCT)
				continue;
			if (u.ch == '{')
				depth++;
			else if (u.ch == '}')
				depth--;
		}
		if (depth != 0) {
			/* Unterminated block: the rest of the file is opaque. */
			pos = scan;
			continue;
		}

		/*
		 * Let the block own the newline that ends its line. Without
		 * this, removing a block leaves that newline behind as a blank
		 * line, and a block we appended could not be removed back to
		 * the original bytes. A trailing comment after the '}' is left
		 * outside, because it is the user's and A0.4 keeps it.
		 */
		{
			size_t	 k = scan;

			while (text[k] == ' ' || text[k] == '\t')
				k++;
			if (text[k] == '\r' && text[k + 1] == '\n')
				k += 2;
			else if (text[k] == '\n')
				k++;
			else
				k = scan;
			scan = k;
		}

		/* Opaque text before the block, if any. */
		if (t.start > chunk_start) {
			c = push_chunk(db, CHUNK_TEXT);
			if (c == NULL)
				goto fail;
			c->raw = dupn(text + chunk_start,
			    t.start - chunk_start);
			if (c->raw == NULL)
				goto fail;
		}

		c = push_chunk(db, CHUNK_BLOCK);
		if (c == NULL)
			goto fail;
		c->raw = dupn(text + t.start, scan - t.start);
		if (c->raw == NULL)
			goto fail;

		if (parse_block_body(text, body, scan, c) == 0)
			c->parsed = 1;

		chunk_start = scan;
		pos = scan;
	}

	/* Whatever is left after the last block. */
	if (text[chunk_start] != '\0') {
		struct chunk	*c = push_chunk(db, CHUNK_TEXT);

		if (c == NULL)
			goto fail;
		c->raw = strdup(text + chunk_start);
		if (c->raw == NULL)
			goto fail;
	}

	if (split_marker(db) != 0)
		goto fail;

	return (db);

fail:
	hcsecd_free(db);

	return (NULL);
}

void
hcsecd_free(struct hcsecd_db *db)
{
	size_t	 i;

	if (db == NULL)
		return;

	for (i = 0; i < db->n; i++)
		free_chunk(&db->c[i]);

	free(db->c);
	free(db);
}

int
hcsecd_dirty(const struct hcsecd_db *db)
{

	return (db->dirty);
}

size_t
hcsecd_count(const struct hcsecd_db *db)
{
	size_t	 i, n = 0;

	for (i = 0; i < db->n; i++)
		if (db->c[i].kind == CHUNK_BLOCK && !db->c[i].deleted)
			n++;

	return (n);
}

static struct chunk *
find_block(const struct hcsecd_db *db, const uint8_t *addr)
{
	size_t	 i;

	for (i = 0; i < db->n; i++) {
		struct chunk	*c = &db->c[i];

		if (c->kind == CHUNK_BLOCK && !c->deleted && c->parsed &&
		    memcmp(c->addr, addr, 6) == 0)
			return (c);
	}

	return (NULL);
}

int
hcsecd_has_block(const struct hcsecd_db *db, const uint8_t *addr)
{

	return (find_block(db, addr) != NULL);
}

int
hcsecd_is_managed(const struct hcsecd_db *db, const uint8_t *addr)
{
	struct chunk	*c = find_block(db, addr);

	return (c != NULL && c->managed);
}

/* A3.3. Presence only; the value never leaves this file. */
int
hcsecd_has_key(const struct hcsecd_db *db, const uint8_t *addr)
{
	struct chunk	*c = find_block(db, addr);

	return (c != NULL && c->key_tok != NULL &&
	    strcmp(c->key_tok, "nokey") != 0);
}

const char *
hcsecd_name_for(const struct hcsecd_db *db, const uint8_t *addr)
{
	struct chunk	*c = find_block(db, addr);

	return (c == NULL ? NULL : c->name);
}

/*
 * Sanitise for a \".+\" token. A7.1 first, then the non-empty requirement of
 * grammar fact 2: an empty name would not lex, so fall back to something
 * derived from the address rather than emitting a file hcsecd will reject.
 */
static char *
quoted_or_fallback(const char *in, const uint8_t *addr)
{
	char	*out;
	size_t	 len;

	len = in == NULL ? 0 : strlen(in);

	out = malloc(len + 1 > 24 ? len + 1 : 24);
	if (out == NULL)
		return (NULL);

	if (in != NULL && btmgr_sanitise_quoted(in, out, len + 1) != 0) {
		free(out);
		return (NULL);
	}
	if (in == NULL)
		out[0] = '\0';

	if (out[0] == '\0')
		(void)snprintf(out, 24, "bt-%02x%02x%02x",
		    (unsigned int)addr[2], (unsigned int)addr[1],
		    (unsigned int)addr[0]);

	return (out);
}

enum hcsecd_result
hcsecd_set(struct hcsecd_db *db, const uint8_t *addr,
    const struct hcsecd_entry *e, int force)
{
	const char	*name = e->name;
	const char	*pin = e->pin;
	struct chunk	*bl;
	char		*newname, *newpin;
	size_t		 at;
	int		 needs_nl;

	if (memcmp(addr, default_addr, 6) == 0)
		return (HCSECD_REFUSED);

	newname = quoted_or_fallback(name, addr);
	if (newname == NULL)
		return (HCSECD_ERROR);

	newpin = NULL;
	if (pin != NULL && *pin != '\0') {
		newpin = malloc(strlen(pin) + 1);
		if (newpin == NULL ||
		    btmgr_sanitise_quoted(pin, newpin, strlen(pin) + 1) != 0) {
			free(newname);
			free(newpin);
			return (HCSECD_ERROR);
		}
		/* A sanitised pin can still be non-empty; an empty one is nopin. */
		if (newpin[0] == '\0') {
			free(newpin);
			newpin = NULL;
		}
	}

	bl = find_block(db, addr);
	if (bl != NULL) {
		int	 same;

		if (!bl->managed && !force) {
			free(newname);
			free(newpin);
			return (HCSECD_KEPT);
		}

		same = bl->name != NULL && strcmp(bl->name, newname) == 0 &&
		    ((newpin == NULL && !bl->pin_quoted) ||
		    (newpin != NULL && bl->pin_quoted &&
		    bl->pin_tok != NULL && strcmp(bl->pin_tok, newpin) == 0));

		/* Already says this. Keep the original bytes, so A0.5 holds. */
		if (same) {
			free(newname);
			free(newpin);
			return (HCSECD_UNCHANGED);
		}

		free(bl->name);
		bl->name = newname;

		free(bl->pin_tok);
		bl->pin_tok = newpin;
		bl->pin_quoted = newpin != NULL;
		if (newpin == NULL) {
			bl->pin_tok = strdup("nopin");
			if (bl->pin_tok == NULL)
				return (HCSECD_ERROR);
		}

		/* An existing key is hcsecd's, not ours to drop for a rename. */
		if (bl->key_tok == NULL) {
			bl->key_tok = strdup("nokey");
			if (bl->key_tok == NULL)
				return (HCSECD_ERROR);
		}

		bl->authored = 1;
		bl->managed = 1;
		db->dirty = 1;

		return (HCSECD_CHANGED);
	}

	/*
	 * Append a marker chunk then the block. push_chunk() can realloc, so
	 * the first is held by index rather than by pointer.
	 */
	needs_nl = 0;
	if (db->n > 0) {
		const char	*last = db->c[db->n - 1].raw;

		if (last != NULL && *last != '\0' &&
		    last[strlen(last) - 1] != '\n')
			needs_nl = 1;
	}

	if (push_chunk(db, CHUNK_TEXT) == NULL) {
		free(newname);
		free(newpin);
		return (HCSECD_ERROR);
	}
	at = db->n - 1;
	db->c[at].raw = strdup(needs_nl ? "\n" HCSECD_MARKER "\n"
	    : HCSECD_MARKER "\n");
	db->c[at].is_marker = 1;
	if (db->c[at].raw == NULL) {
		db->n--;
		free(newname);
		free(newpin);
		return (HCSECD_ERROR);
	}

	if (push_chunk(db, CHUNK_BLOCK) == NULL) {
		free_chunk(&db->c[at]);
		db->n--;
		free(newname);
		free(newpin);
		return (HCSECD_ERROR);
	}

	bl = &db->c[at + 1];
	memcpy(bl->addr, addr, 6);
	bl->has_addr = 1;
	bl->parsed = 1;
	bl->managed = 1;
	bl->authored = 1;
	bl->name = newname;
	bl->pin_tok = newpin != NULL ? newpin : strdup("nopin");
	bl->pin_quoted = newpin != NULL;
	bl->key_tok = strdup("nokey");

	if (bl->pin_tok == NULL || bl->key_tok == NULL)
		return (HCSECD_ERROR);

	db->dirty = 1;

	return (HCSECD_CHANGED);
}

enum hcsecd_result
hcsecd_remove(struct hcsecd_db *db, const uint8_t *addr, int force)
{
	struct chunk	*bl;
	size_t		 i;

	if (memcmp(addr, default_addr, 6) == 0)
		return (HCSECD_REFUSED);

	bl = find_block(db, addr);
	if (bl == NULL)
		return (HCSECD_UNCHANGED);
	if (!bl->managed && !force)
		return (HCSECD_KEPT);

	bl->deleted = 1;
	db->dirty = 1;

	/* Take our marker with it. */
	for (i = 1; i < db->n; i++) {
		if (&db->c[i] != bl)
			continue;
		if (db->c[i - 1].is_marker && !db->c[i - 1].deleted)
			db->c[i - 1].deleted = 1;
		break;
	}

	return (HCSECD_CHANGED);
}

int
hcsecd_dedupe(struct hcsecd_db *db)
{
	size_t	 i, j;
	int	 dropped = 0;

	for (i = 0; i < db->n; i++) {
		struct chunk	*a = &db->c[i];

		if (a->kind != CHUNK_BLOCK || a->deleted || !a->parsed)
			continue;

		for (j = i + 1; j < db->n; j++) {
			struct chunk	*b = &db->c[j];

			if (b->kind != CHUNK_BLOCK || b->deleted ||
			    !b->parsed)
				continue;
			if (memcmp(a->addr, b->addr, 6) != 0)
				continue;

			b->deleted = 1;
			if (j > 0 && db->c[j - 1].is_marker)
				db->c[j - 1].deleted = 1;
			dropped++;
			db->dirty = 1;
		}
	}

	return (dropped);
}

char *
hcsecd_emit(const struct hcsecd_db *db, size_t *lenp)
{
	char	*buf, *p;
	size_t	 i, cap, len, left;

	cap = 1;
	for (i = 0; i < db->n; i++) {
		struct chunk	*c = &db->c[i];

		if (c->deleted)
			continue;
		if (c->kind == CHUNK_BLOCK && c->authored) {
			/* device {\n + four options + }\n, generously. */
			cap += 64 + strlen(c->name) +
			    strlen(c->key_tok) + strlen(c->pin_tok);
		} else
			cap += strlen(c->raw) + 1;
	}

	buf = malloc(cap);
	if (buf == NULL)
		return (NULL);

	p = buf;
	for (i = 0; i < db->n; i++) {
		struct chunk	*c = &db->c[i];

		if (c->deleted)
			continue;

		left = cap - (size_t)(p - buf);

		if (c->kind == CHUNK_BLOCK && c->authored) {
			/* A1.3.2: canonical, one option per line, tab indented. */
			char	 as[BTMGR_ADDR_BUFSZ];

			btmgr_addr_format(c->addr, as, sizeof(as));
			p += snprintf(p, left,
			    "device {\n"
			    "\tbdaddr\t%s;\n"
			    "\tname\t\"%s\";\n"
			    "\tkey\t%s;\n"
			    "\tpin\t%s%s%s;\n"
			    "}\n",
			    as, c->name, c->key_tok,
			    c->pin_quoted ? "\"" : "", c->pin_tok,
			    c->pin_quoted ? "\"" : "");
		} else {
			len = strlen(c->raw);
			memcpy(p, c->raw, len);
			p += len;
		}
	}
	*p = '\0';

	if (lenp != NULL)
		*lenp = (size_t)(p - buf);

	return (buf);
}

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * memcheck.c - debug allocation tracker. See memcheck.h for why.
 *
 * Deliberately simple: an open-addressed table of live pointers, each tagged
 * with the file and line that allocated it. Not thread safe, which is fine
 * because the daemon is single threaded by design.
 */

#ifdef BTMGR_MEMCHECK

/*
 * memcheck.h redefines malloc and friends, so this one file must reach the
 * real ones. Include the system headers first and do not include memcheck.h
 * until after the real functions have been captured below.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Capture the real allocators before memcheck.h hides them. */
static void	*(*real_malloc)(size_t) = malloc;
static void	*(*real_calloc)(size_t, size_t) = calloc;
static void	*(*real_realloc)(void *, size_t) = realloc;
static void	 (*real_free)(void *) = free;

#include "memcheck.h"

#define	MC_SLOTS	8192

struct mc_entry {
	void		*ptr;		/* NULL means the slot is empty */
	size_t		 size;
	const char	*file;
	int		 line;
};

static struct mc_entry	 mc_table[MC_SLOTS];
static size_t		 mc_live;	/* outstanding allocations */
static size_t		 mc_total;	/* allocations ever made */
static int		 mc_registered;
static int		 mc_overflow;	/* table filled, counts are suspect */

static size_t
mc_hash(const void *p)
{
	/*
	 * Pointers are typically 16 byte aligned, so the low bits carry no
	 * information. Shift them off before mixing.
	 */
	uintptr_t v = (uintptr_t)p >> 4;

	v *= 0x9e3779b97f4a7c15ULL;

	return ((size_t)(v % MC_SLOTS));
}

/* atexit() wants void(void); casting btmgr_mc_report to it would be UB. */
static void
mc_atexit(void)
{
	(void)btmgr_mc_report();
}

static void
mc_insert(void *p, size_t size, const char *file, int line)
{
	size_t	i, start;

	if (p == NULL)
		return;

	if (!mc_registered) {
		mc_registered = 1;
		(void)atexit(mc_atexit);
	}

	mc_total++;

	start = mc_hash(p);
	for (i = 0; i < MC_SLOTS; i++) {
		size_t slot = (start + i) % MC_SLOTS;

		if (mc_table[slot].ptr == NULL) {
			mc_table[slot].ptr = p;
			mc_table[slot].size = size;
			mc_table[slot].file = file;
			mc_table[slot].line = line;
			mc_live++;
			return;
		}
	}

	mc_overflow = 1;
}

/* Returns the slot holding p, or -1. */
static long
mc_find(const void *p)
{
	size_t	i, start;

	if (p == NULL)
		return (-1);

	start = mc_hash(p);
	for (i = 0; i < MC_SLOTS; i++) {
		size_t slot = (start + i) % MC_SLOTS;

		if (mc_table[slot].ptr == p)
			return ((long)slot);
		if (mc_table[slot].ptr == NULL)
			return (-1);	/* empty slot ends the probe chain */
	}

	return (-1);
}

void *
btmgr_mc_malloc(size_t n, const char *file, int line)
{
	void	*p = real_malloc(n);

	mc_insert(p, n, file, line);

	return (p);
}

void *
btmgr_mc_calloc(size_t a, size_t b, const char *file, int line)
{
	void	*p = real_calloc(a, b);

	mc_insert(p, a * b, file, line);

	return (p);
}

void *
btmgr_mc_realloc(void *old, size_t n, const char *file, int line)
{
	void	*p;
	long	 slot;

	p = real_realloc(old, n);

	/*
	 * A failed realloc leaves the original block allocated. Keeping its
	 * entry is what makes this tracker catch the classic
	 * "p = realloc(p, n)" bug, which the static analyzer misses: if the
	 * caller overwrote its only pointer, the entry stays live to the end
	 * and gets reported.
	 */
	if (p == NULL)
		return (NULL);

	if (old != NULL) {
		slot = mc_find(old);
		if (slot >= 0) {
			mc_table[slot].ptr = NULL;
			mc_live--;
		}
	}

	mc_insert(p, n, file, line);

	return (p);
}

char *
btmgr_mc_strdup(const char *s, const char *file, int line)
{
	size_t	 n;
	char	*p;

	if (s == NULL)
		return (NULL);

	n = strlen(s) + 1;
	p = real_malloc(n);
	if (p == NULL)
		return (NULL);

	memcpy(p, s, n);
	mc_insert(p, n, file, line);

	return (p);
}

void
btmgr_mc_free(void *p, const char *file, int line)
{
	long	slot;

	(void)file;
	(void)line;

	if (p == NULL)
		return;

	slot = mc_find(p);
	if (slot >= 0) {
		mc_table[slot].ptr = NULL;
		mc_live--;
	}

	/*
	 * An untracked pointer came from a library whose allocations we do not
	 * wrap, jansson's json_dumps() above all. Free it and say nothing,
	 * rather than reporting a mismatch that is not ours.
	 */
	real_free(p);
}

int
btmgr_mc_report(void)
{
	size_t	i;
	int	shown = 0;

	fprintf(stderr, "memcheck: %zu allocation%s, %zu still live\n",
	    mc_total, mc_total == 1 ? "" : "s", mc_live);

	if (mc_overflow)
		fprintf(stderr, "memcheck: table overflowed, counts are a "
		    "lower bound\n");

	for (i = 0; i < MC_SLOTS; i++) {
		if (mc_table[i].ptr == NULL)
			continue;

		if (shown++ < 32)
			fprintf(stderr, "memcheck:   %zu bytes from %s:%d\n",
			    mc_table[i].size, mc_table[i].file,
			    mc_table[i].line);
	}

	if (shown > 32)
		fprintf(stderr, "memcheck:   ... and %d more\n", shown - 32);

	return ((int)mc_live);
}

#endif /* BTMGR_MEMCHECK */

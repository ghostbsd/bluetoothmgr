/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * memcheck.h - debug allocation tracker.
 *
 * Exists because the two leak shapes clang's static analyzer misses are
 * exactly the two this code uses:
 *
 *   1. p = realloc(p, n)     the original block leaks when realloc fails
 *   2. free(s)               a struct freed without freeing its fields
 *
 * The second is the shape of struct client, whose in and out buffers
 * ipc_client_free() has to release. Measured: the analyzer reports neither.
 *
 * Only active when built with -DBTMGR_MEMCHECK. In a normal build this header
 * defines nothing and costs nothing.
 *
 * Include it AFTER <stdlib.h> and <string.h>, since it works by redefining
 * their names.
 *
 * Pointers we did not allocate are passed straight through to free(3) without
 * complaint, so memory that came from jansson or libbluetooth does not show up
 * as a spurious mismatch. The balance reported therefore covers our own
 * allocations only, which is where our bugs would be.
 */

#ifndef BTMGR_MEMCHECK_H_
#define	BTMGR_MEMCHECK_H_

#ifdef BTMGR_MEMCHECK

#include <stddef.h>

void	*btmgr_mc_malloc(size_t, const char *, int);
void	*btmgr_mc_calloc(size_t, size_t, const char *, int);
void	*btmgr_mc_realloc(void *, size_t, const char *, int);
char	*btmgr_mc_strdup(const char *, const char *, int);
void	 btmgr_mc_free(void *, const char *, int);

/*
 * Report outstanding allocations. Returns the number still live, so a test
 * can assert zero rather than relying on someone reading the output.
 * Registered with atexit() automatically on first allocation.
 */
int	 btmgr_mc_report(void);

#define	malloc(n)	btmgr_mc_malloc((n), __FILE__, __LINE__)
#define	calloc(a, b)	btmgr_mc_calloc((a), (b), __FILE__, __LINE__)
#define	realloc(p, n)	btmgr_mc_realloc((p), (n), __FILE__, __LINE__)
#define	strdup(s)	btmgr_mc_strdup((s), __FILE__, __LINE__)
#define	free(p)		btmgr_mc_free((p), __FILE__, __LINE__)

#else /* !BTMGR_MEMCHECK */

#define	btmgr_mc_report()	(0)

#endif /* BTMGR_MEMCHECK */

#endif /* !BTMGR_MEMCHECK_H_ */

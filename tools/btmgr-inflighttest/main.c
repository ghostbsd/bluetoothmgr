/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-inflighttest - verification for daemon/src/inflight.c.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "btmgr.h"
#include "inflight.h"

static int	 checks;
static int	 failures;

static void	 ok(int cond, const char *fmt, ...) __printflike(2, 3);
static bdaddr_t	 addr_of(uint8_t last);
static void	 count_expired(const struct inflight *e, void *arg);
static void	 test_add_and_take(void);
static void	 test_take_by_handle(void);
static void	 test_table_full(void);
static void	 test_drop_client(void);
static void	 test_expire(void);
static void	 test_shift(void);

static void
ok(int cond, const char *fmt, ...)
{
	va_list	 ap;

	checks++;
	if (!cond)
		failures++;

	printf("%s ", cond ? "ok  " : "FAIL");
	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

static bdaddr_t
addr_of(uint8_t last)
{
	bdaddr_t	 a;

	memset(&a, 0, sizeof(a));
	a.b[0] = last;

	return (a);
}

static void
count_expired(const struct inflight *e, void *arg)
{
	int	*n = arg;

	(void)e;
	(*n)++;
}

static void
test_add_and_take(void)
{
	struct inflight_table	 t;
	struct inflight		*got;
	bdaddr_t		 a = addr_of(1), b = addr_of(2);

	printf("\nadd and take\n");

	memset(&t, 0, sizeof(t));

	ok(inflight_add(&t, INFLIGHT_CONNECT, 7, NULL, &a, 0) == 0,
	    "a connect parks");
	ok(inflight_add(&t, INFLIGHT_CONNECT, 8, NULL, &b, 0) == 0,
	    "a second, for another address");

	got = inflight_take(&t, INFLIGHT_CONNECT, &a);
	ok(got != NULL && got->id == 7, "taking by address returns that entry");

	ok(inflight_take(&t, INFLIGHT_CONNECT, &a) == NULL,
	    "and the slot is gone afterwards");

	got = inflight_take(&t, INFLIGHT_DISCONNECT, &b);
	ok(got == NULL, "the kind has to match too");

	got = inflight_take(&t, INFLIGHT_CONNECT, &b);
	ok(got != NULL && got->id == 8, "the other entry is untouched");
}

static void
test_take_by_handle(void)
{
	struct inflight_table	 t;
	struct inflight		*got;
	bdaddr_t		 a = addr_of(3);

	printf("\ntake by handle\n");

	memset(&t, 0, sizeof(t));
	(void)inflight_add(&t, INFLIGHT_DISCONNECT, 11, NULL, &a, 0x2a);

	ok(inflight_take_handle(&t, INFLIGHT_DISCONNECT, 0x2b) == NULL,
	    "a handle that was never parked matches nothing");

	got = inflight_take_handle(&t, INFLIGHT_DISCONNECT, 0x2a);
	ok(got != NULL && got->id == 11, "the right handle finds the entry");
}

static void
test_table_full(void)
{
	struct inflight_table	 t;
	bdaddr_t		 a;
	int			 i, added = 0;

	printf("\nthe table is bounded\n");

	memset(&t, 0, sizeof(t));

	for (i = 0; i < INFLIGHT_MAX; i++) {
		a = addr_of((uint8_t)(0x40 + i));
		if (inflight_add(&t, INFLIGHT_CONNECT, i, NULL, &a, 0) == 0)
			added++;
	}
	ok(added == INFLIGHT_MAX, "%d entries fit", INFLIGHT_MAX);

	a = addr_of(0xfe);
	ok(inflight_add(&t, INFLIGHT_CONNECT, 99, NULL, &a, 0) == -1,
	    "one more is refused, which the daemon reports as busy");
}

static void
test_drop_client(void)
{
	struct inflight_table	 t;
	/* Only ever compared, never dereferenced. */
	struct client		*mine = (struct client *)(void *)&t;
	bdaddr_t		 a = addr_of(5), b = addr_of(6);

	printf("\ndropping a client\n");

	memset(&t, 0, sizeof(t));
	(void)inflight_add(&t, INFLIGHT_CONNECT, 1, mine, &a, 0);
	(void)inflight_add(&t, INFLIGHT_CONNECT, 2, NULL, &b, 0);

	inflight_drop_client(&t, mine);

	ok(inflight_take(&t, INFLIGHT_CONNECT, &a) == NULL,
	    "that client's entry is forgotten");
	ok(inflight_take(&t, INFLIGHT_CONNECT, &b) != NULL,
	    "another client's entry survives");
}

static void
test_expire(void)
{
	struct inflight_table	 t;
	bdaddr_t		 a = addr_of(7);
	time_t			 base;
	int			 n = 0;

	printf("\nexpiry\n");

	memset(&t, 0, sizeof(t));

	/* inflight_add() stamps the deadline from time(NULL), not from us. */
	base = time(NULL);
	(void)inflight_add(&t, INFLIGHT_CONNECT, 3, NULL, &a, 0);

	inflight_expire(&t, base, count_expired, &n);
	ok(n == 0, "nothing expires before the deadline");

	n = 0;
	inflight_expire(&t, base + INFLIGHT_TIMEOUT_SEC + 1, count_expired, &n);
	ok(n == 1, "the entry expires once past it");

	n = 0;
	inflight_expire(&t, base + INFLIGHT_TIMEOUT_SEC + 1, count_expired, &n);
	ok(n == 0, "and is not reported twice");
}

/*
 * The deadlines are wall-clock, so a backwards step would extend them. This
 * is what keeps a discoverable window from outlasting its timeout.
 */
static void
test_shift(void)
{
	struct inflight_table	 t;
	bdaddr_t		 a = addr_of(8);
	time_t			 base;
	int			 n;

	printf("\nrebasing after the clock steps back\n");

	memset(&t, 0, sizeof(t));
	base = time(NULL);
	(void)inflight_add(&t, INFLIGHT_CONNECT, 4, NULL, &a, 0);

	/* An hour backwards. Unshifted, the entry would gain an hour of life. */
	inflight_shift(&t, 3600);

	n = 0;
	inflight_expire(&t, base - 3600 + INFLIGHT_TIMEOUT_SEC - 2,
	    count_expired, &n);
	ok(n == 0, "the wait that was asked for is still honoured");

	n = 0;
	inflight_expire(&t, base - 3600 + INFLIGHT_TIMEOUT_SEC + 1,
	    count_expired, &n);
	ok(n == 1, "and it expires on the rebased deadline, not an hour later");

	memset(&t, 0, sizeof(t));
	base = time(NULL);
	(void)inflight_add(&t, INFLIGHT_CONNECT, 5, NULL, &a, 0);
	inflight_shift(&t, 0);
	inflight_shift(&t, -60);

	n = 0;
	inflight_expire(&t, base + INFLIGHT_TIMEOUT_SEC - 2, count_expired, &n);
	ok(n == 0, "a zero or backward delta does not expire it early");

	/* Without the guard, a negative delta would push the deadline out. */
	n = 0;
	inflight_expire(&t, base + INFLIGHT_TIMEOUT_SEC + 1, count_expired, &n);
	ok(n == 1, "and leaves the original deadline in place");
}

int
main(void)
{

	printf("btmgr-inflighttest\n");

	test_add_and_take();
	test_take_by_handle();
	test_table_full();
	test_drop_client();
	test_expire();
	test_shift();

	printf("\n%d checks, %d failures\n", checks, failures);

	return (failures != 0 ? 1 : 0);
}

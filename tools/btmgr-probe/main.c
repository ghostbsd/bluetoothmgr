/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-probe - read-only view of the local Bluetooth state.
 *
 * Exercises libbtmgr with no daemon, no event loop and no privilege. If this
 * works, the foundation the daemon is built on works.
 *
 *	btmgr-probe [adapter | conn | scan [seconds]]
 *	btmgr-probe connect <addr>
 *	btmgr-probe disconnect <handle>
 *	btmgr-probe discoverable <on|off>
 *
 * With no argument it runs the three read-only views.
 *
 * The last three need root, per PLAN.md F2. They exist so the privileged
 * operations can be debugged without the daemon in the way.
 */

#include <sys/cdefs.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "btmgr.h"

#define	DEFAULT_SCAN_SECS	5

/*
 * The verb is resolved once, into an enum, rather than strcmp'd at each use.
 * Seven repeated comparisons of the same string are easy to get out of step,
 * and they also defeat the static analyzer: it treats every strcmp() as an
 * opaque call, so it happily assumes "not discoverable" where the argument is
 * validated and "is discoverable" where the argument is used, and then reports
 * a null dereference that cannot happen.
 */
enum verb {
	VERB_ALL,
	VERB_ADAPTER,
	VERB_CONN,
	VERB_SCAN,
	VERB_CONNECT,
	VERB_DISCONNECT,
	VERB_DISCOVERABLE
};

static const struct {
	const char	*name;
	enum verb	 verb;
} verbs[] = {
	{ "all",		VERB_ALL },
	{ "adapter",		VERB_ADAPTER },
	{ "conn",		VERB_CONN },
	{ "scan",		VERB_SCAN },
	{ "connect",		VERB_CONNECT },
	{ "disconnect",		VERB_DISCONNECT },
	{ "discoverable",	VERB_DISCOVERABLE }
};

static void	usage(void) __dead2;
static int	parse_positive(const char *);
static int	show_adapters(struct btmgr_adapter *, int *);
static void	show_conns(const char *);
static void	show_scan(const char *, int);
static void	do_connect(const char *, const char *);

static void
usage(void)
{
	(void)fprintf(stderr,
	    "usage: btmgr-probe [adapter | conn | scan [seconds]]\n"
	    "       btmgr-probe connect <addr>        (root)\n"
	    "       btmgr-probe disconnect <handle>   (root)\n"
	    "       btmgr-probe discoverable <on|off> (root)\n");
	exit(1);
}

/*
 * A whole positive number, or -1.
 *
 * atoi() cannot tell "0" from "not a number", and it stops at the first byte it
 * does not like without saying so, which made "scan 5x" scan for 5 seconds and
 * "disconnect 7bogus" disconnect handle 7. Both callers want the input refused.
 */
static int
parse_positive(const char *s)
{
	char	*end;
	long	 v;

	errno = 0;
	v = strtol(s, &end, 10);

	if (errno != 0 || end == s || *end != '\0' || v <= 0 || v > INT_MAX)
		return (-1);

	return ((int)v);
}

/*
 * Page a device and wait for the outcome.
 *
 * btmgr_connect_start() does not block, so this polls the connection list to
 * report something useful. The daemon does it properly, by watching for
 * Connection_Complete on its event socket; here a poll keeps the CLI simple.
 */
static void
do_connect(const char *node, const char *addrstr)
{
	struct btmgr_conn	conns[BTMGR_MAX_CONNS];
	bdaddr_t		addr;
	int			i, n, tries;

	if (!bt_aton(addrstr, &addr)) {
		/* Not a raw address: try /etc/bluetooth/hosts. */
		struct hostent *he = bt_gethostbyname(addrstr);

		if (he == NULL || he->h_addr_list[0] == NULL)
			errx(1, "cannot resolve '%s'", addrstr);
		memcpy(&addr, he->h_addr_list[0], sizeof(addr));
	}

	if (btmgr_connect_start(node, &addr) < 0)
		err(1, "btmgr_connect_start (need root?)");

	printf("paging %s...\n", addrstr);
	(void)fflush(stdout);

	for (tries = 0; tries < 20; tries++) {
		sleep(1);

		n = (int)(sizeof(conns) / sizeof(conns[0]));
		if (btmgr_conn_list(node, conns, &n) < 0)
			err(1, "btmgr_conn_list");

		for (i = 0; i < n; i++) {
			if (bdaddr_same(&conns[i].bdaddr, &addr)) {
				printf("connected, handle %u\n",
				    conns[i].handle);
				return;
			}
		}
	}

	errx(1, "no connection after 20s");
}

/*
 * Print every adapter. Fills the caller's array so the other views can reuse
 * the first adapter's node name. Returns the number found.
 */
static int
show_adapters(struct btmgr_adapter *ad, int *n)
{
	char	addr[BTMGR_ADDR_STRSIZE];
	int	i;

	if (btmgr_adapter_list(ad, n) < 0)
		err(1, "btmgr_adapter_list");

	if (*n == 0) {
		printf("no Bluetooth adapter found\n");
		return (0);
	}

	for (i = 0; i < *n; i++) {
		printf("adapter %s\n", ad[i].node);
		printf("  address      %s\n", bt_ntoa(&ad[i].bdaddr, addr));
		printf("  name         %s\n",
		    ad[i].name[0] != '\0' ? ad[i].name : "(unknown)");
		printf("  state        %s\n",
		    ad[i].inited ? "inited" : "NOT inited");
		printf("  class        %02x:%02x:%02x\n",
		    ad[i].devclass[2], ad[i].devclass[1], ad[i].devclass[0]);
		printf("  scan         inquiry:%s page:%s\n",
		    ad[i].inquiry_scan ? "on" : "off",
		    ad[i].page_scan ? "on" : "off");
	}

	return (*n);
}

static void
show_conns(const char *node)
{
	struct btmgr_conn	conns[BTMGR_MAX_CONNS];
	char			addr[BTMGR_ADDR_STRSIZE];
	int			n, i;

	n = (int)(sizeof(conns) / sizeof(conns[0]));
	if (btmgr_conn_list(node, conns, &n) < 0)
		err(1, "btmgr_conn_list");

	printf("connections    %d\n", n);
	for (i = 0; i < n; i++)
		printf("  %-17s handle=%-5u %s %s %s\n",
		    bt_ntoa(&conns[i].bdaddr, addr),
		    conns[i].handle,
		    conns[i].acl ? "ACL" : "SCO",
		    conns[i].master ? "master" : "slave",
		    conns[i].encrypted ? "encrypted" : "plain");
}

static void
show_scan(const char *node, int secs)
{
	struct btmgr_device	devs[BTMGR_MAX_SCAN];
	char			addr[BTMGR_ADDR_STRSIZE];
	int			n, i;

	printf("scanning %ds...\n", secs);
	(void)fflush(stdout);

	n = (int)(sizeof(devs) / sizeof(devs[0]));
	if (btmgr_scan(node, secs, devs, &n) < 0)
		err(1, "btmgr_scan");

	if (n == 0) {
		printf("  no devices found\n");
		return;
	}

	for (i = 0; i < n; i++)
		printf("  %-17s %-10s %02x:%02x:%02x  %s\n",
		    bt_ntoa(&devs[i].bdaddr, addr),
		    btmgr_type_name(devs[i].type),
		    devs[i].devclass[2], devs[i].devclass[1],
		    devs[i].devclass[0],
		    devs[i].name[0] != '\0' ? devs[i].name : "(no name)");
}

int
main(int argc, char *argv[])
{
	struct btmgr_adapter	 ad[BTMGR_MAX_ADAPTERS];
	const char		*what, *arg;
	enum verb		 verb;
	size_t			 i;
	int			 n, secs;

	what = (argc > 1) ? argv[1] : "all";
	arg = (argc > 2) ? argv[2] : NULL;
	secs = DEFAULT_SCAN_SECS;

	if (argc > 3)
		usage();

	for (i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++)
		if (strcmp(what, verbs[i].name) == 0)
			break;
	if (i == sizeof(verbs) / sizeof(verbs[0]))
		usage();
	verb = verbs[i].verb;

	/*
	 * Whether the argument is required, optional or refused, in one place.
	 * usage() does not return, so past this switch an argument is non-NULL
	 * for exactly the three verbs that need one.
	 */
	switch (verb) {
	case VERB_CONNECT:
	case VERB_DISCONNECT:
	case VERB_DISCOVERABLE:
		if (arg == NULL)
			usage();
		break;
	case VERB_SCAN:
		if (arg != NULL) {
			secs = parse_positive(arg);
			if (secs < 0)
				usage();
		}
		break;
	default:
		if (arg != NULL)
			usage();
		break;
	}

	/*
	 * Every verb needs to know which adapter to talk to, so list them
	 * first regardless, and print them only when they were asked for.
	 */
	n = (int)(sizeof(ad) / sizeof(ad[0]));
	if (verb == VERB_ADAPTER || verb == VERB_ALL) {
		if (show_adapters(ad, &n) == 0)
			return (1);
	} else {
		if (btmgr_adapter_list(ad, &n) < 0)
			err(1, "btmgr_adapter_list");
		if (n == 0)
			errx(1, "no Bluetooth adapter found");
	}

	/* Privileged verbs. Each does its thing and exits. */
	if (verb == VERB_CONNECT) {
		do_connect(ad[0].node, arg);
		return (0);
	}

	if (verb == VERB_DISCONNECT) {
		int handle = parse_positive(arg);

		if (handle < 0)
			errx(1, "handle must be a positive number");
		if (btmgr_disconnect_start(ad[0].node, (uint16_t)handle,
		    BTMGR_REASON_USER) < 0)
			err(1, "btmgr_disconnect_start (need root?)");
		printf("disconnect requested for handle %d\n", handle);
		return (0);
	}

	if (verb == VERB_DISCOVERABLE) {
		int on;

		if (strcmp(arg, "on") == 0)
			on = 1;
		else if (strcmp(arg, "off") == 0)
			on = 0;
		else
			usage();

		/*
		 * Page scan stays on either way. Turning it off would make us
		 * unreachable even to already-paired devices, which is not
		 * what "not discoverable" means to a user.
		 */
		if (btmgr_set_scan(ad[0].node, on, 1) < 0)
			err(1, "btmgr_set_scan (need root?)");
		printf("discoverable %s\n", on ? "on" : "off");
		return (0);
	}

	if (verb == VERB_CONN || verb == VERB_ALL) {
		if (verb == VERB_ALL)
			printf("\n");
		show_conns(ad[0].node);
	}

	if (verb == VERB_SCAN || verb == VERB_ALL) {
		if (verb == VERB_ALL)
			printf("\n");
		show_scan(ad[0].node, secs);
	}

	return (0);
}

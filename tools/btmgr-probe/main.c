/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btmgr-probe - read-only view of the local Bluetooth state.
 *
 * Exercises libbtmgr with no daemon, no event loop and no privilege. If this
 * works, the foundation the daemon is built on works.
 *
 *	btmgr-probe [adapter | conn | scan [seconds]]
 *
 * With no argument it runs all three.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btmgr.h"

#define	DEFAULT_SCAN_SECS	5

static void	usage(void);
static int	show_adapters(struct btmgr_adapter *, int *);
static void	show_conns(const char *);
static void	show_scan(const char *, int);

static void
usage(void)
{
	fprintf(stderr,
	    "usage: btmgr-probe [adapter | conn | scan [seconds]]\n");
	exit(1);
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
	fflush(stdout);

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
	struct btmgr_adapter	ad[BTMGR_MAX_ADAPTERS];
	const char		*what;
	int			 n, secs;

	what = (argc > 1) ? argv[1] : "all";
	secs = DEFAULT_SCAN_SECS;

	if (strcmp(what, "scan") == 0 && argc > 2) {
		secs = atoi(argv[2]);
		if (secs <= 0)
			usage();
	} else if (argc > 2) {
		usage();
	}

	if (strcmp(what, "all") != 0 && strcmp(what, "adapter") != 0 &&
	    strcmp(what, "conn") != 0 && strcmp(what, "scan") != 0)
		usage();

	/*
	 * Every view needs to know which adapter to talk to, so list them
	 * first regardless of what was asked for, and print them only when
	 * they were asked for.
	 */
	n = (int)(sizeof(ad) / sizeof(ad[0]));
	if (strcmp(what, "adapter") == 0 || strcmp(what, "all") == 0) {
		if (show_adapters(ad, &n) == 0)
			return (1);
	} else {
		if (btmgr_adapter_list(ad, &n) < 0)
			err(1, "btmgr_adapter_list");
		if (n == 0)
			errx(1, "no Bluetooth adapter found");
	}

	if (strcmp(what, "conn") == 0 || strcmp(what, "all") == 0) {
		if (strcmp(what, "all") == 0)
			printf("\n");
		show_conns(ad[0].node);
	}

	if (strcmp(what, "scan") == 0 || strcmp(what, "all") == 0) {
		if (strcmp(what, "all") == 0)
			printf("\n");
		show_scan(ad[0].node, secs);
	}

	return (0);
}
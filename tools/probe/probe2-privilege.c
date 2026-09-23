/* probe2.c - where exactly is the root boundary? */
#include <sys/types.h>
#include <sys/ioctl.h>
#define L2CAP_SOCKET_CHECKED   /* silences bluetooth.h's #warning */
#include <bluetooth.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(void)
{
	struct ng_btsocket_hci_raw_node_debug	dbg;
	struct bt_devinquiry			*ii = NULL;
	char					addr[32];
	int					s, n, i;

	s = bt_devopen("ubt0hci");
	if (s < 0) {
		printf("bt_devopen: FAILED: %s\n", strerror(errno));
		return (1);
	}
	printf("bt_devopen  : ok (fd %d)\n", s);

	/* A privileged ioctl. Read current value, then write it back
	 * unchanged - so if it succeeds nothing actually changes. */
	if (ioctl(s, SIOC_HCI_RAW_NODE_GET_DEBUG, &dbg, sizeof(dbg)) < 0)
		printf("GET_DEBUG   : FAILED: %s\n", strerror(errno));
	else {
		printf("GET_DEBUG   : ok (debug=%d)\n", dbg.debug);
		if (ioctl(s, SIOC_HCI_RAW_NODE_SET_DEBUG, &dbg, sizeof(dbg)) < 0)
			printf("SET_DEBUG   : FAILED: %s  <-- root boundary\n",
			    strerror(errno));
		else
			printf("SET_DEBUG   : ok (no root needed?!)\n");
	}
	bt_devclose(s);

	/* Scanning: sec_filter says INQUIRY is allowed unprivileged. Verify. */
	printf("inquiry     : scanning ~5s ...\n");
	n = bt_devinquiry("ubt0hci", 5, 10, &ii);
	if (n < 0) {
		printf("inquiry     : FAILED: %s\n", strerror(errno));
	} else {
		printf("inquiry     : %d device(s) found\n", n);
		for (i = 0; i < n; i++) {
			char *name = bt_devremote_name_gen("ubt0hci",
			    &ii[i].bdaddr);
			printf("   [%d] %s  class=%02x:%02x:%02x  name=%s\n", i,
			    bt_ntoa(&ii[i].bdaddr, addr),
			    ii[i].dev_class[2], ii[i].dev_class[1],
			    ii[i].dev_class[0],
			    name ? name : "(no name)");
			free(name);
		}
		free(ii);
	}
	return (0);
}

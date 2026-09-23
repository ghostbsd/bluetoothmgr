/*
 * probe.c - datapoint gatherer for BluetoothMgr planning.
 * Answers: what can an UNPRIVILEGED process see via libbluetooth?
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#define L2CAP_SOCKET_CHECKED	/* silences bluetooth.h's #warning */
#include <bluetooth.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * bt_devenum() calls this once per HCI node it finds.
 * `s` is an already-open raw HCI socket bound to that node.
 * Returning 0 means "keep enumerating", >0 means "stop".
 */
static int
on_device(int s, struct bt_devinfo const *di, void *arg)
{
	struct ng_btsocket_hci_raw_con_list	cl;
	char					addr[32];
	int					i;

	(void)arg;	/* we passed NULL; silence -Wunused-parameter */

	printf("node        : %s\n", di->devname);
	printf("bdaddr      : %s\n", bt_ntoa(&di->bdaddr, addr));
	printf("state       : 0x%08x (%s)\n", di->state,
	    (di->state & NG_HCI_UNIT_INITED) ? "inited" : "NOT inited");
	printf("acl buf     : size=%u pkts=%u free=%u\n",
	    di->acl_size, di->acl_pkts, di->acl_free);
	printf("features[0] : 0x%02x\n", di->features[0]);

	/* Does an unprivileged socket get the connection list? */
	memset(&cl, 0, sizeof(cl));
	cl.num_connections = NG_HCI_MAX_CON_NUM;
	cl.connections = calloc(NG_HCI_MAX_CON_NUM, sizeof(ng_hci_node_con_ep));
	if (cl.connections == NULL)
		return (0);

	if (ioctl(s, SIOC_HCI_RAW_NODE_GET_CON_LIST, &cl, sizeof(cl)) < 0) {
		printf("con list    : FAILED: %s\n", strerror(errno));
	} else {
		printf("con list    : %u connection(s)\n", cl.num_connections);
		for (i = 0; i < (int)cl.num_connections; i++)
			printf("   [%d] %s handle=%u type=%s\n", i,
			    bt_ntoa(&cl.connections[i].bdaddr, addr),
			    cl.connections[i].con_handle,
			    cl.connections[i].link_type == NG_HCI_LINK_ACL
			        ? "ACL" : "SCO");
	}
	free(cl.connections);

	return (0);	/* keep going */
}

int
main(void)
{
	int n;

	printf("=== bt_devenum() ===\n");
	n = bt_devenum(on_device, NULL);
	if (n < 0) {
		printf("bt_devenum FAILED: %s\n", strerror(errno));
		return (1);
	}
	printf("total HCI nodes: %d\n", n);
	return (0);
}

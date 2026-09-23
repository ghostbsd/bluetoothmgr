/* probe3.c - adapter readable state + local name + scan enable */
#include <sys/types.h>
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

int
main(void)
{
	struct bt_devreq		r;
	ng_hci_read_local_name_rp	name_rp;
	ng_hci_read_scan_enable_rp	scan_rp;
	ng_hci_read_unit_class_rp	class_rp;
	int				s;

	s = bt_devopen("ubt0hci");
	if (s < 0) { perror("bt_devopen"); return (1); }

	/* Read local (adapter) friendly name. */
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_READ_LOCAL_NAME);
	r.rparam = &name_rp;
	r.rlen = sizeof(name_rp);
	if (bt_devreq(s, &r, 3) < 0)
		printf("local name  : FAILED: %s\n", strerror(errno));
	else
		printf("local name  : \"%s\" (status %d)\n",
		    name_rp.name, name_rp.status);

	/* Read scan enable == the "discoverable"/"connectable" state. */
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_READ_SCAN_ENABLE);
	r.rparam = &scan_rp;
	r.rlen = sizeof(scan_rp);
	if (bt_devreq(s, &r, 3) < 0)
		printf("scan enable : FAILED: %s\n", strerror(errno));
	else
		printf("scan enable : 0x%02x (inquiry_scan=%s page_scan=%s)\n",
		    scan_rp.scan_enable,
		    (scan_rp.scan_enable & 0x1) ? "ON" : "off",
		    (scan_rp.scan_enable & 0x2) ? "ON" : "off");

	/* Read our own class of device. */
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_READ_UNIT_CLASS);
	r.rparam = &class_rp;
	r.rlen = sizeof(class_rp);
	if (bt_devreq(s, &r, 3) < 0)
		printf("unit class  : FAILED: %s\n", strerror(errno));
	else
		printf("unit class  : %02x:%02x:%02x\n", class_rp.uclass[2],
		    class_rp.uclass[1], class_rp.uclass[0]);

	bt_devclose(s);
	return (0);
}

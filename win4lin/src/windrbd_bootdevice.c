#include "drbd_windows.h"
#include "drbd_wingenl.h"
#include "wingenl.h"
#include "drbd_int.h"
#include "windrbd_threads.h"

#include <aux_klib.h>  /* TODO: not needed any more */
#include <stdlib.h>

/* This creates a device on boot (called via wsk init thread).
 * It feeds DRBD via netlink packets to create the boot device.
 */

#define KERNEL_PORT_ID  42

	/* from: drbd-utils/user/shared/libgenl_windrbd.c */

static void fill_in_header(struct sk_buff *skb)
{
        struct nlmsghdr *n = (struct nlmsghdr *)skb->data;

        n->nlmsg_len = skb->tail;
        n->nlmsg_flags |= NLM_F_REQUEST;
        n->nlmsg_pid = KERNEL_PORT_ID;	/* we are kernel */
}

extern struct genl_family drbd_genl_family;

#define SEQ_START 1000

static int reply_code(int cmd)
{
	char reply[NLMSG_GOODSIZE];
	size_t reply_size;
	int i;
	struct nlmsghdr *header;
	struct genlmsghdr *genlmsg_header;
	struct drbd_genlmsghdr *drbd_header;
	static int expected_seq = SEQ_START;

#define MIN_REPLY_SIZE (NLMSG_HDRLEN+GENL_HDRLEN+NLMSG_ALIGN(sizeof(struct drbd_genlmsghdr)))

	for (i=0;i<100;i++) {
		reply_size = windrbd_receive_netlink_packets(reply, sizeof(reply), KERNEL_PORT_ID);
		if (reply_size > 0)
			break;

		msleep(100);
	}
	if (reply_size == 0) {
		printk("Timeout waiting for netlink reply packet.\n");
		return -1;
	}
	if (reply_size < MIN_REPLY_SIZE) {
		printk("Reply too small.\n");
		return -1;
	}

	header = (struct nlmsghdr*) reply;
	genlmsg_header = nlmsg_data(header);
	drbd_header = genlmsg_data(genlmsg_header);

	if (header->nlmsg_pid != KERNEL_PORT_ID) {
		printk("Warning: header->nlmsg_pid(%d) != KERNEL_PORT_ID\n", header->nlmsg_pid, KERNEL_PORT_ID);
		return -1;
	}
	if (genlmsg_header->cmd != cmd) {
		printk("Warning: genlmsg_header->cmd(%d) != DRBD_ADM_NEW_RESOURCE (%d)\n", genlmsg_header->cmd, cmd);
		return -1;
	}
		/* TODO: currently does not work because of races
		 * between two threads. Fix it by having expected
		 * seq per thread.
		 */
	if (header->nlmsg_seq != expected_seq) {
		printk("Warning: header->nlmsg_seq(%d) != expected_seq(%d)\n", header->nlmsg_seq, expected_seq);
	}
	expected_seq++;

	return drbd_header->ret_code;
}

static struct sk_buff *prepare_netlink_packet(int cmd, int minor)
{
	struct sk_buff *skb;
	struct drbd_genlmsghdr *dhdr;
	static int seq = SEQ_START;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		return NULL;

        dhdr = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, cmd);
	seq++;

	dhdr->minor = minor;
	dhdr->flags = 0;

	return skb;
}


static int finish_netlink_packet(struct sk_buff *skb, int cmd)
{
	int ret, rc;

	fill_in_header(skb);
	ret = windrbd_process_netlink_packet(&skb->data, skb->tail);

	nlmsg_free(skb);

	if (ret != 0)
		return ret;

	rc = reply_code(cmd);

		/* connect will return SS_SUCCESS which is 1 */
	if (rc != NO_ERROR && rc != SS_SUCCESS) {
		printk("status is %d\n", rc);
		return rc;
	}
	return 0;
}

static int new_resource(const char *resource_name, int my_node_id)
{
	struct sk_buff *skb;
	struct nlattr *nla;

	skb = prepare_netlink_packet(DRBD_ADM_NEW_RESOURCE, -1);
	if (skb == NULL)
		return -ENOMEM;

	nla = nla_nest_start(skb, DRBD_NLA_CFG_CONTEXT);
	nla_put_string(skb, T_ctx_resource_name, resource_name);
	nla_nest_end(skb, nla);

	nla = nla_nest_start(skb, DRBD_NLA_RESOURCE_OPTS);
	nla_put_u32(skb, T_node_id, my_node_id);
	nla_put_u32(skb, T_on_no_data, OND_SUSPEND_IO);
	nla_nest_end(skb, nla);

	return finish_netlink_packet(skb, DRBD_ADM_NEW_RESOURCE);
}

static int new_minor(const char *resource_name, int minor, int volume)
{
	struct sk_buff *skb;
	struct nlattr *nla;

	skb = prepare_netlink_packet(DRBD_ADM_NEW_MINOR, minor);
	if (skb == NULL)
		return -ENOMEM;

	nla = nla_nest_start(skb, DRBD_NLA_CFG_CONTEXT);
	nla_put_string(skb, T_ctx_resource_name, resource_name);
	nla_put_u32(skb, T_ctx_volume, volume);
	nla_nest_end(skb, nla);

	return finish_netlink_packet(skb, DRBD_ADM_NEW_MINOR);
}

static int new_peer(const char *resource_name, const char *peer_name, int peer_node_id, int protocol)
{
	struct sk_buff *skb;
	struct nlattr *nla;

	skb = prepare_netlink_packet(DRBD_ADM_NEW_PEER, -1);
	if (skb == NULL)
		return -ENOMEM;

	nla = nla_nest_start(skb, DRBD_NLA_CFG_CONTEXT);
	nla_put_string(skb, T_ctx_resource_name, resource_name);
	nla_put_u32(skb, T_ctx_peer_node_id, peer_node_id);
	nla_nest_end(skb, nla);

	nla = nla_nest_start(skb, DRBD_NLA_NET_CONF);
	nla_put_string(skb, T_name, peer_name);
	nla_put_string(skb, T_verify_alg, "crc32c");
	nla_put_u32(skb, T_rcvbuf_size, 0xa00000);
	nla_put_u32(skb, T_sndbuf_size, 0xa00000);
	nla_put_u32(skb, T_timeout, 60*10);
/*	nla_put_u32(skb, T_ping_timeo, 5);
	nla_put_u32(skb, T_ping_int, 10); */
	nla_put_u32(skb, T_connect_int, 120);
	nla_put_u8(skb, T_use_rle, 0);
	nla_put_u32(skb, T_wire_protocol, protocol);
	nla_nest_end(skb, nla);

	return finish_netlink_packet(skb, DRBD_ADM_NEW_PEER);
}

int my_atoi(const char *c)
{
	int i;

	if (c == NULL)
		return 0;

	i=0;
	while (*c >= '0' && *c <= '9') {
		i*=10;
		i+=*c-'0';
		c++;
	}
	return i;
}


	/* TODO: take sockaddr_from_str from drbd-utils */

static int parse_ipv4_addr(struct sockaddr_in *addr, const char *a)
{
	const char *port;

	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	if (my_inet_aton(a, &addr->sin_addr) < 0)
		return -1;

	port = strchr(a, ':');
	if (port == NULL)
		return -1;
	port++;
	addr->sin_port = htons(my_atoi(port));
	return 0;
}

static int new_path(const char *resource_name, int peer_node_id, const char *local_ip, const char *remote_ip)
{
	struct sk_buff *skb;
	struct nlattr *nla;
	struct sockaddr_in my_addr;
	struct sockaddr_in peer_addr;

	if (parse_ipv4_addr(&my_addr, local_ip) < 0)
		return -EINVAL;
	if (parse_ipv4_addr(&peer_addr, remote_ip) < 0)
		return -EINVAL;

	skb = prepare_netlink_packet(DRBD_ADM_NEW_PATH, -1);
	if (skb == NULL)
		return -ENOMEM;

	nla = nla_nest_start(skb, DRBD_NLA_CFG_CONTEXT);
	nla_put_string(skb, T_ctx_resource_name, resource_name);
	nla_put_u32(skb, T_ctx_peer_node_id, peer_node_id);
	nla_nest_end(skb, nla);

	nla = nla_nest_start(skb, DRBD_NLA_PATH_PARMS);
	nla_put(skb, T_my_addr, sizeof(my_addr), &my_addr);
	nla_put(skb, T_peer_addr, sizeof(peer_addr), &peer_addr);
	nla_nest_end(skb, nla);

	return finish_netlink_packet(skb, DRBD_ADM_NEW_PATH);
}

static int connect(const char *resource_name, int peer_node_id)
{
	struct sk_buff *skb;
	struct nlattr *nla;

	skb = prepare_netlink_packet(DRBD_ADM_CONNECT, -1);
	if (skb == NULL)
		return -ENOMEM;

	nla = nla_nest_start(skb, DRBD_NLA_CFG_CONTEXT);
	nla_put_string(skb, T_ctx_resource_name, resource_name);
	nla_put_u32(skb, T_ctx_peer_node_id, peer_node_id);
	nla_nest_end(skb, nla);

	return finish_netlink_packet(skb, DRBD_ADM_CONNECT);
}

static int primary(const char *resource_name)
{
	struct sk_buff *skb;
	struct nlattr *nla;

	skb = prepare_netlink_packet(DRBD_ADM_PRIMARY, -1);
	if (skb == NULL)
		return -ENOMEM;

	nla = nla_nest_start(skb, DRBD_NLA_CFG_CONTEXT);
	nla_put_string(skb, T_ctx_resource_name, resource_name);
	nla_nest_end(skb, nla);

#if 0
	nla = nla_nest_start(skb, DRBD_NLA_SET_ROLE_PARMS);
	nla_put_flag(skb, T_assume_uptodate);	/* primary --force */
	nla_nest_end(skb, nla);
#endif

	return finish_netlink_packet(skb, DRBD_ADM_PRIMARY);
}

static int attach(int minor, const char *backing_dev, const char *meta_dev, int meta_dev_idx)
{
	struct sk_buff *skb;
	struct nlattr *nla;

	skb = prepare_netlink_packet(DRBD_ADM_ATTACH, minor);
	if (skb == NULL)
		return -ENOMEM;

	nla = nla_nest_start(skb, DRBD_NLA_DISK_CONF);
	nla_put_string(skb, T_backing_dev, backing_dev);
	nla_put_string(skb, T_meta_dev, meta_dev);
	nla_put_u32(skb, T_meta_dev_idx, meta_dev_idx);
	nla_nest_end(skb, nla);

	return finish_netlink_packet(skb, DRBD_ADM_ATTACH);
}

/* TODO: later we want to get this parameters via ACPI (or
 * similar approach).
 */

#if 0
#define BOOT_RESOURCE "tiny-windows-boot"
#define BOOT_NUM_NODES 2
#define BOOT_MINOR 1
#define BOOT_VOLUME 1
/* TODO: C: for diskless client, W: for test/dev VM */
#define BOOT_DRIVE L"C:"
#define BOOT_PEER "johannes-VirtualBox"
#define BOOT_PEER_NODE_ID 1
#define BOOT_PROTOCOL 3	/* protocol C */
#define BOOT_MY_ADDRESS "0.0.0.0:7681"
#define BOOT_PEER_ADDRESS "192.168.56.102:7681"
#endif

static struct drbd_params {
	char *resource;
	int num_nodes;
	int minor;
	int volume;
	wchar_t *mount_point; /* might be NULL */
	char *peer;
	int peer_node_id;
	int protocol;	/* 1=A, 2=B or 3=C */
	char *my_address;
	char *peer_address;
} boot_devices[1] = {
	{
		.resource = "tiny-windows-disk",
		.num_nodes = 2,
		.minor = 1,
		.volume = 1,
		.mount_point = NULL, 
		.peer = "johannes-VirtualBox",
		.peer_node_id = 1,
		.protocol = 3,
		.my_address = "0.0.0.0:7683",
		.peer_address = "192.168.56.102:7683"
	}
#if 0
, {
			/* The hidden system partition-> /Device/HarddiskVolume1 , no mount point */
		.resource = "tiny-windows-system",
		.num_nodes = 2,
		.minor = 1,
		.volume = 1,
		.mount_point = L"X:", /* dummy so that Volume symlink is created */
		.peer = "johannes-VirtualBox",
		.peer_node_id = 1,
		.protocol = 3,
		.my_address = "0.0.0.0:7682",
		.peer_address = "192.168.56.102:7682"
	}
#endif
};

static int windrbd_create_boot_device_stage1(struct drbd_params *p)
{
	int ret;
	struct drbd_device *drbd_device;

        drbd_genl_family.id = WINDRBD_NETLINK_FAMILY_ID;

	if ((ret = new_resource(p->resource, p->num_nodes)) != 0)
		return ret;

	if ((ret = new_minor(p->resource, p->minor, p->volume)) != 0)
		return ret;

	/* The Windows device is now created when creating the minor */

	/* The 'mount_point' is now handled by the disk.sys (or partman.sys)
	 * driver, no need to do that here.
	 */

	if ((ret = new_peer(p->resource, p->peer, p->peer_node_id, p->protocol)) != 0)
		return ret;

		/* Since we do not have any interfaces yet, bind listeing
		 * socket to INADDR_ANY, else it will fail an node
		 * will go into standalone.
		 */
	if ((ret = new_path(p->resource, p->peer_node_id, p->my_address, p->peer_address)) != 0)
		return ret;

	drbd_device = minor_to_device(p->minor);
	if (drbd_device != NULL && drbd_device->this_bdev != NULL)
		drbd_device->this_bdev->is_bootdevice = 1;
	else
		printk("internal error: cannot find drbd device for minor %d\n", p->minor);

	return 0;
}

/*
	if ((ret = attach(5, "\\DosDevices\\F:", "\\DosDevices\\G:", -2)) != 0)
		printk("attach failed with error code %d (ignored)\n", ret);
*/

extern int windrbd_wait_for_bus_object(void);

/* This does the networking part of DRBD device setup. We
 * do this in a separate thread so that DriverEntry can
 * exit (and followup drivers can initialize the network)
 */

static int windrbd_create_boot_device_stage2(void *pp)
{
	struct drbd_params *p = pp;
	int ret;

	if ((ret = windrbd_wait_for_network()) < 0)
		return ret;

	/* Usually once network is there, the bus object is also
	 * there (provided it was installed properly by the installer).
	 */

                /* Tell the PnP manager that we are there ... */
	windrbd_rescan_bus();

	if ((ret = connect(p->resource, p->peer_node_id)) != 0)
		return ret;

		/* We are now 'auto-promoting' in the windrbd_device
		 * layer, so no need to call primary() here */

	return 0;
}

/* taken from iPXE: ipxe/acpi.h */

#pragma pack(1)

struct acpi_header {
        /** ACPI signature (4 ASCII characters) */
        uint32_t signature;
        /** Length of table, in bytes, including header */
        uint32_t length;
        /** ACPI Specification minor version number */
        uint8_t revision;
        /** To make sum of entire table == 0 */
        uint8_t checksum;
        /** OEM identification */
        char oem_id[6];
        /** OEM table identification */
        char oem_table_id[8];
        /** OEM revision number */
        uint32_t oem_revision;
        /** ASL compiler vendor ID */
        char asl_compiler_id[4];
        /** ASL compiler revision number */
        uint32_t asl_compiler_revision;
	/** DRBD config */
	char drbd_config[0];
} __attribute__ (( __packed__ ));

#pragma pack()

#define ACPI_SIGNATURE( a, b, c, d ) \
        ( ( (a) << 0 ) | ( (b) << 8 ) | ( (c) << 16 ) | ( (d) << 24 ) )

#define DRBD_SIG ACPI_SIGNATURE ( 'D', 'R', 'B', 'D' )

#define LOWER_MEM_LENGTH 0xa0000

static int search_for_drbd_config(char *drbd_config, size_t buflen)
{
	char *first_1m;
	LARGE_INTEGER zero;
	int i, j;
	struct acpi_header *header;
	uint32_t len;
	uint8_t sum;
	int ret;

	zero.QuadPart = 0;
	first_1m = MmMapIoSpace(zero, LOWER_MEM_LENGTH, MmNonCached);
	if (first_1m == NULL) {
		printk("Couldn't map lower physical memory\n");
		return -1;
	}
	ret = -1;

	for (i=0;i<LOWER_MEM_LENGTH;i+=0x10) {
		header = (struct acpi_header*) (first_1m+i);
		if (header->signature != DRBD_SIG)
			continue;

		len = header->length;
		if (len+i > LOWER_MEM_LENGTH)
			continue;

		if (header->revision != 1)
			continue;

		sum = 0;
		for (j=i;j<i+len;j++)
			sum+=first_1m[j];
		if (sum != 0)
			continue;

		if (len-sizeof(*header) > buflen) {
			printk("Warning: oversized DRBD config (len is %d buflen is %d)\n", len, buflen);
			continue;
		}
		memcpy(drbd_config, &header->drbd_config, len-sizeof(*header));

		ret = 0;
		break;
	}
	MmUnmapIoSpace(first_1m, LOWER_MEM_LENGTH);

	return ret;
}

	/* TODO: this does not work. The ACPI driver seems to
	 * parse the signature and throw away tables with unknown
	 * signatures. Linux behaves the same, but on the other
	 * hand, searches in lower memory for the iBFT (iSCSI)
	 * signature by hand.
	 *
	 * Delete this code if it is certain that it isn't needed.
	 */

static int read_acpi_table(void)
{
	NTSTATUS status;
	ULONG size;
	char buf[4096];	/* TODO: which maximum is defined? */
	DWORD all_ids[100];
	ULONG ids_bytes;
	int i;

	status = AuxKlibInitialize();
	if (status != STATUS_SUCCESS) {
		printk("Couldn't initialize AuxKlib, status is %x\n", status);
		return -EINVAL;
	}

	status = AuxKlibEnumerateSystemFirmwareTables('ACPI', all_ids, sizeof(all_ids), &ids_bytes);
	if (status != STATUS_SUCCESS) {
		printk("Couldn't iterate over ACPI IDs\n");
	} else {
		printk("%d bytes returned by AuxKlibEnumerateSystemFirmwareTables()\n", ids_bytes);

		for (i=0;i<ids_bytes/sizeof(all_ids[0]);i++) {
			printk("boot table %d: %c%c%c%c\n", i, all_ids[i] & 0xff, (all_ids[i] >> 8) & 0xff, (all_ids[i] >> 16) & 0xff, (all_ids[i] >> 24) & 0xff);
		}
	}

	status = AuxKlibGetSystemFirmwareTable('ACPI', 'TFBi', buf, sizeof(buf), &size);

	if (status == STATUS_SUCCESS) {
printk("table DRBD found\n");
		return 0;
	} else {
		printk("error searching for ACPI table DRBD status is %x\n", status);
		printk("Please pass boot parameters via ACPI (use iPXE to do so)\n");
		return -ENOENT;
	}
}

/* We use (for now) a semicolon, since the colon is also used for
 * IPv6 addresses (and for the port number).
 */

#define DRBD_CONFIG_SEPERATOR ';'

/* This function intentionally does not allow for leading spaces. */

static unsigned long my_strtoul(const char *nptr, char ** endptr, int base)
{
	unsigned long val = 0;

	while (isdigit(*nptr)) {
		val *= 10;
		val += (*nptr)-'0';
		nptr++;
	}
	if (endptr)
		*endptr = (char*) nptr;

	return val;
}

static char *my_strndup(const char *s, size_t n)
{
	char *new_string;

	new_string = kmalloc(n+1, 0, 'DRBD');
	if (new_string == NULL)
		return NULL;

	strncpy(new_string, s, n);
	new_string[n] = '\0';

	return new_string;
}

int parse_drbd_params(const char *drbd_config, struct drbd_params *params)
{
	const char *from, *to;
	char *end, *s;

	if (strncmp(drbd_config, "drbd:", 5) != 0) {
		printk("Parse error: drbd URL must start with drbd:\n");
		return -1;
	}
	from = drbd_config+5;
	to = strchr(from, DRBD_CONFIG_SEPERATOR);
	if (to == NULL) {
		printk("Parse error: no semicolon after resource name\n");
		return -1;
	}
	params->resource = my_strndup(from, to-from);
	if (params->resource == NULL) {
		printk("Cannot allocate memory for resource name\n");
		return -ENOMEM;
	}

	to++;
	if (*to != 'A' && *to != 'B' && *to != 'C') {
		printk("Parse error: Protocol must be either (captial) A, B or C\n");
		return -1;
	}
	params->protocol = *to - 0x40;

	to++;
	if (*to != DRBD_CONFIG_SEPERATOR) {
		printk("Parse error: no semicolon after protocol\n");
		return -1;
	}
	to++;

	params->num_nodes = my_strtoul(to, &end, 10);
	if (end == to) {
		printk("Parse error: num-nodes must be a number\n");
		return -1;
	}
	to = end;
	if (*to != DRBD_CONFIG_SEPERATOR) {
		printk("Parse error: no semicolon after protocol\n");
		return -1;
	}
	to++;

	from = to;
	to = strchr(from, DRBD_CONFIG_SEPERATOR);
	if (to == NULL) {
		printk("Parse error: no semicolon after resource name\n");
		return -1;
	}
	params->my_address = my_strndup(from, to-from);
	if (params->my_address == NULL) {
		printk("Cannot allocate memory for resource name\n");
		return -ENOMEM;
	}
	to++;

	params->minor = my_strtoul(to, &end, 10);
	if (end == to) {
		printk("Parse error: num-nodes must be a number\n");
		return -1;
	}
	to = end;
	if (*to != DRBD_CONFIG_SEPERATOR) {
		printk("Parse error: no semicolon after protocol\n");
		return -1;
	}
	to++;

	params->volume = my_strtoul(to, &end, 10);
	if (end == to) {
		printk("Parse error: num-nodes must be a number\n");
		return -1;
	}
	to = end;
	if (*to != DRBD_CONFIG_SEPERATOR) {
		printk("Parse error: no semicolon after protocol\n");
		return -1;
	}
	to++;

	from = to;
	to = strchr(from, DRBD_CONFIG_SEPERATOR);
	if (to == NULL) {
		printk("Parse error: no semicolon after resource name\n");
		return -1;
	}
	params->peer = my_strndup(from, to-from);
	if (params->peer == NULL) {
		printk("Cannot allocate memory for resource name\n");
		return -ENOMEM;
	}
	to++;

	params->peer_node_id = my_strtoul(to, &end, 10);
	if (end == to) {
		printk("Parse error: num-nodes must be a number\n");
		return -1;
	}
	to = end;
	if (*to != DRBD_CONFIG_SEPERATOR) {
		printk("Parse error: no semicolon after protocol\n");
		return -1;
	}
	to++;

	from = to;
	to = strchr(from, DRBD_CONFIG_SEPERATOR);
	if (to == NULL) {
		to = strchr(from, '\0');
	} else {
		printk("Warning: excess arguments after peer-address\n");
	}
	params->peer_address = my_strndup(from, to-from);
	if (params->peer_address == NULL) {
		printk("Cannot allocate memory for resource name\n");
		return -ENOMEM;
	}

	return 0;
}

#define MAX_DRBD_CONFIG 16*1024

void parser_test(void)
{
	struct drbd_params p;

	if (parse_drbd_params("drbd:tiny-windows-disk;C;2;0.0.0.0:7683;1;1;johannes-VirtualBox;1;192.168.56.102:7683", &p) < 0) {
		printk("Parser test: error\n");
	} else {
		printk("Parsertest results: resource: %s num_nodes: %d minor: %d volume: %d peer: %s peer_node_id: %d protocol: %d my_address: %s peer_address: %s", p.resource, p.num_nodes, p.minor, p.volume, p.peer, p.peer_node_id, p.protocol, p.my_address, p.peer_address);
	}
}

void windrbd_init_boot_device(void)
{
	int ret;
	int i;
	static char drbd_config[MAX_DRBD_CONFIG];

	if (search_for_drbd_config(drbd_config, sizeof(drbd_config)) < 0) {
		printk("No DRBD config found in first 1Meg, please use iPXE to boot via network.\n");
		return;
	}
	printk("ACPI table reading successful, creating boot device now\n");

printk("drbd config is %s\n", drbd_config);

	if (parse_drbd_params(drbd_config, &boot_devices[0]) < 0) {
		printk("Error parsing drbd URI (which is '%s') not booting via network\n", drbd_config);
		return;
	}

	for (i=0;i<1;i++) {
		ret = windrbd_create_boot_device_stage1(&boot_devices[i]);
		if (ret != 0)
			printk("Warning: stage1 returned %d for %s\n", ret, boot_devices[i].resource);

		if (kthread_run(windrbd_create_boot_device_stage2, &boot_devices[i], "bootdev") == NULL) {
			printk("Failed to create bootdevice thread.\n");
		}
	}
}

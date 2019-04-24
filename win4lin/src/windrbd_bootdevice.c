#include "drbd_windows.h"
#include "drbd_wingenl.h"
#include "wingenl.h"
#include "drbd_int.h"
#include "windrbd_threads.h"

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

	if (header->nlmsg_seq != expected_seq) {
		printk("Warning: header->nlmsg_seq(%d) != expected_seq(%d)\n", header->nlmsg_seq, expected_seq);
		return -1;
	}
	expected_seq++;
	if (header->nlmsg_pid != KERNEL_PORT_ID) {
		printk("Warning: header->nlmsg_pid(%d) != KERNEL_PORT_ID\n", header->nlmsg_pid, KERNEL_PORT_ID);
		return -1;
	}
	if (genlmsg_header->cmd != cmd) {
		printk("Warning: genlmsg_header->cmd(%d) != DRBD_ADM_NEW_RESOURCE (%d)\n", genlmsg_header->cmd, cmd);
		return -1;
	}

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
} boot_devices[2] = {
	{
			/* The "C:" drive -> /Device/HarddiskVolume2 */
		.resource = "tiny-windows-boot",
		.num_nodes = 2,
		.minor = 2,
		.volume = 1,
		.mount_point = L"W:",	/* C: later */
		.peer = "johannes-VirtualBox",
		.peer_node_id = 1,
		.protocol = 3,
		.my_address = "0.0.0.0:7681",
		.peer_address = "192.168.56.102:7681"
	}, {
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
};


static int windrbd_create_boot_device_stage1(struct drbd_params *p)
{
	int ret;

printk("karin %S\n", p->mount_point);
printk("1\n");
        drbd_genl_family.id = WINDRBD_NETLINK_FAMILY_ID;

printk("2\n");
	if ((ret = new_resource(p->resource, p->num_nodes)) != 0)
		return ret;

printk("3\n");
	if ((ret = new_minor(p->resource, p->minor, p->volume)) != 0)
		return ret;

/* For now, this will also create the mount point. */
/* When booting this should be C: when testing this should be W: */
printk("4\n");
	if (p->mount_point) {
		if ((ret = windrbd_set_mount_point_for_minor_utf16(p->minor, p->mount_point)) != 0)
			printk("Mounting minor %d to %s failed.\n", p->minor, p->mount_point);
	} else {
printk("no mount point for %s\n", p->resource);
	}

printk("5\n");
	if ((ret = new_peer(p->resource, p->peer, p->peer_node_id, p->protocol)) != 0)
		return ret;

		/* Since we do not have any interfaces yet, bind listeing
		 * socket to INADDR_ANY, else it will fail an node
		 * will go into standalone.
		 */
printk("6\n");
	if ((ret = new_path(p->resource, p->peer_node_id, p->my_address, p->peer_address)) != 0)
		return ret;

	return 0;
}

/*
	if ((ret = attach(5, "\\DosDevices\\F:", "\\DosDevices\\G:", -2)) != 0)
		printk("attach failed with error code %d (ignored)\n", ret);
*/

extern int windrbd_wait_for_bus_object(void);

static int windrbd_create_boot_device_stage2(void *pp)
{
	struct drbd_params *p = pp;
	int ret;

printk("7 %s\n", p->resource);
	if ((ret = windrbd_wait_for_network()) < 0)
		return ret;

printk("7-1\n");
	if ((ret = windrbd_wait_for_bus_object()) < 0)
		return ret;
printk("7-2\n");

                /* Tell the PnP manager that we are there ... */
	if (drbd_bus_device != NULL) {
printk("7-3\n");
		IoInvalidateDeviceRelations(drbd_bus_device, BusRelations);
printk("7-4\n");
	} else {
		printk("Warning: no bus objects, Plug and play will not work.\n");
	}

printk("7a %s\n", p->resource);
	if ((ret = connect(p->resource, p->peer_node_id)) != 0)
		return ret;

	while (1) {
printk("8\n");
		ret = primary(p->resource);
printk("9\n");
		if (ret == 0)
			break;
printk("a 123\n");
		msleep(1000);
printk("b\n");
	}
printk("c\n");
	return 0;
}

void windrbd_init_boot_device(void)
{
	int ret;
	int i;

	for (i=0;i<2;i++) {
		ret = windrbd_create_boot_device_stage1(&boot_devices[i]);
		if (ret != 0)
			printk("Warning: stage1 returned %d for %s\n", ret, boot_devices[i].resource);
/*
	ret = windrbd_create_boot_device_stage2(NULL);
	if (ret != 0)
		printk("Warning: stage1 returned %d\n", ret);
*/

		if (kthread_run(windrbd_create_boot_device_stage2, &boot_devices[i], "bootdev") == NULL) {
			printk("Failed to create bootdevice thread.\n");
		}
	}
}

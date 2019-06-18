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

        drbd_genl_family.id = WINDRBD_NETLINK_FAMILY_ID;

	if ((ret = new_resource(p->resource, p->num_nodes)) != 0)
		return ret;

	if ((ret = new_minor(p->resource, p->minor, p->volume)) != 0)
		return ret;

	if ((ret = windrbd_create_windows_device_for_minor(p->minor)) != 0)
		printk("Creating windows device for minor %d failed.\n", p->minor);
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

void windrbd_init_boot_device(void)
{
	int ret;
	int i;

	for (i=0;i<1;i++) {
		ret = windrbd_create_boot_device_stage1(&boot_devices[i]);
		if (ret != 0)
			printk("Warning: stage1 returned %d for %s\n", ret, boot_devices[i].resource);

		if (kthread_run(windrbd_create_boot_device_stage2, &boot_devices[i], "bootdev") == NULL) {
			printk("Failed to create bootdevice thread.\n");
		}
	}
}

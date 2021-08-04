#include "drbd_windows.h"
#include "drbd_wingenl.h"
#include "wingenl.h"
#include "drbd_int.h"
#include "windrbd_threads.h"

struct genl_reply_buffer {
	struct list_head list;
	void *buf;
	size_t len;
};

struct genl_reply {
	struct list_head buffer_list;
	struct list_head list;
	u32 portid;
	ULONGLONG last_used;
};

static LIST_HEAD(reply_buffers);

struct genl_multicast_element {
	struct list_head list;
	u32 portid;
	char name[GENL_NAMSIZ];
	struct _FILE_OBJECT *file_object;
};

static LIST_HEAD(multicast_elements);

static struct mutex genl_reply_mutex;
static struct mutex genl_multicast_mutex;
static struct mutex genl_drbd_mutex;

static struct genl_reply *find_reply(u32 portid)
{
	struct genl_reply *g;
	list_for_each_entry(struct genl_reply, g, &reply_buffers, list) {
		if (g->portid == portid)
			return g;
	}
	return NULL;
}

static struct genl_reply *find_or_create_reply(u32 portid)
{
	struct genl_reply *g;
	g = find_reply(portid);
	if (g == NULL) {
		g = kmalloc(sizeof(*g), 0, 'DRBD');
		if (g == NULL)
			return NULL;
		g->portid = portid;
		INIT_LIST_HEAD(&g->buffer_list);
		list_add(&g->list, &reply_buffers);
	}
	return g;
}

static struct genl_reply_buffer *new_buffer(struct genl_reply *r)
{
	struct genl_reply_buffer *b;

	b = kmalloc(sizeof(*b), 0, 'DRBD');
	if (b == NULL)
		return NULL;

	list_add_tail(&b->list, &r->buffer_list);
	return b;
}

static int next_buffer_size(struct genl_reply *r)
{
	struct genl_reply_buffer *b;

	if (!list_empty(&r->buffer_list)) {
		b = list_first_entry(&r->buffer_list, struct genl_reply_buffer, list);
		return b->len;
	}
	return -1;
}

static struct genl_reply_buffer *next_buffer(struct genl_reply *r)
{
	struct genl_reply_buffer *b;

	if (!list_empty(&r->buffer_list)) {
		b = list_first_entry(&r->buffer_list, struct genl_reply_buffer, list);
		list_del(&b->list);
		return b;
	}
	return NULL;
}

static int delete_reply_if_empty(struct genl_reply *r)
{
	if (list_empty(&r->buffer_list)) {
		list_del(&r->list);
		kfree(r);
		return 1;
	}
	return 0;
}

static void touch(struct genl_reply *r)
{
	if (r)
		r->last_used = jiffies;
}

	/* Must hold genl_multicast_mutex */
static void delete_multicast_elements_for_portid(u32 portid)
{
	struct list_head *lh, *lhn;
	struct genl_multicast_element *m;

	list_for_each_safe(lh, lhn, &multicast_elements) {
		m = list_entry(lh, struct genl_multicast_element, list);
		if (m->portid == portid) {
			list_del(&m->list);
			kfree(m);
		}
	}
}

static void delete_reply(struct genl_reply *r)
{
	struct list_head *bh, *bhn;
	struct genl_reply_buffer *b;
	if (!r)
		return;

	list_for_each_safe(bh, bhn, &r->buffer_list) {
		b = list_entry(bh, struct genl_reply_buffer, list);
		list_del(&b->list);
		kfree(b->buf);
		kfree(b);
	}
	list_del(&r->list);
	kfree(r);
}

static void delete_replies_for_portid(u32 portid)
{
	struct list_head *rh, *rhn;
	struct genl_reply *r;

	list_for_each_safe(rh, rhn, &reply_buffers) {
		r = list_entry(rh, struct genl_reply, list);
		if (r->portid == portid)
			delete_reply(r);
	}
}

static void delete_multicast_elements_and_replies_for_file_object(struct _FILE_OBJECT *f)
{
	struct list_head *lh, *lhn;
	struct genl_multicast_element *m;

	mutex_lock(&genl_multicast_mutex);
	mutex_lock(&genl_reply_mutex);

	list_for_each_safe(lh, lhn, &multicast_elements) {
		m = list_entry(lh, struct genl_multicast_element, list);
		if (m->file_object == f) {
			delete_replies_for_portid(m->portid);
			list_del(&m->list);
			kfree(m);
		}
	}

	mutex_unlock(&genl_reply_mutex);
	mutex_unlock(&genl_multicast_mutex);
}

#define MAX_REPLY_AGE 10

static int run_reaper;
static void *reaper_thread_object;

	/* TODO: this should mostly get away. We now know when
	 * the userland utility exits (device file gets closed)
	 * and should free the memory there instead.
	 */

static NTSTATUS reply_reaper(void *unused)
{
	LARGE_INTEGER interval;
	struct list_head *rh, *rhn;
	struct genl_reply *r;
	ULONGLONG now;

	while (run_reaper) {
		interval.QuadPart = -1*1000*1000;   /* 1/10th second relative */
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
		now = jiffies;

		mutex_lock(&genl_multicast_mutex);
		mutex_lock(&genl_reply_mutex);
		list_for_each_safe(rh, rhn, &reply_buffers) {
			r = list_entry(rh, struct genl_reply, list);
			if (r->last_used + MAX_REPLY_AGE*1000 < now) {
				delete_multicast_elements_for_portid(r->portid);
				delete_reply(r);
			}
		}
		mutex_unlock(&genl_reply_mutex);
		mutex_unlock(&genl_multicast_mutex);

		windrbd_reap_threads();
	}
	return STATUS_SUCCESS;
}

size_t windrbd_receive_netlink_packets(void *vbuf, size_t remaining_size, u32 portid)
{
	struct genl_reply *r;
	struct genl_reply_buffer *b;
	size_t bytes_copied;
	char *buf = vbuf;

	bytes_copied = 0;
	mutex_lock(&genl_reply_mutex);

	r = find_reply(portid);
	if (r == NULL)
		goto out_mutex;

	touch(r);
	for (;;) {
		int nbs = next_buffer_size(r);
		if (nbs == -1)
			break;
		if (nbs > remaining_size)
			break;

		b = next_buffer(r);
		RtlCopyMemory(buf, b->buf, nbs);
		kfree(b->buf);
		kfree(b);

		remaining_size -= nbs;
		bytes_copied += nbs;
		buf += nbs;

		if (delete_reply_if_empty(r))
			break;

			/* Workaround for drbdsetup being not able
			 * to handle multiple packets. Remove this
			 * break if it is fixed.
			 */
		break;
	}
out_mutex:
	mutex_unlock(&genl_reply_mutex);
	return bytes_copied;
}

static int do_genlmsg_unicast(struct sk_buff *skb, u32 portid)
{
	struct genl_reply *reply;
	struct genl_reply_buffer *buffer;
	int ret = -ENOMEM;

	mutex_lock(&genl_reply_mutex);
	reply = find_or_create_reply(portid);
	touch(reply);
	if (reply == NULL)
		goto out_mutex;

	buffer = new_buffer(reply);
	if (buffer == NULL)
		goto out_mutex;

	buffer->buf = kmalloc(skb->len, 0, 'DRBD');
	if (buffer->buf == NULL)
		goto out_mutex;
		/* TODO: clean up. */

	buffer->len = skb->len;
	RtlCopyMemory(buffer->buf, skb->data, skb->len);

	ret = 0;

out_mutex:
	mutex_unlock(&genl_reply_mutex);
	return ret;
}

int genlmsg_unicast(struct sk_buff *skb, struct genl_info *info)
{
	int ret;

	ret = do_genlmsg_unicast(skb, info->snd_portid);
	nlmsg_free(skb);
	return ret;
}

static int do_genl_multicast(struct sk_buff *skb, const char *group_name)
{

	struct genl_multicast_element *m;
	int ret;

	ret = 0;
	mutex_lock(&genl_multicast_mutex);
	list_for_each_entry(struct genl_multicast_element, m, &multicast_elements, list) {
		if (strncmp(m->name, group_name, sizeof(m->name)) == 0) {
			ret = do_genlmsg_unicast(skb, m->portid);
			if (ret != 0)
				break;
		}
	}
	mutex_unlock(&genl_multicast_mutex);

	nlmsg_free(skb);
	return ret;
}

/* This is a generated function originally. It calls genl_multicast
 * with drbd as the genl_family and events as the multicast group.
 * If we really have time we keep that and implement genl_multicast()
 * instead.
 */

int drbd_genl_multicast_events(struct sk_buff * skb, gfp_t flags)
{
	return do_genl_multicast(skb, "events");
}

int windrbd_join_multicast_group(u32 portid, const char *name, struct _FILE_OBJECT *f)
{
	struct genl_multicast_element *m;

	m = kmalloc(sizeof(*m), 0, 'DRBD');
	if (m == NULL)
		return -ENOMEM;

	strncpy(m->name, name, sizeof(m->name)-1);
	m->name[sizeof(m->name)-1] = '\0';
	m->portid = portid;
	m->file_object = f;
	mutex_lock(&genl_multicast_mutex);
	list_add(&m->list, &multicast_elements);
	mutex_unlock(&genl_multicast_mutex);

	return 0;
}

int windrbd_delete_multicast_groups_for_file(struct _FILE_OBJECT *f)
{
		/* maybe TODO: also delete other replies here ..
		 * in that case we won't need the reply_reaper
		 * any more (but how to associate replies with
		 * file objects?)
		 */

	delete_multicast_elements_and_replies_for_file_object(f);

	return 0;
}

/* TODO: into drbd_limits.h */
#define DRBD_MAX_ATTRS 128

static struct genl_info *genl_info_new(struct nlmsghdr * nlh)
{
	struct genl_info *info = kzalloc(sizeof(*info), 0, 'DRBD');
	if (!info)
		return NULL;

	info->attrs = kmalloc(sizeof(*info->attrs)*DRBD_MAX_ATTRS, 0, 'DRBD');
	if (!info->attrs) {
		kfree(info);
		return NULL;
	}
	info->seq = nlh->nlmsg_seq;
	info->nlhdr = nlh;
	info->genlhdr = nlmsg_data(nlh);
	info->userhdr = genlmsg_data(nlmsg_data(nlh));
	info->snd_seq = nlh->nlmsg_seq;
	info->snd_portid = nlh->nlmsg_pid;

	return info;
}

struct sk_buff *genlmsg_new(size_t payload, gfp_t flags)
{
	struct sk_buff *skb;

	skb = kzalloc(sizeof(*skb) + payload, GFP_KERNEL, '67DW');
	if (skb == NULL)
		return NULL;

	skb->len = 0;
	skb->tail = 0;
	skb->end = payload - sizeof(*skb);

	return skb;
}

/**
* nlmsg_free - free a netlink message
* @skb: socket buffer of netlink message
*/

void nlmsg_free(struct sk_buff *skb)
{
	kfree(skb);
}

/* This is a separate thread, since it blocks until Windows has finished
 * booting. It initializes everything we need and then exits. You can
 * ignore the return value.
 */

void windrbd_init_netlink(void)
{
	NTSTATUS    status;
	HANDLE h;

        mutex_init(&genl_drbd_mutex);
        mutex_init(&genl_reply_mutex);
        mutex_init(&genl_multicast_mutex);

	run_reaper = 1;
	status = windrbd_create_windows_thread(reply_reaper, NULL, &reaper_thread_object);
	if (!NT_SUCCESS(status))
		printk(KERN_WARNING "Couldn't start reply reaper (status is %x), expect memory leaks.\n", status);

	printk("Netlink initialized.\n");
}

void windrbd_shutdown_netlink(void)
{
	NTSTATUS status;

	run_reaper = 0;
	status = windrbd_cleanup_windows_thread(reaper_thread_object);

	if (!NT_SUCCESS(status))
		printk("Could not clean up reply reaper, status is %x\n", status);
}

static int _genl_dump(struct genl_ops * pops, struct sk_buff * skb, struct netlink_callback * cb, struct genl_info * info)
{
    struct nlmsghdr * nlh = NULL;
    int err = pops->dumpit(skb, cb);

    if (err == 0)
    {
	nlh = nlmsg_put(skb, cb->nlh->nlmsg_pid, cb->nlh->nlmsg_seq, NLMSG_DONE, GENL_HDRLEN, NLM_F_MULTI);
    }
    else if (err < 0)
    {
	nlh = nlmsg_put(skb, cb->nlh->nlmsg_pid, cb->nlh->nlmsg_seq, NLMSG_DONE, GENL_HDRLEN, NLM_F_ACK);

        // -ENODEV : occured by first drbdadm adjust. response?
        printk("drbd_adm_get_status_all err = %d\n", err);
    }

    if (nlh)
    {
        struct genlmsghdr * hdr = nlmsg_data(nlh);
        hdr->cmd = 0;
        hdr->version = 0;
        hdr->reserved = 0;
    }

    drbd_adm_send_reply(skb, info);

    return err;
}

unsigned long long config_key;
int is_locked = 0;

int lock_interface(const char *config_key_param)
{
	if (is_locked)
		return -EPERM;

	is_locked = 1;
	config_key = my_strtoull(config_key_param, NULL, 16);
	return 0;
}

/* Sort of kernel function, but now (4.18) this is in
 * genl_family_rcv_msg()
 */

static int _genl_ops(struct genl_ops * pops, struct genl_info * pinfo)
{
	if ((pops->flags & GENL_ADMIN_PERM) && (current->is_root == 0))
		return -EPERM;

	/* TODO: and if dump? According to net/netlink/genetlink.c:500
	 * (function genl_family_rcv_msg) this has to be checked first.
	 */
	if (pops->doit)
			/* TODO: NULL? Really? */
		return pops->doit(NULL, pinfo);

	if (pinfo->nlhdr->nlmsg_flags && NLM_F_DUMP)
	{
		int ret;
		struct sk_buff *skb;
		struct netlink_callback ncb;
		int i;

		ncb.nlh = pinfo->nlhdr;
		for (i=0; i<ARRAY_SIZE(ncb.args); i++)
			ncb.args[i] = 0;

		do {
			skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
			if (skb == NULL)
				return -ENOMEM;

			ncb.skb = skb;

				/* This calls drbd_adm_send_reply internally,
				 * which in turn calls genlmsg_free, which
				 * will free the skb (Under Linux it changes
				 * ownership to the network stack, which
				 * eventually also frees it). So we need
				 * a new skb after that.
				 */

			ret = _genl_dump(pops, skb, &ncb, pinfo);
		} while (ret > 0);

		if (pops->done)
			pops->done(&ncb);
        }
	return 0;
}


struct genl_thread_args {
	struct genl_info *info;
	struct genl_ops *op;
	KEVENT completion_event;
	int ret;
};

	/* We need to execute the actual netlink procedure in a separate
	 * thread, else driver verifier will complain (with BSOD) when
	 * we do I/O (ZwQuerySymbolicLinkObject() in attach for example)
	 * while in user mode context.
	 */

static int windrbd_netlink_thread(void *context)
{
	struct genl_thread_args *args = (struct genl_thread_args*) context;

		/* This actually calls the routine in drbd_nl.c */
	args->ret = _genl_ops(args->op, args->info);
	KeSetEvent(&args->completion_event, 0, FALSE);
	return 0;
}

int windrbd_process_netlink_packet(void *msg, size_t msg_size)
{
	struct nlmsghdr *nlh;
	struct genl_info *info;
	int ret;
	NTSTATUS status;
	struct genl_thread_args args;
	struct task_struct *t;

	if (msg == NULL)
		return -EINVAL;

	nlh = (struct nlmsghdr *)msg;
	info = genl_info_new(nlh);
	if (info == NULL)
		return -ENOMEM;

	drbd_tla_parse(nlh, info->attrs);
	if (!nlmsg_ok(nlh, msg_size)) {
		ret = -EINVAL;
		goto out_free_info;
	}
	unsigned int cmd = info->genlhdr->cmd;
	struct genl_ops *op = get_drbd_genl_ops(cmd);

	if (!op) {
		ret = -EINVAL;
		goto out_free_info;
	}
	printk("drbd cmd(%s:%u)\n", windrbd_genl_cmd_to_str(cmd), cmd);

	status = mutex_lock_timeout(&genl_drbd_mutex, CMD_TIMEOUT_SHORT_DEF * 1000);
	if (status != STATUS_SUCCESS) {
		printk("failed to acquire the mutex, probably a previous drbd command is stuck.\n");
		ret = -EAGAIN;
		goto out_free_info;
	}

	args.op = op;
	args.info = info;
	KeInitializeEvent(&args.completion_event, SynchronizationEvent, FALSE);
	args.ret = -ENOMEM;

	t = kthread_run(windrbd_netlink_thread, (void *) &args, "netlink");
	if (IS_ERR(t)) {
		printk("Couldn't create netlink thread, error is %d\n", PTR_ERR(t));
		ret = PTR_ERR(t);
		goto out_unlock_mutex;
	}
	status = KeWaitForSingleObject(&args.completion_event, Executive, KernelMode, FALSE, (PLARGE_INTEGER)NULL);
	if (!NT_SUCCESS(status)) {
		printk("Couldn't wait for netlink thread completion event, status is %x\n", status);
		ret = -ENOMEM;
		goto out_unlock_mutex;
	}
	ret = args.ret;

out_unlock_mutex:
	mutex_unlock(&genl_drbd_mutex);

out_free_info:
	kfree(info->attrs);
	kfree(info);

	return ret;
}

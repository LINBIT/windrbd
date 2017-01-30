#include "drbd_windows.h"
#include "wsk2.h"
#include "drbd_wingenl.h"
#include "linux-compat/idr.h"
#include "Drbd_int.h"
#include "../../drbd/drbd_nla.h"

extern int drbd_tla_parse(struct nlmsghdr *nlh, struct nlattr **attr);

extern int drbd_adm_new_resource(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_del_resource(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_down(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_set_role(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_attach(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_disk_opts(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_detach(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_connect(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_net_opts(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_resize(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_start_ov(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_new_c_uuid(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_disconnect(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_invalidate(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_invalidate_peer(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_pause_sync(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_resume_sync(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_suspend_io(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_resume_io(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_outdate(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_resource_opts(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_get_status(struct sk_buff *skb, struct genl_info *info);
extern int drbd_adm_get_timeout_type(struct sk_buff *skb, struct genl_info *info);
/* .dumpit */
#ifdef _WIN32
extern int drbd_adm_send_reply(struct sk_buff *skb, struct genl_info *info);
#else
extern void drbd_adm_send_reply(struct sk_buff *skb, struct genl_info *info);
#endif

extern int _drbd_adm_get_status(struct sk_buff *skb, struct genl_info * pinfo);

/*
static struct genl_ops drbd_genl_ops[] = {
{ .doit = drbd_adm_new_minor, .flags = 0x01, .cmd = DRBD_ADM_NEW_MINOR, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_del_minor, .flags = 0x01, .cmd = DRBD_ADM_DEL_MINOR, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_new_resource, .flags = 0x01, .cmd = DRBD_ADM_NEW_RESOURCE, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_del_resource, .flags = 0x01, .cmd = DRBD_ADM_DEL_RESOURCE, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_resource_opts, .flags = 0x01, .cmd = DRBD_ADM_RESOURCE_OPTS, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_new_peer, .flags = 0x01, .cmd = DRBD_ADM_NEW_PEER, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_new_path, .flags = 0x01, .cmd = DRBD_ADM_NEW_PATH, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_del_peer, .flags = 0x01, .cmd = DRBD_ADM_DEL_PEER, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_del_path, .flags = 0x01, .cmd = DRBD_ADM_DEL_PATH, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_connect, .flags = 0x01, .cmd = DRBD_ADM_CONNECT, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_net_opts, .flags = 0x01, .cmd = DRBD_ADM_CHG_NET_OPTS, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_disconnect, .flags = 0x01, .cmd = DRBD_ADM_DISCONNECT, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_attach, .flags = 0x01, .cmd = DRBD_ADM_ATTACH, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_disk_opts, .flags = 0x01, .cmd = DRBD_ADM_CHG_DISK_OPTS, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_resize, .flags = 0x01, .cmd = DRBD_ADM_RESIZE, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_set_role, .flags = 0x01, .cmd = DRBD_ADM_PRIMARY, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_set_role, .flags = 0x01, .cmd = DRBD_ADM_SECONDARY, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_new_c_uuid, .flags = 0x01, .cmd = DRBD_ADM_NEW_C_UUID, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_start_ov, .flags = 0x01, .cmd = DRBD_ADM_START_OV, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_detach, .flags = 0x01, .cmd = DRBD_ADM_DETACH, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_invalidate, .flags = 0x01, .cmd = DRBD_ADM_INVALIDATE, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_invalidate_peer, .flags = 0x01, .cmd = DRBD_ADM_INVAL_PEER, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_pause_sync, .flags = 0x01, .cmd = DRBD_ADM_PAUSE_SYNC, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_resume_sync, .flags = 0x01, .cmd = DRBD_ADM_RESUME_SYNC, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_suspend_io, .flags = 0x01, .cmd = DRBD_ADM_SUSPEND_IO, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_resume_io, .flags = 0x01, .cmd = DRBD_ADM_RESUME_IO, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_outdate, .flags = 0x01, .cmd = DRBD_ADM_OUTDATE, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_get_timeout_type, .flags = 0x01, .cmd = DRBD_ADM_GET_TIMEOUT_TYPE, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_down, .flags = 0x01, .cmd = DRBD_ADM_DOWN, .policy = drbd_tla_nl_policy, },
{ .dumpit = drbd_adm_dump_resources, .cmd = DRBD_ADM_GET_RESOURCES, .policy = drbd_tla_nl_policy, },
{ .dumpit = drbd_adm_dump_devices, .done = drbd_adm_dump_devices_done, .cmd = DRBD_ADM_GET_DEVICES, .policy = drbd_tla_nl_policy, },
{ .dumpit = drbd_adm_dump_connections, .done = drbd_adm_dump_connections_done, .cmd = DRBD_ADM_GET_CONNECTIONS, .policy = drbd_tla_nl_policy, },
{ .dumpit = drbd_adm_dump_peer_devices, .done = drbd_adm_dump_peer_devices_done, .cmd = DRBD_ADM_GET_PEER_DEVICES, .policy = drbd_tla_nl_policy, },
{ .dumpit = drbd_adm_get_initial_state, .cmd = DRBD_ADM_GET_INITIAL_STATE, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_forget_peer, .flags = 0x01, .cmd = DRBD_ADM_FORGET_PEER, .policy = drbd_tla_nl_policy, },
{ .doit = drbd_adm_peer_device_opts, .flags = 0x01, .cmd = DRBD_ADM_CHG_PEER_DEVICE_OPTS, .policy = drbd_tla_nl_policy, },
};
*/

/*
static struct genl_family drbd_genl_family  = {
	.id = 0,
	.name = "drbd",
	.version = 2,

	.hdrsize = (((sizeof(struct drbd_genlmsghdr)) + 4 - 1) & ~(4 - 1)),
	.maxattr = (sizeof(drbd_tla_nl_policy) / sizeof((drbd_tla_nl_policy)[0]))-1,
};
*/

#define cli_info(_minor, _fmt, ...)

// globals

extern struct mutex g_genl_mutex;

static ERESOURCE    genl_multi_socket_res_lock;

PTR_ENTRY gSocketList =
{
    .slink = { .Next = NULL },
    .ptr = NULL,
};

/**
* @brief    Multicast를 위한 socket 포인터를 list에 push 한다.
*/
static bool push_msocket_entry(void * ptr)
{
    if (!ptr)
    {
        return FALSE;
    }

    PPTR_ENTRY entry = (PPTR_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(PTR_ENTRY), '57DW');
	if (!entry) {
		return FALSE;
	}
    entry->ptr = ptr;

    MvfAcquireResourceExclusive(&genl_multi_socket_res_lock);

    PushEntryList(&gSocketList.slink, &(entry->slink));
    //WDRBD_TRACE("Added entry(0x%p), slink(0x%p), socket(0x%p)\n", entry, entry->slink, entry->ptr);

    MvfReleaseResource(&genl_multi_socket_res_lock);

	return TRUE;
}

/**
* @brief    socket 포인터 list에서 argument 포인터를 list에서 pop한다.
*/
static PPTR_ENTRY pop_msocket_entry(void * ptr)
{
    PPTR_ENTRY ret = NULL;
    PSINGLE_LIST_ENTRY iter = &gSocketList.slink;

    MvfAcquireResourceExclusive(&genl_multi_socket_res_lock);

    while (iter)
    {
        PPTR_ENTRY socket_entry = (PPTR_ENTRY)CONTAINING_RECORD(iter->Next, PTR_ENTRY, slink);

        if (socket_entry && socket_entry->ptr == ptr)
        {
            //WDRBD_TRACE("socket_entry(0x%p), slink(0x%p), socket(0x%p) found in list\n", socket_entry, socket_entry->slink, socket_entry->ptr);
            iter->Next = PopEntryList(iter->Next);

            ExFreePool(socket_entry);
            ret = socket_entry;
            break;
        }
        iter = iter->Next;
    }

    MvfReleaseResource(&genl_multi_socket_res_lock);

    return NULL;
}

/**
* @brief    multicast를 위한 전역 소켓 리스트 변수(gSocketList)를 활용하여
*           리스트내에 있는 socket으로 모두 send를 보내는 일을 한다.
*/
int drbd_genl_multicast_events(struct sk_buff * skb, const struct sib_info *sib)
{
    int ret = 0;

    if (!skb)
    {
        return EINVAL;
    }

    PSINGLE_LIST_ENTRY iter = &gSocketList.slink;

    MvfAcquireResourceShared(&genl_multi_socket_res_lock);

    while (iter)
    {
        PPTR_ENTRY socket_entry = (PPTR_ENTRY)CONTAINING_RECORD(iter->Next, PTR_ENTRY, slink);

        if (socket_entry)
        {
            //WDRBD_TRACE("send socket(0x%p), data(0x%p), len(%d)\n", socket_entry->ptr, skb->data, skb->len);
#ifdef _WIN32  // _WIN32_SEND_BUFFING
			int sent = SendLocal(socket_entry->ptr, skb->data, skb->len, 0, 0);
#endif
            if (sent != skb->len)
            {
                WDRBD_WARN("Failed to send socket(0x%x)\n", socket_entry->ptr);
            }
        }

        iter = iter->Next;
    }

    MvfReleaseResource(&genl_multi_socket_res_lock);

    nlmsg_free(skb);

    return ret;
}

NTSTATUS reply_error(int type, int flags, int error, struct genl_info * pinfo)
{
    struct sk_buff * reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

    if (reply_skb)
    {
#ifdef _WIN32
		struct nlmsghdr * nlh = nlmsg_put((struct msg_buff*)reply_skb, pinfo->nlhdr->nlmsg_pid,
			pinfo->nlhdr->nlmsg_seq, type, GENL_HDRLEN, flags);
#else
		struct nlmsghdr * nlh = nlmsg_put(reply_skb, pinfo->nlhdr->nlmsg_pid,
			pinfo->nlhdr->nlmsg_seq, type, GENL_HDRLEN, flags);
#endif
        if (nlh)
        {
            struct nlmsgerr * err = nlmsg_data(nlh);
            err->error = -error;
            err->msg.nlmsg_len = 0;

            drbd_adm_send_reply(reply_skb, pinfo);
        }
        nlmsg_free(reply_skb);
    }
    else
    {
        return STATUS_NO_MEMORY;
    }
              
    return STATUS_SUCCESS;
}

static int _genl_dump(struct genl_ops * pops, struct sk_buff * skb, struct netlink_callback * cb, struct genl_info * info)
{
    struct nlmsghdr * nlh = NULL;
    int err = pops->dumpit(skb, cb);

    if (0 == err)
    {
#ifdef _WIN32
		nlh = nlmsg_put((struct msg_buff*)skb, cb->nlh->nlmsg_pid, cb->nlh->nlmsg_seq, NLMSG_DONE, GENL_HDRLEN, NLM_F_MULTI);
#else
		nlh = nlmsg_put(skb, cb->nlh->nlmsg_pid, cb->nlh->nlmsg_seq, NLMSG_DONE, GENL_HDRLEN, NLM_F_MULTI);
#endif
    }
    else if (err < 0)
    {
#ifdef _WIN32
		nlh = nlmsg_put((struct msg_buff*)skb, cb->nlh->nlmsg_pid, cb->nlh->nlmsg_seq, NLMSG_DONE, GENL_HDRLEN, NLM_F_ACK);
#else
		nlh = nlmsg_put(skb, cb->nlh->nlmsg_pid, cb->nlh->nlmsg_seq, NLMSG_DONE, GENL_HDRLEN, NLM_F_ACK);
#endif
        
        // -ENODEV : occured by first drbdadm adjust. response?
        WDRBD_WARN("drbd_adm_get_status_all err = %d\n", err);
    }

    if (nlh)
    {
        struct genlmsghdr * hdr = nlmsg_data(nlh);
        hdr->cmd = 0;
        hdr->version = 0;
        hdr->reserved = 0;
    }

	if(drbd_adm_send_reply(skb, info) < 0) {
		err = -1;
	}

    WDRBD_TRACE_NETLINK("send_reply(%d) seq(%d)\n", err, cb->nlh->nlmsg_seq);

    return err;
}

int genlmsg_unicast(struct sk_buff *skb, struct genl_info *info)
{
    int sent;

    if (info->NetlinkSock == 0)
    {
        return -1; // return non-zero!
    }
#ifdef _WIN32 // _WIN32_SEND_BUFFING
	if ((sent = SendLocal(info->NetlinkSock, skb->data, skb->len, 0, 0)) == (skb->len))
#endif
    {
        return 0; // success
    }
    else
    {
        WDRBD_WARN("sent Error=0x%x. sock=%p, data=%p sz=%d\n", sent, info->NetlinkSock, skb->data, skb->len);
        return -2; // return non-zero!
    }
}

NPAGED_LOOKASIDE_LIST drbd_workitem_mempool;
NPAGED_LOOKASIDE_LIST genl_info_mempool;
NPAGED_LOOKASIDE_LIST genl_msg_mempool;

typedef struct _NETLINK_WORK_ITEM{
    WORK_QUEUE_ITEM Item;
    PWSK_SOCKET Socket;
} NETLINK_WORK_ITEM, *PNETLINK_WORK_ITEM;

// DW-1229: using global attr may cause BSOD when we receive plural netlink requests. use local attr.
struct genl_info * genl_info_new(struct nlmsghdr * nlh, PWSK_SOCKET socket, struct nlattr **attrs)
{
    struct genl_info * pinfo = ExAllocateFromNPagedLookasideList(&genl_info_mempool);

    if (!pinfo)
    {
        WDRBD_ERROR("Failed to allocate (struct genl_info) memory. size(%d)\n",
            sizeof(struct genl_info));
        return NULL;
    }

    RtlZeroMemory(pinfo, sizeof(struct genl_info));

    pinfo->seq = nlh->nlmsg_seq;
    pinfo->nlhdr = nlh;
    pinfo->genlhdr = nlmsg_data(nlh);
    pinfo->userhdr = genlmsg_data(nlmsg_data(nlh));
    pinfo->attrs = attrs;
    pinfo->snd_seq = nlh->nlmsg_seq;
    pinfo->snd_portid = nlh->nlmsg_pid;
    pinfo->NetlinkSock = socket;

    return pinfo;
}

__inline
void _genlmsg_init(struct sk_buff * pmsg, size_t size)
{
    RtlZeroMemory(pmsg, size);

    pmsg->tail = 0;
    pmsg->end = size - sizeof(*pmsg);
}

struct sk_buff *genlmsg_new(size_t payload, gfp_t flags)
{
    struct sk_buff *skb;

    if (NLMSG_GOODSIZE == payload)
    {
        payload = NLMSG_GOODSIZE - sizeof(*skb);
        skb = ExAllocateFromNPagedLookasideList(&genl_msg_mempool);
        RtlZeroMemory(skb, NLMSG_GOODSIZE);
    }
    else
    {
        skb = kmalloc(sizeof(*skb) + payload, GFP_KERNEL, '67DW');
    }

    if (!skb)
        return NULL;

    _genlmsg_init(skb, sizeof(*skb) + payload);

    return skb;
}

/**
* nlmsg_free - free a netlink message
* @skb: socket buffer of netlink message
*/
__inline void nlmsg_free(struct sk_buff *skb)
{
    ExFreeToNPagedLookasideList(&genl_msg_mempool, skb);
}

void
InitWskNetlink(void * pctx)
{
    NTSTATUS    status;
    PWSK_SOCKET netlink_socket = NULL;
    SOCKADDR_IN LocalAddress = {0};

    // Init WSK
    status = SocketsInit();
    if (!NT_SUCCESS(status))
    {
        WDRBD_ERROR("Failed to init. status(0x%x)\n", status);
        return;
    }

    // Init WSK Event Callback
    status = InitWskEvent();
    if (!NT_SUCCESS(status))
    {
        return;
    }

    //WDRBD_INFO("Start\n");

    netlink_socket = CreateSocketEvent(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP,
        WSK_FLAG_LISTEN_SOCKET);

    if (!netlink_socket)
    {
        WDRBD_ERROR("Failed to create socket\n");
        goto end;
    }

    LocalAddress.sin_family = AF_INET;
    LocalAddress.sin_addr.s_addr = INADDR_ANY;
    LocalAddress.sin_port = HTONS(g_netlink_tcp_port);

    status = Bind(netlink_socket, (PSOCKADDR)&LocalAddress);
    if (!NT_SUCCESS(status))
    {
        WDRBD_ERROR("Failed to bind. status(0x%x)\n", status);
        CloseSocket(netlink_socket);
    }

    netlink_server_socket = netlink_socket;

    ExInitializeNPagedLookasideList(&drbd_workitem_mempool, NULL, NULL,
        0, sizeof(struct _NETLINK_WORK_ITEM), '27DW', 0);
    ExInitializeNPagedLookasideList(&genl_info_mempool, NULL, NULL,
        0, sizeof(struct genl_info), '37DW', 0);
    ExInitializeNPagedLookasideList(&genl_msg_mempool, NULL, NULL,
        0, NLMSG_GOODSIZE, '47DW', 0);

    ExInitializeResourceLite(&genl_multi_socket_res_lock);

end:
    ReleaseProviderNPI();

    PsTerminateSystemThread(status);
}

NTSTATUS
ReleaseWskNetlink()
{
    ExDeleteNPagedLookasideList(&drbd_workitem_mempool);
    ExDeleteNPagedLookasideList(&genl_info_mempool);
    ExDeleteNPagedLookasideList(&genl_msg_mempool);

    ExDeleteResourceLite(&genl_multi_socket_res_lock);
    
    return CloseWskEventSocket();
}
#if 0
static int w_connect(struct drbd_work *w, int cancel)
{
	struct connect_work* pcon_work = container_of(w, struct connect_work, w);
	struct drbd_resource* resource = pcon_work->resource;
	LARGE_INTEGER		timeout;
	NTSTATUS			status;

	timeout.QuadPart = (-1 * 10000 * 6000);   // wait 6000 ms relative

	pcon_work->ops.doit(NULL, &pcon_work->info);
	WDRBD_INFO("w_connect:\n");

	status = KeWaitForSingleObject(&resource->workerdone, Executive, KernelMode, FALSE, &timeout);
	if (status == STATUS_TIMEOUT) {
		WDRBD_INFO("w_connect:KeWaitForSingleObject timeout\n");
	}

	kfree(pcon_work);

	return 0;
}
#endif

static int _genl_ops(struct genl_ops * pops, struct genl_info * pinfo)
{
	if (pops->doit)
    {
#if 0
		struct drbd_config_context adm_ctx;

		if (pinfo->genlhdr->cmd == DRBD_ADM_CONNECT) {
			struct connect_work* pcon_work = NULL;
			struct drbd_resource* resource = NULL;
			pcon_work = kmalloc(sizeof(*pcon_work), GFP_ATOMIC, 'F1DW');
			if (pcon_work) {
				pcon_work->w.cb = w_connect;
				RtlCopyMemory(&pcon_work->ops, pops, sizeof(*pops));
				RtlCopyMemory(&pcon_work->info, pinfo, sizeof(*pinfo));
				resource = get_resource_from_genl_info(pinfo);
				pcon_work->resource = resource;
				if (resource) {
					drbd_queue_work(&resource->work, &pcon_work->w);
					return 0;
				}
			}
			return ERR_RES_NOT_KNOWN;
		}
		else if (pinfo->genlhdr->cmd == DRBD_ADM_DISCONNECT) {
			struct disconnect_work* pdiscon_work;
		}
#endif
        return pops->doit(NULL, pinfo);
    }

    if (pinfo->nlhdr->nlmsg_flags && NLM_F_DUMP)
    {
        struct sk_buff * skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

        if (skb)
        {
            struct netlink_callback ncb = {
                .skb = skb,
                .nlh = pinfo->nlhdr,
                .args = { 0, }
            };
            
            int ret = _genl_dump(pops, skb, &ncb, pinfo);
			int cnt = 0;
            while (ret > 0) {
                RtlZeroMemory(skb, NLMSG_GOODSIZE);
                _genlmsg_init(skb, NLMSG_GOODSIZE);

                ret = _genl_dump(pops, skb, &ncb, pinfo);
				if(cnt++ > 512) {
					WDRBD_WARN("_genl_dump exceed process break;\n");
					break;
				}
            }

            if (pops->done)
            {
                pops->done(&ncb);
            }

            nlmsg_free(skb);
        }

        return 0;
    }

	return 0;
}

VOID
NetlinkWorkThread(PVOID context)
{
    ASSERT(context);

    PWSK_SOCKET socket = ((PNETLINK_WORK_ITEM)context)->Socket;
    LONG readcount, minor = 0;
    int err = 0, errcnt = 0;
    struct genl_info * pinfo = NULL;

    ct_add_thread(KeGetCurrentThread(), "drbdcmd", FALSE, '25DW');
    //WDRBD_INFO("Thread(%s-0x%p) IRQL(%d) socket(0x%p)------------- start!\n", current->comm, current->pid, KeGetCurrentIrql(), pctx);

    void * psock_buf = ExAllocateFromNPagedLookasideList(&genl_msg_mempool);

    if (!psock_buf)
    {
        WDRBD_ERROR("Failed to allocate NP memory. size(%d)\n", NLMSG_GOODSIZE);
        goto cleanup;
    }

    while (TRUE)
    {
        readcount = Receive(socket, psock_buf, NLMSG_GOODSIZE, 0, 0);

        if (readcount == 0)
        {
            //WDRBD_INFO("peer closed\n"); // disconenct 명령??
            goto cleanup;
        }
        else if(readcount < 0)
        {
            WDRBD_ERROR("Receive error = 0x%x\n", readcount);
            goto cleanup;
        }

		struct nlmsghdr *nlh = (struct nlmsghdr *)psock_buf;

        if (strstr(psock_buf, DRBD_EVENT_SOCKET_STRING))
        {
			WDRBD_TRACE("DRBD_EVENT_SOCKET_STRING received. socket(0x%p)\n", socket);
			if (!push_msocket_entry(socket)) {
				goto cleanup;
			}

			if (strlen(DRBD_EVENT_SOCKET_STRING) < readcount)
			{
				nlh = (struct nlmsghdr *)((char*)psock_buf + strlen(DRBD_EVENT_SOCKET_STRING));
				readcount -= strlen(DRBD_EVENT_SOCKET_STRING);
			}
			else
			{
				continue;
			}
        }

        if (pinfo)
            ExFreeToNPagedLookasideList(&genl_info_mempool, pinfo);
		
		// DW-1229: using global attr may cause BSOD when we receive plural netlink requests. use local attr.
		struct nlattr *local_attrs[128];

		pinfo = genl_info_new(nlh, socket, local_attrs);
        if (!pinfo)
        {
            WDRBD_ERROR("Failed to allocate (struct genl_info) memory. size(%d)\n", sizeof(struct genl_info));
            goto cleanup;
        }

        drbd_tla_parse(nlh, local_attrs);
        if (!nlmsg_ok(nlh, readcount))
        {
            WDRBD_ERROR("rx message(%d) crashed!\n", readcount);
            goto cleanup;
        }

        WDRBD_TRACE_NETLINK("rx(%d), len(%d), cmd(%d), flags(0x%x), type(0x%x), seq(%d), pid(%d)\n",
            readcount, nlh->nlmsg_len, pinfo->genlhdr->cmd, nlh->nlmsg_flags, nlh->nlmsg_type, nlh->nlmsg_seq, nlh->nlmsg_pid);

        // check whether resource suspended
        struct drbd_genlmsghdr * gmh = pinfo->userhdr;
        if (gmh)
        {
            minor = gmh->minor;
            struct drbd_conf * mdev = minor_to_device(minor);
#ifdef _WIN32
            if (mdev && drbd_suspended(mdev))
#else
            if (mdev && (drbd_suspended(mdev) || test_bit(SUSPEND_IO, &mdev->flags)))
#endif
            {
                reply_error(NLMSG_ERROR, NLM_F_MULTI, EIO, pinfo);
                WDRBD_WARN("minor(%d) suspended\n", gmh->minor);
                goto cleanup;
            }
        }

        int i;
        u8 cmd = pinfo->genlhdr->cmd;
        struct genl_ops * pops = get_drbd_genl_ops(cmd);

        if (pops)
        {
			NTSTATUS status = STATUS_UNSUCCESSFUL;

            WDRBD_INFO("drbd cmd(%s:%u)\n", pops->str, cmd);
            cli_info(gmh->minor, "Command (%s:%u)\n", pops->str, cmd);
			
			status = mutex_lock_timeout(&g_genl_mutex, CMD_TIMEOUT_SHORT_DEF * 1000);

			if (STATUS_SUCCESS == status)
			{
				err = _genl_ops(pops, pinfo);
				mutex_unlock(&g_genl_mutex);
				if (err)
				{
					WDRBD_ERROR("Failed while operating. cmd(%u), error(%d)\n", cmd, err);
					errcnt++;
				}
			}
			else
			{
				WDRBD_WARN("Failed to acquire the mutex : 0x%x\n", status);
			}

        }
        else
        {
            WDRBD_WARN("Not validated cmd(%d)\n", cmd);
        }
    }

cleanup:
    pop_msocket_entry(socket);
    Disconnect(socket);
    CloseSocket(socket);
    ct_delete_thread(KeGetCurrentThread());
    ExFreeToNPagedLookasideList(&drbd_workitem_mempool, context);
    if (pinfo)
        ExFreeToNPagedLookasideList(&genl_info_mempool, pinfo);
    if (psock_buf)
        ExFreeToNPagedLookasideList(&genl_msg_mempool, psock_buf);

    if (errcnt)
    {
        WDRBD_ERROR("done. error occured %d times\n", errcnt);
    }
    else
    {
        WDRBD_INFO("done\n");
    }
}

// Listening socket callback which is invoked whenever a new connection arrives.
NTSTATUS
WSKAPI
NetlinkAcceptEvent(
_In_  PVOID         SocketContext,
_In_  ULONG         Flags,
_In_  PSOCKADDR     LocalAddress,
_In_  PSOCKADDR     RemoteAddress,
_In_opt_  PWSK_SOCKET AcceptSocket,
_Outptr_result_maybenull_ PVOID *AcceptSocketContext,
_Outptr_result_maybenull_ CONST WSK_CLIENT_CONNECTION_DISPATCH **AcceptSocketDispatch
)
{
    UNREFERENCED_PARAMETER(Flags);

    if (AcceptSocket == NULL)
    {
        // If WSK provider makes a WskAcceptEvent callback with NULL 
        // AcceptSocket, this means that the listening socket is no longer
        // functional. The WSK client may handle this situation by trying
        // to create a new listening socket or by restarting the driver, etc.
        // In this sample, we will attempt to close the existing listening
        // socket and create a new one. Note that the AcceptEvent
        // callback is guaranteed to be invoked with a NULL AcceptSocket
        // by the WSK subsystem only *once*. So, we can safely use the same
        // operation context that was originally used for enqueueing the first
        // WskSampleStartListen operation on the listening socket. The
        // WskSampleStartListen operation will close the existing listening
        // socket and create a new one.
        return STATUS_REQUEST_NOT_ACCEPTED;
    }

    SOCKADDR_IN * premote = (SOCKADDR_IN *)RemoteAddress;
    SOCKADDR_IN * plocal = (SOCKADDR_IN *)LocalAddress;

    DbgPrint("\n");
    WDRBD_TRACE_NETLINK("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u connected\n",
        premote->sin_addr.S_un.S_un_b.s_b1,
        premote->sin_addr.S_un.S_un_b.s_b2,
        premote->sin_addr.S_un.S_un_b.s_b3,
        premote->sin_addr.S_un.S_un_b.s_b4,
        HTON_SHORT(premote->sin_port),
        plocal->sin_addr.S_un.S_un_b.s_b1,
        plocal->sin_addr.S_un.S_un_b.s_b2,
        plocal->sin_addr.S_un.S_un_b.s_b3,
        plocal->sin_addr.S_un.S_un_b.s_b4,
        HTON_SHORT(plocal->sin_port));

    PNETLINK_WORK_ITEM netlinkWorkItem = ExAllocateFromNPagedLookasideList(&drbd_workitem_mempool);

    if (!netlinkWorkItem)
    {
        WDRBD_ERROR("Failed to allocate NP memory. size(%d)\n", sizeof(NETLINK_WORK_ITEM));
        return STATUS_REQUEST_NOT_ACCEPTED;
    }

    netlinkWorkItem->Socket = AcceptSocket;

	ExInitializeWorkItem(&netlinkWorkItem->Item,
		NetlinkWorkThread,
		netlinkWorkItem);

	ExQueueWorkItem(&netlinkWorkItem->Item, DelayedWorkQueue);
    return STATUS_SUCCESS;
}


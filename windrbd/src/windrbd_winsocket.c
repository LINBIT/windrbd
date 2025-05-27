/* Uncomment this if you want more debug output (disable for releases) */
// #define DEBUG 1

#ifdef RELEASE
#ifdef DEBUG
#undef DEBUG
#endif
#endif

#include "windrbd_config.h"
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/gfp.h>
#include <linux/printk.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/rwlock.h>
#include <linux/kthread.h>
#include <pseh/pseh2.h>

#include <wsk.h>
#include <windef.h>

#include <windrbd_internal.h>

struct net init_net;

/* Protects from API functions being called before the WSK provider is
 * initialized (see SocketsInit).
 */
/* TODO: resource deallocation via goto's */

/* TODO: store type of wsk socket (WSK_FLAG_XXX) in socket and check it..
 * the Dispatcher cast is dangerous.
 */

/* TODO: !! have refcnt on struct socket. Reason is that there might
 * be use-after-free (in the completion handler) when the socket
 * is shut down.
 */

/* Done: In theory, stack can be swapped out while waiting for
 * the EVENTs (they are on the stack). See KeSetKernelStackSwapEnable()
 * To fix use:
 *	completion_event = kmalloc(sizeof(*completion_event));
 * instead of events on the stack.
 *
 * Update: yes this really happens!
 * Update: Now we disabled stack swapping in the WinDRBD thread library.
 */

#define WSK_DEINITIALIZED	0
#define WSK_DEINITIALIZING	1
#define WSK_INITIALIZING	2
#define WSK_INITIALIZED		3

static LONG wsk_state = WSK_DEINITIALIZED;

static struct _KEVENT net_initialized_event;

static WSK_REGISTRATION		g_WskRegistration;
static WSK_PROVIDER_NPI		g_WskProvider;
static WSK_CLIENT_DISPATCH	g_WskDispatch = { MAKE_WSK_VERSION(1, 0), 0, NULL };

static int winsock_to_linux_error(NTSTATUS status)
{
	if (status != STATUS_SUCCESS)
		printk("got status %x\n", status);

	switch (status) {
	case STATUS_SUCCESS:
		return 0;
	case STATUS_CONNECTION_RESET:
		return -ECONNRESET;
	case STATUS_CONNECTION_DISCONNECTED:
		return -ECONNRESET;
	case STATUS_CONNECTION_ABORTED:
//		printk("Got STATUS_CONNECTION_ABORTED returning -ECONNRESET ...\n");
		return -ECONNRESET;	/* was: -ECONNABORTED */
	case STATUS_IO_TIMEOUT:
	case STATUS_TIMEOUT:
		return -EAGAIN;
	case STATUS_INVALID_DEVICE_STATE:
		return -EINVAL;
	case STATUS_NETWORK_UNREACHABLE:
		return -ENETUNREACH;
	case STATUS_HOST_UNREACHABLE:
		return -EHOSTUNREACH;
	case STATUS_CONNECTION_REFUSED:
		return -ECONNREFUSED;
	case STATUS_ACCESS_DENIED:  /* returned when port is blocked by firewall, retry again later */
		/* Do not log this: logfile may get 150GB ... */
//		printk("Got STATUS_ACCESS_DENIED, please check your firewall settings\n");
		return -EAGAIN;
	case STATUS_LOCAL_DISCONNECT: /* Sent by ReactOS on connection timeout */
//		printk("Got STATUS_LOCAL_DISCONNECT returning -ECONNRESET ...\n");
		return -ECONNRESET;


	case STATUS_REMOTE_DISCONNECT:	/* Sometimes they happen on ReactOS */
//		printk("Got STATUS_REMOTE_DISCONNECT returning -ECONNRESET ...\n");
		return -ECONNRESET;

	case STATUS_FILE_CLOSED:
//		printk("Got STATUS_FILE_CLOSED returning -ECONNRESET ...\n");
		return -ECONNRESET;

	case STATUS_CANCELLED:
		return -EINTR;

	case STATUS_ADDRESS_ALREADY_EXISTS:
		return -EAGAIN; /* should be -EADDRINUSE, but we want DRBD to retry. */

	default:
		printk("Unknown status %x, returning -EIO.\n", status);
		return -EIO;
	}
}

static void terminate_receive_thread(struct socket *socket)
{
// printk("About to terminate receive thread for socket %p\n", socket);
	if (socket->receive_thread_should_run) {
// printk("1 socket->receive_thread_should_run is %d\n", socket->receive_thread_should_run);
		socket->receive_thread_should_run = false;
// printk("2 socket->receive_thread_should_run is %d\n", socket->receive_thread_should_run);
		wake_up(&socket->buffer_available);
//		wait_for_completion(&socket->receiver_thread_completion);
	}
}

static void sock_really_free(struct kref *kref)
{
	struct socket *socket = container_of(kref, struct socket, kref);

	kfree(socket->receive_buffer);
	kfree(socket->sk);
	kfree(socket);
}

	/* Use this only if socket is valid but socket->wsk_socket is
	 * not.
	 */

static void sock_free_linux_socket(struct socket *socket)
{
	if (socket == NULL)
		return;

// printk("into kref_put(socket %p)\n", socket);
	kref_put(&socket->kref, sock_really_free);
// printk("2\n");
}

static NTSTATUS __attribute__((stdcall)) completion_fire_event(struct _DEVICE_OBJECT *DeviceObject,struct _IRP *irp, void *event_p)
{
	struct _KEVENT *event = event_p;
	/* Must not printk in here, will loop forever. Hence also no
	 * ASSERT.
	 */

	KeSetEvent(event, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS __attribute__((stdcall)) connect_completion(struct _DEVICE_OBJECT *DeviceObject,struct _IRP *irp, void *sock_p)
{
	struct socket *s = sock_p;

	s->is_connected = true;
	wake_up(&s->connected_waitqueue);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS __attribute__((stdcall)) receive_completion(struct _DEVICE_OBJECT *DeviceObject,struct _IRP *irp, void *sock_p)
{
	struct socket *s = sock_p;

// printk("irp->IoStatus.Status is 0x%08x irp->IoStatus.Information is %d\n", irp->IoStatus.Status, irp->IoStatus.Information);

	s->data_received = true;
	wake_up(&s->receive_waitqueue);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS __attribute__((stdcall)) completion_free_irp(struct _DEVICE_OBJECT *DeviceObject,struct _IRP *Irp, void *event)
{
	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;  /* meaning do not touch the irp */
}

	/* Creates a new IRP for use with wsk functions. If CompletionEvent
	 * is non-NULL, it is initialized and completion_fire_event (which
	 * signals the event) is used as completion routine, else
	 * completion_free_irp is used (which just frees the irp).
	 */

static struct _IRP *wsk_new_irp(struct _KEVENT *CompletionEvent, struct socket *s, PIO_COMPLETION_ROUTINE completion_routine)
{
	struct _IRP *irp;

	irp = IoAllocateIrp(1, FALSE);
	if (irp == NULL) {
		dbg("IoAllocateIrp returned NULL, out of IRPs?\n");
		return NULL;
	}
	irp->Tail.Overlay.Thread = PsGetCurrentThread();

	if (CompletionEvent) {
		KeInitializeEvent(CompletionEvent, NotificationEvent, FALSE);
		IoSetCompletionRoutine(irp, completion_fire_event, CompletionEvent, TRUE, TRUE, TRUE);
	} else if (s) {
		IoSetCompletionRoutine(irp, completion_routine, s, TRUE, TRUE, TRUE);
	} else {
		IoSetCompletionRoutine(irp, completion_free_irp, NULL, TRUE, TRUE, TRUE);
	}
	return irp;
}

static NTSTATUS InitWskBuffer(
	__in  PVOID		Buffer,
	__in  ULONG		BufferSize,
	__out PWSK_BUF	WskBuffer,
	__in  BOOLEAN	bWriteAccess,
	__in  BOOLEAN	may_printk
)
{
	int probe_and_lock_failed;
	int retries;
	NTSTATUS Status = STATUS_SUCCESS;

	WskBuffer->Offset = 0;
	WskBuffer->Length = BufferSize;

	WskBuffer->Mdl = IoAllocateMdl(Buffer, BufferSize, FALSE, FALSE, NULL);
	if (!WskBuffer->Mdl) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	retries = 0;
	while (1) {
		probe_and_lock_failed = 0;
#ifdef CONFIG_HAVE_SEH2
		_SEH2_TRY {
#endif
			MmProbeAndLockPages(WskBuffer->Mdl, KernelMode, bWriteAccess?IoWriteAccess:IoReadAccess);
#ifdef CONFIG_HAVE_SEH2
		}
		_SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
			probe_and_lock_failed = 1;
		}
		_SEH2_END;
#endif

		if (probe_and_lock_failed == 0) {
                        if (may_printk && retries > 0)
                                printk("succeeded after %d retries\n", retries);
			break;
		}
		if (may_printk && retries % 10 == 0)
			printk(KERN_ERR "MmProbeAndLockPages failed, retrying ...\n");

                if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
                        if (may_printk && retries == 0)
                                printk("cannot sleep now, busy looping\n");
                } else {
                        msleep(100);
                }
                retries++;
	}
	return Status;
}

static VOID FreeWskBuffer(
__in PWSK_BUF WskBuffer,
int may_printk
)
{
	if (WskBuffer->Mdl->MdlFlags & MDL_PAGES_LOCKED) {
		int unlock_max_loops;
		MmUnlockPages(WskBuffer->Mdl);

			/* TODO: do we still need this: */
		unlock_max_loops=100;
		while ((WskBuffer->Mdl->MdlFlags & MDL_PAGES_LOCKED) && (unlock_max_loops > 0)) {
			unlock_max_loops--;
			MmUnlockPages(WskBuffer->Mdl); 
		}
	} else {
		if (may_printk)
			printk("Page not locked in FreeWskBuffer\n");
	}
	IoFreeMdl(WskBuffer->Mdl);
}

struct send_page_completion_info {
	struct page *page;
	char *data_buffer;
	struct _WSK_BUF *wsk_buffer;
	struct socket *socket;
	struct _MDL *the_mdl;	/* copy of the pointer. For debugging. */
};

	/* We track active completions to see if there is the completion
	 * routine called twice on the same completion. This is most likely
	 * due to a Windows bug which occurs after 2-3 days of running
	 * an I/O test.
	 */

struct allocated_completions {
	struct send_page_completion_info *completion;
	struct list_head list;
};

static LIST_HEAD(completions);
static spinlock_t completions_lock;

static int remove_completion_locked(struct send_page_completion_info *c)
{
	struct list_head *lh, *lhn;
	struct allocated_completions *alloc_completion;
	int n = 0;
	int m = 0;

	list_for_each_safe(lh, lhn, &completions) {
		alloc_completion = list_entry(lh, struct allocated_completions, list);
		if (alloc_completion->completion == c) {
			list_del(&alloc_completion->list);
			kfree(alloc_completion);
			n++;
		}
		m++;
	}
// printk("%d completions in the queue.\n", m);
	if (n == 0)
		return -ENOENT;
	if (n == 1)
		return 0;

	return -EINVAL;
}

static int remove_completion(struct send_page_completion_info *c)
{
	int rv;
	KIRQL flags;

	spin_lock_irqsave(&completions_lock, flags);
	rv = remove_completion_locked(c);
	spin_unlock_irqrestore(&completions_lock, flags);

	return rv;
}

static int add_completion(struct send_page_completion_info *c)
{
	int rv;
	KIRQL flags;
	struct allocated_completions *new_completion;

	new_completion = kmalloc(sizeof(*new_completion), GFP_KERNEL);
	if (new_completion == NULL)
		return -ENOMEM;

	spin_lock_irqsave(&completions_lock, flags);
	rv = remove_completion_locked(c);

	if (rv != -ENOENT) {
		spin_unlock_irqrestore(&completions_lock, flags);
		kfree(new_completion);
		return -EEXIST;
	}
	new_completion->completion = c;
	list_add(&new_completion->list, &completions);

	spin_unlock_irqrestore(&completions_lock, flags);
	return 0;
}

static void have_sent(struct socket *socket, size_t length)
{
	KIRQL flags;

	spin_lock_irqsave(&socket->send_buf_counters_lock, flags);
	socket->sk->sk_wmem_queued -= length;
	socket->num_sends_inflight--;
	spin_unlock_irqrestore(&socket->send_buf_counters_lock, flags);

	KeSetEvent(&socket->data_sent, IO_NO_INCREMENT, FALSE);
}

static NTSTATUS __attribute__((stdcall)) SendPageCompletionRoutine(struct _DEVICE_OBJECT	*DeviceObject, struct _IRP *Irp,void *completion_p)
{
	struct send_page_completion_info *completion = completion_p;
	int may_printk = completion->socket->wsk_flags != WSK_FLAG_DATAGRAM_SOCKET;
	size_t length;

	if (Irp->IoStatus.Status != STATUS_SUCCESS) {
		int new_status = winsock_to_linux_error(Irp->IoStatus.Status);

		if (new_status != -EAGAIN && new_status != -EINTR) {
			if (may_printk && completion->socket->error_status != 0 &&
			    completion->socket->error_status != new_status)
				dbg(KERN_WARNING "Last error status of socket was %d, now got %d (ntstatus %x)\n", completion->socket->error_status, new_status, Irp->IoStatus.Status);

/* TODO: completion->socket may be NULL here? */
			completion->socket->error_status = new_status;
		}
	} else {
			/* Only for connectionless sockets: clear error
			 * status (they may "repair" themselves).
			 */
		if (completion->socket->wsk_flags == WSK_FLAG_DATAGRAM_SOCKET)
			completion->socket->error_status = 0;
	}

	length = completion->wsk_buffer->Length;
		/* Also unmaps the pages of the containg Mdl */

		/* TODO: remove that again: */
	if (completion->the_mdl != NULL && completion->the_mdl != completion->wsk_buffer->Mdl) {
		if (may_printk)
			printk("Warning: Mdl field changed from %p to %p\n", completion->the_mdl, completion->wsk_buffer->Mdl);
		/* completion->wsk_buffer->Mdl = completion->the_mdl */
	}
	FreeWskBuffer(completion->wsk_buffer, may_printk);

		/* To avoid unmapping the page again in free_bio(). */
	if (completion->page)
		completion->page->is_unmapped = 1;

	kfree(completion->wsk_buffer);

	have_sent(completion->socket, length);

	if (completion->page)
		put_page(completion->page); /* Might free the page if connection is already down */

	if (completion->data_buffer) {	/* Is from SendPage, do not printk */
#if (defined KMALLOC_DEBUG) && (defined WINNT_52)
		ExFreePoolWithTag(completion->data_buffer, DRBD_TAG);
#else
		kfree(completion->data_buffer);
#endif
		if (completion->socket != NULL)
		        kref_put(&completion->socket->kref, sock_really_free);
	} else {
		if (completion->socket != NULL)
		        kref_put(&completion->socket->kref, sock_really_free);
	}

	kfree(completion);

	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

int duplicate_completions;

static NTSTATUS __attribute__((stdcall)) send_page_completion_onlyonce(struct _DEVICE_OBJECT *DeviceObject, struct _IRP	*Irp, void *completion_p)
{
	struct send_page_completion_info *completion = completion_p;
	int err;

	err = remove_completion(completion);
	if (err != 0) {
		duplicate_completions++;
		return STATUS_MORE_PROCESSING_REQUIRED;
	}
	return SendPageCompletionRoutine(DeviceObject, Irp, completion);
}

	/* NO printk's here it is in the UDP send path. */

static int wait_for_sendbuf(struct socket *socket, size_t want_to_send)
{
	KIRQL flags;
	LARGE_INTEGER timeout;
	NTSTATUS status;
	void *wait_objects[2];
	int num_objects;

	while (1) {
		spin_lock_irqsave(&socket->send_buf_counters_lock, flags);

/*
		if (socket->sk->sk_wmem_queued > socket->sk->sk_sndbuf ||
		    socket->num_sends_inflight > 1000) { // TODO: make configurable
*/
		if (socket->sk->sk_wmem_queued > socket->sk->sk_sndbuf) {
			spin_unlock_irqrestore(&socket->send_buf_counters_lock, flags);

			timeout.QuadPart = -1 * socket->sk->sk_sndtimeo * 10 * 1000 * 1000 / HZ;

	/* TODO: once it is fixed, use wait_event_interruptible() here. */

			wait_objects[0] = &socket->data_sent;
			num_objects = 1;
			if (current->has_sig_event) {
				wait_objects[1] = &current->sig_event;
				num_objects = 2;
			}
			status = KeWaitForMultipleObjects(num_objects, &wait_objects[0], WaitAny, Executive, KernelMode, FALSE, &timeout, NULL);

			switch (status) {
			case STATUS_WAIT_0:
				continue;
			case STATUS_WAIT_1:
				return -EINTR;
			case STATUS_TIMEOUT:
					/* Returning -ETIMEOUT here causes
					 * the connection to be disconnected
					 * which we don't want here. DRBD
					 * knows how to handle this.
					 */
				return -EAGAIN;
			default:
				dbg("KeWaitForMultipleObjects returned unexpected error %x\n", status);
				return winsock_to_linux_error(status);
			}
		} else {
			socket->sk->sk_wmem_queued += want_to_send;
			socket->num_sends_inflight++;
			spin_unlock_irqrestore(&socket->send_buf_counters_lock, flags);
			return 0;
		}
			/* TODO: if socket closed meanwhile return an error */
			/* TODO: need socket refcount for doing so */
	}
}

/* Library initialization routine: registers us and waits for
 * provider NPI to become ready (which may take some time on boot,
 * so do not call from DriverEntry, call it in a separate thread)
 */

static NTSTATUS SocketsInit(void)
{
	static WSK_CLIENT_NPI	WskClient = { 0 };
	NTSTATUS		Status;

	if (InterlockedCompareExchange(&wsk_state, WSK_INITIALIZING, WSK_DEINITIALIZED) != WSK_DEINITIALIZED)
		return STATUS_ALREADY_REGISTERED;

	WskClient.ClientContext = NULL;
	WskClient.Dispatch = &g_WskDispatch;

	Status = WskRegister(&WskClient, &g_WskRegistration);
	if (!NT_SUCCESS(Status)) {
		InterlockedExchange(&wsk_state, WSK_DEINITIALIZED);
		return Status;
	}

	printk("WskCaptureProviderNPI start.\n");
	Status = WskCaptureProviderNPI(&g_WskRegistration, WSK_INFINITE_WAIT, &g_WskProvider);
	printk("WskCaptureProviderNPI done.\n"); // takes long time! msg out after MVL loaded.

	if (!NT_SUCCESS(Status)) {
		printk(KERN_ERR "WskCaptureProviderNPI() failed with status 0x%08X\n", Status);
		WskDeregister(&g_WskRegistration);
		InterlockedExchange(&wsk_state, WSK_DEINITIALIZED);
		return Status;
	}

	InterlockedExchange(&wsk_state, WSK_INITIALIZED);
	KeSetEvent(&net_initialized_event, 0, FALSE);
	return STATUS_SUCCESS;
}

int windrbd_wait_for_network(void)
{
	NTSTATUS status;

	status = KeWaitForSingleObject(&net_initialized_event, Executive, KernelMode, FALSE, NULL);
	if (status != STATUS_SUCCESS) {
		printk("KeWaitForSingleObject returned %x when waiting for network event\n", status);
		return -1;
	}
	return 0;
}

/* Deregister network programming interface (NPI) and wsk. Reverse of
 * SocketsInit()
 */

static void SocketsDeinit(void)
{
	if (InterlockedCompareExchange(&wsk_state, WSK_INITIALIZED, WSK_DEINITIALIZING) != WSK_INITIALIZED)
		return;
	WskReleaseProviderNPI(&g_WskRegistration);
	WskDeregister(&g_WskRegistration);

	InterlockedExchange(&wsk_state, WSK_DEINITIALIZED);
}

static int disconnect_socket(struct socket *socket)
{
	struct _KEVENT event;
	struct _IRP *irp;
	NTSTATUS status;

	if (wsk_state != WSK_INITIALIZED || socket == NULL)
		return -EINVAL;

	if (socket->wsk_flags != WSK_FLAG_CONNECTION_SOCKET)
		return 0;

	irp = wsk_new_irp(&event, NULL, NULL);
	if (irp == NULL)
		return -ENOMEM;

	status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) socket->wsk_socket->Dispatch)->WskDisconnect(socket->wsk_socket, NULL, 0, irp);

	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = irp->IoStatus.Status;
	}
	if (!NT_SUCCESS(status))
		printk("WskDisconnect returned error status 0x%08x\n", status);

	IoFreeIrp(irp);

	return winsock_to_linux_error(status);
}

static int CreateSocket(
	ADDRESS_FAMILY		AddressFamily,
	USHORT			SocketType,
	ULONG			Protocol,
	PVOID			SocketContext,
	struct _WSK_CLIENT_LISTEN_DISPATCH *Dispatch,
	ULONG			Flags,
	struct _WSK_SOCKET		**out
)
{
	KEVENT			CompletionEvent = { 0 };
	PIRP			Irp = NULL;
	NTSTATUS		Status;

	/* NO _printk HERE, WOULD LOOP */
	if (wsk_state != WSK_INITIALIZED || out == NULL)
		return -EINVAL;

	Irp = wsk_new_irp(&CompletionEvent, NULL, NULL);
	if (Irp == NULL)
		return -ENOMEM;

	Status = g_WskProvider.Dispatch->WskSocket(
				g_WskProvider.Client,
				AddressFamily,
				SocketType,
				Protocol,
				Flags,
				SocketContext,
				Dispatch,
				NULL,
				NULL,
				NULL,
				Irp);

	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	if (NT_SUCCESS(Status))
		*out = (struct _WSK_SOCKET*) Irp->IoStatus.Information;

	IoFreeIrp(Irp);
	return winsock_to_linux_error(Status);
}

static struct _WSK_SOCKET *get_accept_socket(struct socket *listening_socket)
{
	KIRQL flags;
	struct _WSK_SOCKET *ws = NULL;

	if (listening_socket->accept_wsk_sockets == NULL)
		return NULL;

	spin_lock_irqsave(&listening_socket->accept_socket_lock, flags);

	if (listening_socket->accept_sockets_head != listening_socket->accept_sockets_tail) {
		ws = listening_socket->accept_wsk_sockets[listening_socket->accept_sockets_tail];
		listening_socket->accept_sockets_tail++;
		if (listening_socket->accept_sockets_tail >= listening_socket->num_accept_sockets)
			listening_socket->accept_sockets_tail = 0;
	}

	spin_unlock_irqrestore(&listening_socket->accept_socket_lock, flags);

	return ws;
}

static int put_accept_socket(struct socket *listening_socket, struct _WSK_SOCKET *accept_socket)
{
	KIRQL flags;
	int old_accept_sockets_head;

	if (listening_socket->accept_wsk_sockets == NULL)
		return -EINVAL;

	spin_lock_irqsave(&listening_socket->accept_socket_lock, flags);
	old_accept_sockets_head = listening_socket->accept_sockets_head;

	listening_socket->accept_sockets_head++;
	if (listening_socket->accept_sockets_head >= listening_socket->num_accept_sockets)
		listening_socket->accept_sockets_head = 0;

	if (listening_socket->accept_sockets_head == listening_socket->accept_sockets_tail) {
		listening_socket->accept_sockets_head = old_accept_sockets_head;

		spin_unlock_irqrestore(&listening_socket->accept_socket_lock, flags);
		return -ENOBUFS;
	}
	listening_socket->accept_wsk_sockets[old_accept_sockets_head] = accept_socket;

	spin_unlock_irqrestore(&listening_socket->accept_socket_lock, flags);

	return 0;
}

	/* Use this only to close a newly created wsk_socket which
	 * does not have a Linux socket yet (e.g. in accept when
	 * creating Linux socket fails).
	 */

static void close_wsk_socket(struct _WSK_SOCKET *wsk_socket)
{
	struct _IRP *Irp;

	if (wsk_state != WSK_INITIALIZED || wsk_socket == NULL)
		return;

	Irp = wsk_new_irp(NULL, NULL, NULL);
	if (Irp == NULL)
		return;

	(void) ((PWSK_PROVIDER_BASIC_DISPATCH) wsk_socket->Dispatch)->WskCloseSocket(wsk_socket, Irp);
}


	/* We do not wait for completion here, errors are ignored.
	 */

static void close_socket(struct socket *socket)
{
	struct _IRP *Irp;

	if (wsk_state != WSK_INITIALIZED || socket == NULL)
		return;

	if (socket->is_closed) {
// printk("Socket already closed, refusing to close it again.\n");
		return;
	}

// printk("terminate_receive_thread ...\n");
	terminate_receive_thread(socket);

	Irp = wsk_new_irp(NULL, NULL, NULL);
	if (Irp == NULL)
		return;

	if (socket->accept_wsk_sockets != NULL) {
		struct _WSK_SOCKET *ws;

		while ((ws = get_accept_socket(socket)) != NULL) {
			close_wsk_socket(ws);
		}
		kfree(socket->accept_wsk_sockets);
		socket->accept_wsk_sockets = NULL;
	}

	if (socket->wsk_socket != NULL) {
		mutex_lock(&socket->wsk_mutex);

		/* gracefully disconnect if this is a connection oriented
		 * socket.
		 */
		disconnect_socket(socket);

		(void) ((PWSK_PROVIDER_BASIC_DISPATCH) socket->wsk_socket->Dispatch)->WskCloseSocket(socket->wsk_socket, Irp);
		socket->wsk_socket = NULL;

		mutex_unlock(&socket->wsk_mutex);
	}
	socket->error_status = 0;
	socket->is_closed = 1;	/* TODO: can it be reopened? Then we need to reset this flag. */
}

static int wsk_getname(struct socket *socket, struct sockaddr *uaddr, int peer)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	status;

	if (peer == 0)
		return -EOPNOTSUPP;

	if (wsk_state != WSK_INITIALIZED || socket == NULL || socket->wsk_socket == NULL)
		return -EINVAL;

	Irp = wsk_new_irp(&CompletionEvent, NULL, NULL);
	if (Irp == NULL)
		return -ENOMEM;

	status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) socket->wsk_socket->Dispatch)->WskGetRemoteAddress(socket->wsk_socket, uaddr, Irp);
	if (status != STATUS_SUCCESS)
	{
		if (status == STATUS_PENDING) {
			KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
			status = Irp->IoStatus.Status;
		}
	}
	IoFreeIrp(Irp);

	if (status == STATUS_SUCCESS) {
		dbg("peer address is %s\n", my_inet_ntoa(&((struct sockaddr_in*) uaddr)->sin_addr));
		return sizeof(*uaddr);
	}

	return winsock_to_linux_error(status);
}

static int wsk_connect(struct socket *socket, struct sockaddr *vaddr, int sockaddr_len, int flags)
{
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_SUCCESS;

		/* TODO: check/implement those: */
	(void) sockaddr_len;
	(void) flags;

	if (wsk_state != WSK_INITIALIZED || socket == NULL || socket->wsk_socket == NULL || vaddr == NULL)
		return -EINVAL;

	Irp = wsk_new_irp(NULL, socket, connect_completion);
	if (Irp == NULL)
		return -ENOMEM;

	socket->is_connected = false;
	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) socket->wsk_socket->Dispatch)->WskConnect(
		socket->wsk_socket,
		vaddr,
		0,
		Irp);

	if (Status == STATUS_PENDING) {
		int ret;

		ret = wait_event_interruptible(
			socket->connected_waitqueue,
			socket->is_connected);

		if (ret == -EINTR) {	/* Signal was sent */
			IoCancelIrp(Irp);
			IoFreeIrp(Irp);

			return ret;
		}
		Status = STATUS_SUCCESS;
	}

	if (Status == STATUS_SUCCESS)
	{
		Status = Irp->IoStatus.Status;
		if (Status == STATUS_SUCCESS) {
			socket->sk->sk_state = TCP_ESTABLISHED;
			wake_up(&socket->buffer_available);
			wake_up(&socket->data_available);
		}
	}
	IoFreeIrp(Irp);

	return winsock_to_linux_error(Status);
}

static int sock_create_linux_socket(struct socket **out, unsigned short type);

int kernel_accept(struct socket *socket, struct socket **newsock, int io_flags)
{
	int err;
	struct _WSK_SOCKET *wsk_socket;
	struct socket *accept_socket;

	if (wsk_state != WSK_INITIALIZED || socket == NULL || socket->wsk_socket == NULL)
		return -EINVAL;

	if (socket->accept_wsk_sockets == NULL) {
		printk("Warning: accept() without listen() called.\n");
		return -EINVAL;
	}

	do {
		wsk_socket = get_accept_socket(socket);

		if (wsk_socket == NULL) {
			if ((io_flags & O_NONBLOCK) != 0)
				return -EWOULDBLOCK;

			/* TODO: handle signals */
			KeWaitForSingleObject(&socket->accept_event, Executive, KernelMode, FALSE, NULL);
		}
	} while (wsk_socket == NULL);

	err = sock_create_linux_socket(&accept_socket, SOCK_STREAM);
	if (err < 0)
		close_wsk_socket(wsk_socket);
	else {
		accept_socket->wsk_socket = wsk_socket;
		accept_socket->wsk_flags = WSK_FLAG_CONNECTION_SOCKET;
		accept_socket->sk->sk_state = TCP_ESTABLISHED;
		accept_socket->sk->sk_state_change = socket->sk->sk_state_change;
		accept_socket->sk->sk_user_data = socket->sk->sk_user_data;

		wake_up(&accept_socket->buffer_available);
		wake_up(&accept_socket->data_available);
		*newsock = accept_socket;
	}

	return err;
}

	/* TODO: Or use the ControlSocket function */

static int wsk_set_event_callbacks(struct socket *socket, int mask)
{
	KEVENT CompletionEvent;
	PIRP Irp;
	NTSTATUS Status;
	WSK_EVENT_CALLBACK_CONTROL callbackControl;

	if (wsk_state != WSK_INITIALIZED || socket == NULL || socket->wsk_socket == NULL)
		return -EINVAL;

	Irp = wsk_new_irp(&CompletionEvent, NULL, NULL);
	if (Irp == NULL)
		return -ENOMEM;

	callbackControl.NpiId = &NPI_WSK_INTERFACE_ID;
	callbackControl.EventMask = mask;

	Status = ((PWSK_PROVIDER_BASIC_DISPATCH)socket->wsk_socket->Dispatch)->WskControlSocket(socket->wsk_socket,
	        WskSetOption,
		SO_WSK_EVENT_CALLBACK,
		SOL_SOCKET,
		sizeof(WSK_EVENT_CALLBACK_CONTROL),
		&callbackControl,
		0,
		NULL,
		NULL,
		Irp
        );

	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	return winsock_to_linux_error(Status);
}

/* This just sets the callback event mask, socket->wsk_socket
 * must be a LISTEN socket (WSK_FLAG_LISTEN_SOCKET).
 */

static int wsk_listen(struct socket *socket, int backlog)
{
	if (wsk_state != WSK_INITIALIZED || socket == NULL || socket->wsk_socket == NULL)
		return -EINVAL;

	if (socket->accept_wsk_sockets != NULL) {
		printk("Warning: socket->accept_sockets is != NULL (%p), currently only one call to listen() is supported for a socket\n");
	} else {
		socket->accept_wsk_sockets = kmalloc(sizeof(struct _WSK_SOCKET*)*backlog, GFP_KERNEL);
		if (socket->accept_wsk_sockets == NULL)
			return -ENOMEM;

		socket->num_accept_sockets = backlog;
		socket->accept_sockets_head = 0;
		socket->accept_sockets_tail = 0;
	}

	return wsk_set_event_callbacks(socket, WSK_EVENT_ACCEPT);
}

int kernel_sock_shutdown(struct socket *sock, enum sock_shutdown_cmd how)
{
		/* TODO: one day ... */
	(void) how;

	if (wsk_state != WSK_INITIALIZED || sock == NULL || sock->wsk_socket == NULL)
		return -EINVAL;

	sock->sk->sk_state = 0;
	close_socket(sock);

	return 0;
}

/* Low level sending function. Waits if the send buffer is full.
 * Sends len bytes from buffer buf using connected socket socket.
 * page is just for grabbing a reference to the page (and releasing
 * it in the completion routine) if the buffer is referenced by
 * a page. It may be NULL.
 * RemoteAddress is the remote address if the socket is a datagram
 * (i.e. UDP) socket. In that case WskSendTo (instead of WskSend)
 * will be called.
 */

static ssize_t do_send(struct socket *socket, void *buf, int len, struct page *page, PSOCKADDR RemoteAddress)
{
	struct _IRP *Irp;
	struct _WSK_BUF *WskBuffer;
	struct send_page_completion_info *completion;
	NTSTATUS status;
	int err, err2;
	int flags = 0;
	char *tmp_buffer;

	if (wsk_state != WSK_INITIALIZED || !socket || !socket->wsk_socket || !buf || ((int) len <= 0))
		return -EINVAL;

	if (socket->error_status != 0) {
// printk("error status is already %d returning it\n", socket->error_status);
		return socket->error_status;
}

	if (page)
		get_page(page);	/* we might sleep soon, do this before */

// printk("socket sendbuffer: %d len is %d socket->sk->sk_wmem_queued is %d\n", socket->sk->sk_sndbuf, len, socket->sk->sk_wmem_queued);
	err = wait_for_sendbuf(socket, len);
	if (err < 0)
		goto out_put_page;

	WskBuffer = kzalloc(sizeof(*WskBuffer), GFP_KERNEL);
	if (WskBuffer == NULL) {
		err = -ENOMEM;
		goto out_have_sent;
	}

	completion = kzalloc(sizeof(*completion), GFP_KERNEL);
	if (completion == NULL) {
		err = -ENOMEM;
		goto out_free_wsk_buffer;
	}

#if (defined KMALLOC_DEBUG) && (defined WINNT_52)

	/* We copy what we send to a tmp buffer, so
	 * caller may free or use otherwise what we
	 * have got in Buffer.
	 * Reason is that with kmalloc_debug the allocated
	 * region is not equal the pointer returned. At
	 * least Windows Server 2003 SP2 32 bit has a
	 * problem with that, so use the ExAllocatePoolWithTag
	 * function directory instead of kmalloc() here.
	 */

	if (page != NULL) {
		put_page(page);
		page = NULL;
	}

	tmp_buffer = ExAllocatePoolWithTag(WinDRBDNonPagedPool, len, DRBD_TAG);

	if (tmp_buffer == NULL) {
		err = -ENOMEM;
		goto out_free_completion;
	}
	memcpy(tmp_buffer, buf, len);

	status = InitWskBuffer(tmp_buffer, len, WskBuffer, FALSE, TRUE);
#else
	if (page == NULL) {
		/* We copy what we send to a tmp buffer, so
		 * caller may free or use otherwise what we
		 * have got in Buffer.
		 */

		tmp_buffer = kmalloc(len, GFP_KERNEL);
		if (tmp_buffer == NULL) {
			err = -ENOMEM;
			goto out_free_completion;
		}
		memcpy(tmp_buffer, buf, len);

		status = InitWskBuffer(tmp_buffer, len, WskBuffer, FALSE, TRUE);
	} else {
		tmp_buffer = NULL;
		status = InitWskBuffer(buf, len, WskBuffer, FALSE, TRUE);
	}
#endif
	if (!NT_SUCCESS(status)) {
		err = -ENOMEM;
		goto out_maybe_free_tmp_buffer;
	}

	completion->data_buffer = tmp_buffer;  /* may be NULL */
	completion->page = page;	/* may be NULL */
	completion->wsk_buffer = WskBuffer;
	completion->socket = socket;
	completion->the_mdl = WskBuffer->Mdl;
	kref_get(&socket->kref);

	err2 = add_completion(completion);
	if (err2 != 0) {
		err = -ENOMEM;
		goto out_free_wsk_buffer_mdl;
	}

	Irp = IoAllocateIrp(1, FALSE);
	if (Irp == NULL) {
		err = -ENOMEM;
		goto out_remove_completion;
	}
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	IoSetCompletionRoutine(Irp, send_page_completion_onlyonce, completion, TRUE, TRUE, TRUE);

	if (socket->no_delay)
		flags |= WSK_FLAG_NODELAY;
	else
		flags &= ~WSK_FLAG_NODELAY;

	mutex_lock(&socket->wsk_mutex);

	if (socket->wsk_socket == NULL) {
		err = -ENOTCONN;
		goto out_unlock_mutex;
	}
	if (socket->wsk_flags == WSK_FLAG_DATAGRAM_SOCKET) {
		status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH) socket->wsk_socket->Dispatch)->WskSendTo(
			socket->wsk_socket,
			WskBuffer,
			0,
			RemoteAddress,
			0,
			NULL,
			Irp);
	} else {
		status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) socket->wsk_socket->Dispatch)->WskSend(
			socket->wsk_socket,
			WskBuffer,
			flags,
			Irp);
	}
	mutex_unlock(&socket->wsk_mutex);

	switch (status) {
	case STATUS_PENDING:
			/* This now behaves just like Linux kernel socket
			 * sending functions do for TCP/IP: on return,
			 * the data is queued, if there is an error later
			 * we cannot know now, but a follow-up sending
			 * function will fail. To know about it, we
			 * have a error_status field in our socket struct
			 * which is set by the completion routine on
			 * error.
			 */

// printk("STATUS_PENDING, relaxing a bit ...\n");
// msleep(10);
		return len;

	case STATUS_SUCCESS:
		return (LONG) Irp->IoStatus.Information;
	}
	err = winsock_to_linux_error(status);
	if (err != 0 && err != -ENOMEM && err != -EAGAIN && err != -EINTR)
		socket->error_status = err;

		/* Resources are freed by completion routine. */
// dbg("returning %d\n", err);
	return err;

out_unlock_mutex:
	mutex_unlock(&socket->wsk_mutex);
out_remove_completion:
	remove_completion(completion);
out_free_wsk_buffer_mdl:
        kref_put(&socket->kref, sock_really_free);
	FreeWskBuffer(WskBuffer, 1);
out_maybe_free_tmp_buffer:
	kfree(tmp_buffer);
out_free_completion:
	kfree(completion);
out_free_wsk_buffer:
	kfree(WskBuffer);
out_have_sent:
	have_sent(socket, len);
out_put_page:
	if (page)
		put_page(page);

	if (err != 0 && err != -ENOMEM && err != -EAGAIN && err != -EINTR)
		socket->error_status = err;
	return err;
}

static ssize_t wsk_sendpage(struct socket *socket, struct page *page, int offset, size_t len, int flags)
{
	if (!page)
		return -EINVAL;

	return do_send(socket, (void*) (((unsigned char *) page->addr)+offset), len, page, NULL);
}


	/* TODO: implement MSG_MORE? */
	/* TODO: honor len */

int kernel_sendmsg(struct socket *socket, struct msghdr *msg, struct kvec *vec,
                   size_t num, size_t len)
{
	int i, ret, bytes_sent;

	bytes_sent = 0;
	for (i=0;i<num;i++) {
		ret = do_send(socket, vec[i].iov_base, vec[i].iov_len, NULL, NULL);
		if (ret < 0)
			return ret;
		bytes_sent += ret;
		if (ret != vec[i].iov_len)
			break;
	}
	return bytes_sent;
}

int sock_sendmsg(struct socket *socket, struct msghdr *msg)
{
	const struct bio_vec *bio_vec = msg->msg_iter.bvec;

	return do_send(socket, bio_vec->bv_page->addr+bio_vec->bv_offset, bio_vec->bv_len, bio_vec->bv_page, NULL);
}

/* Do not use printk's in here, will loop forever... */

int SendTo(struct socket *socket, void *buf, size_t len, PSOCKADDR RemoteAddress)
{
	return do_send(socket, buf, len, NULL, RemoteAddress);
}


static int wsk_recvmsg(struct socket *socket, struct msghdr *msg, struct kvec *vec,
                   size_t num, size_t len, int flags)
{
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesReceived;
	NTSTATUS	Status;
	ULONG		wsk_flags;

	int remaining_time;
	int cancel_remaining_time;

	if (wsk_state != WSK_INITIALIZED || !socket || !socket->wsk_socket || !vec || vec[0].iov_base == NULL || ((int) vec[0].iov_len == 0))
		return -EINVAL;

	if (num != 1)
		return -EOPNOTSUPP;

	if (socket->error_status != 0)
		return socket->error_status;

	Status = InitWskBuffer(vec[0].iov_base, vec[0].iov_len, &WskBuffer, TRUE, TRUE);
	if (!NT_SUCCESS(Status)) {
		return winsock_to_linux_error(Status);
	}

	Irp = wsk_new_irp(NULL, socket, receive_completion);
	if (Irp == NULL) {
		FreeWskBuffer(&WskBuffer, 1);
		return -ENOMEM;
	}
// printk("Ok, Irp is %p\n", Irp);

	wsk_flags = 0;
	if (flags & MSG_WAITALL)
		wsk_flags |= WSK_FLAG_WAITALL;

	mutex_lock(&socket->wsk_mutex);

	if (socket->wsk_socket == NULL) {
		mutex_unlock(&socket->wsk_mutex);
		FreeWskBuffer(&WskBuffer, 1);
		return -ENOTCONN;
	}
	socket->data_received = false;
// printk("socket %p into WskReceive ...\n", socket);
	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) socket->wsk_socket->Dispatch)->WskReceive(
				socket->wsk_socket,
				&WskBuffer,
				wsk_flags,
				Irp);
// printk("socket %p out of WskReceive, Status is 0x%08x ...\n", socket, Status);
	mutex_unlock(&socket->wsk_mutex);

	if (Status == STATUS_PENDING)
	{
// printk("socket %p into wait_event_interruptible_timeout ...\n", socket);
		remaining_time = wait_event_interruptible_timeout(
			socket->receive_waitqueue,
			socket->data_received,
			socket->sk->sk_rcvtimeo);

// printk("socket %p out of wait_event_interruptible_timeout remaining_time is %d Irp->IoStatus.Information is %d ...\n", socket, remaining_time, Irp->IoStatus.Information);
		if (remaining_time == 0)
			remaining_time = -EAGAIN;

		if (remaining_time == -EINTR || remaining_time == -EAGAIN)
		{
// printk("socket %p CANCELLING IRP %p ...\n", socket, Irp);
			IoCancelIrp(Irp);
// printk("socket %p waiting for IRP completion\n", socket);
			cancel_remaining_time = wait_event_interruptible_timeout(
				socket->receive_waitqueue,
				socket->data_received,
				socket->sk->sk_rcvtimeo);

			if (cancel_remaining_time <= 0)
				printk("Warning: cancel_remaining_time is %d after IRP cancellation\n", cancel_remaining_time);

// printk("socket %p Ok IRP completed cancel_remaining_time is %d Irp->IoStatus.Information is %d\n", socket, cancel_remaining_time, Irp->IoStatus.Information);

			if (Irp->IoStatus.Information > 0) {
// printk("socket %p some data was received ...\n", socket);
				BytesReceived = Irp->IoStatus.Information;
			} else {
				BytesReceived = remaining_time;
			}

			goto out;
		}
		Status = Irp->IoStatus.Status;
	}
	if (Status == STATUS_SUCCESS)
		BytesReceived = (LONG) Irp->IoStatus.Information;
	else
		BytesReceived = winsock_to_linux_error(Status);

out:
// printk("About to free Irp %p ...\n", Irp);
	IoFreeIrp(Irp);
// printk("Irp %p freed.\n", Irp);
	FreeWskBuffer(&WskBuffer, 1);

	if (BytesReceived < 0 && BytesReceived != -EINTR && BytesReceived != -EAGAIN) {
		socket->error_status = BytesReceived;
	}
// printk("socket: %p returning %d ...\n", socket, BytesReceived);
	return BytesReceived;
}

/* TODO for receiver cache:

	.) Test: disconnect on secondary
	.) Test: network outage (on linux using iptables)

   Done:
	.) Make it optional (via registry key, default on)
	.) Make it work with DRBD (Wrong magic value)
	.) Compare performance
		It is about 2-4 times faster than before (!).
	.) Test speed with -rc9
		Yes rc9 is really slow
	.) Rejected: Return partial data received on connection close / error?
	.) dynamically allocate receive buffer. And make its size
	   configurable (via registry key).
	.) Rejected: BSOD when writing on Primary
		Couldn't reproduce, continue observing.

*/

/* Do nothing..just for debugging ... */
static void dump_packet(unsigned char *buf, size_t buflen)
{
	return;

#if 0
	size_t i;
	char s[80];
	int pos;

	pos=0;
	for (i=0;i<buflen;i++) {
		if (i%16 == 0)
			pos+=snprintf(s+pos, sizeof(s)-pos-1, "%08x: ", i);
		pos+=snprintf(s+pos, sizeof(s)-pos-1, "%02x ", buf[i]);
		if (i%16==15) {
			printk("%s\n", s);
			pos=0;
		}
	}
	if (i%16 != 0)
		printk("%s\n", s);
#endif
}

	/* This function returns data received by the receive_cache
	 * thread. We need that extra thread for performance reasons.
	 */

int kernel_recvmsg(struct socket *socket, struct msghdr *msg, struct kvec *vec,
                   size_t num, size_t len, int flags)
{
	size_t bytes_to_copy;
	size_t return_buffer_index;
	KIRQL irq_flags;
	int ret;
	LONG_PTR timeout, remaining_time;

	if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
		if (!socket->have_printed_status) {
			if (!socket->receiver_cache_enabled)
				printk("Receiver cache disabled\n");
			else
				printk("Receiver cache enabled, buffer size is %d\n", socket->receive_buffer_size);

			socket->have_printed_status = true;
		}
	} else {
		printk("KeGetCurrentIrql() in kernel_recvmsg() should not happen.\n");
	}

// printk("flags is %x len is %d\n", flags, len);
	if (!socket->receiver_cache_enabled) {
		ret = wsk_recvmsg(socket, msg, vec, num, len, flags);
		if (ret > 0)
			dump_packet(vec[0].iov_base, ret);
// printk("socket: %p returning %d ...\n", socket, ret);
		return ret;
	}

	if (wsk_state != WSK_INITIALIZED || !socket || !socket->wsk_socket || !vec || vec[0].iov_base == NULL || ((int) vec[0].iov_len == 0))
		return -EINVAL;

	if (num != 1)
		return -EOPNOTSUPP;

	if (socket->error_status != 0)
		return socket->error_status;

	return_buffer_index = 0;

	timeout = socket->sk->sk_rcvtimeo;
	while (1) {
// printk("socket is %p into wait_event_interruptible_timeout timeout is %d...\n", socket, timeout);
		if (timeout < 0) {
			printk("Warning: timeout < 0 before wait_event_interruptible_timeout...\n");
			return -EINVAL;
		}
		remaining_time = wait_event_interruptible_timeout(
			socket->data_available,
			socket->write_index != socket->read_index ||
			(socket->write_index == socket->read_index && socket->receive_buffer_full) ||
			socket->error_status != 0 ||
			socket->sk->sk_state != TCP_ESTABLISHED ||
			((flags & MSG_DONTWAIT) != 0),
			timeout);

// printk("socket is %p out of wait_event_interruptible_timeout, remaining time is %d ... flags & MSG_DONTWAIT is 0x%08x\n", socket, remaining_time, flags & MSG_DONTWAIT);
		ret = 1;
		if (remaining_time < 0)
			ret = remaining_time;
		if (remaining_time == 0)
			ret = -EAGAIN;
		timeout = remaining_time;

		if (socket->error_status != 0)
			ret = socket->error_status;
		if (socket->sk->sk_state != TCP_ESTABLISHED)
			ret = 0;

		if (((flags & MSG_DONTWAIT) != 0) && (ret == 1))
{
// printk("socket %p MSG_DONTWAIT set and no error / EOF setting ret to 0...\n", socket);
			ret = 0;
}
// printk("socket is %p ret is %d\n", socket, ret);

		spin_lock_irqsave(&socket->receive_lock, irq_flags);
		if (socket->read_index < socket->write_index)
			bytes_to_copy = socket->write_index - socket->read_index;
		else {
			if (socket->read_index == socket->write_index) {
				if (socket->receive_buffer_full)
					bytes_to_copy = socket->receive_buffer_size - socket->read_index;
				else
					bytes_to_copy = 0;
			} else { /* read_index > write_index */
				bytes_to_copy = socket->receive_buffer_size - socket->read_index;
			}
		}
		spin_unlock_irqrestore(&socket->receive_lock, irq_flags);

		if (bytes_to_copy > len-return_buffer_index) {
			bytes_to_copy = len-return_buffer_index;
		}

		if (bytes_to_copy <= 0) {
			if (ret != 1)
{
// printk("socket: %p nothing received and ret is %d, returning that ...\n", socket, ret);
				return ret;
}
			continue;
		}

		memcpy(&((char*)vec[0].iov_base)[return_buffer_index], 
			&socket->receive_buffer[socket->read_index],
			bytes_to_copy);

		spin_lock_irqsave(&socket->receive_lock, irq_flags);

		return_buffer_index += bytes_to_copy;
		socket->read_index += bytes_to_copy;

		if (socket->read_index == socket->receive_buffer_size)
			socket->read_index = 0;

		if (socket->write_index == socket->read_index)
			socket->receive_buffer_full = false;

		spin_unlock_irqrestore(&socket->receive_lock, irq_flags);

		wake_up(&socket->buffer_available);

// printk("about to maybe return data ...\n");
		if (flags & MSG_WAITALL) {
// printk("MSG_WAITALL ...\n");
			if (ret != 1 || return_buffer_index == len) {
				dump_packet(vec[0].iov_base, return_buffer_index);
// printk("socket: %p data %d ret is %d len is %d...\n", socket, return_buffer_index, ret, len);
				return return_buffer_index;
			}
		} else {
			dump_packet(vec[0].iov_base, return_buffer_index);
// printk("socket: %p some data received: return_buffer_index is %d\n", socket, return_buffer_index);
			return return_buffer_index;
		}
		if (ret != 1)
{
// printk("socket: %p ok ret is %d, returning it ...\n", socket, ret);
			return ret;
}

// printk("socket: %p ok, next iteration ...\n", socket);
	}
	return -EINVAL;
}

static int socket_receive_thread(void *p)
{
	struct socket *s = p;
        struct kvec iov = { 0 };
        struct msghdr msg = { .msg_flags = 0 };
	int err;
	KIRQL flags;

// TODO: maybe enable this again?
	while (1) {
		wait_event(s->buffer_available, 
			!s->receive_thread_should_run ||
			(s->sk->sk_state == TCP_ESTABLISHED &&
			(s->write_index != s->read_index ||
			(s->write_index == s->read_index && !s->receive_buffer_full)))); 

		if (!s->receive_thread_should_run)
{
// printk("s->receive_thread_should_run is %d\n", s->receive_thread_should_run);
			break;
}


		spin_lock_irqsave(&s->receive_lock, flags);
		if (s->read_index == s->write_index && !s->receive_buffer_full) {
			s->read_index = s->write_index = 0;
			iov.iov_len = s->receive_buffer_size;
		} else {
			if (s->read_index < s->write_index)
				iov.iov_len = s->receive_buffer_size-s->write_index;
			else
				iov.iov_len = s->read_index-s->write_index;
		}
		iov.iov_base = &s->receive_buffer[s->write_index];
		spin_unlock_irqrestore(&s->receive_lock, flags);

		if (iov.iov_len == 0) {
			printk("Warning: iov.iov_len is 0 in WinDRBD receiver thread .. should not happen.\n");
// printk("3a read_index is %d write_index is %d\n", s->read_index, s->write_index);
			continue;	/* wait_event should block */
		}
		err = wsk_recvmsg(s, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
// printk("socket: %p wsk_recvmsg returned %d ...\n", s, err);

		if (err == -EAGAIN || err == -EINTR)
			continue;

		if (err <= 0) {
			printk(KERN_DEBUG "wsk_recvmsg returned %d, terminating receiver thread.\n", err);
			break;
		}

		spin_lock_irqsave(&s->receive_lock, flags);

		s->write_index+=err;
		if (s->write_index == s->receive_buffer_size)
			s->write_index = 0;

		if (s->write_index == s->read_index)
			s->receive_buffer_full = true;

		spin_unlock_irqrestore(&s->receive_lock, flags);

		wake_up(&s->data_available);
		if (s->sk->sk_data_ready)
			s->sk->sk_data_ready(s->sk);
	}

	s->sk->sk_state = TCP_NO_CONNECTION;
	wake_up(&s->data_available);
	kref_put(&s->kref, sock_really_free);
//	complete(&s->receiver_thread_completion);

//	printk("terminating socket_receive_thread %p (socket is %p)\n", current, s);
	return 0;
}

/* Must not printk() from in here, might loop forever */
static int wsk_bind(
	struct socket *socket,
	struct sockaddr *myaddr,
	int sockaddr_len
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status;
	(void) sockaddr_len;	/* TODO: check this parameter */

	if (wsk_state != WSK_INITIALIZED || socket == NULL || socket->wsk_socket == NULL || myaddr == NULL)
		return -EINVAL;

	Irp = wsk_new_irp(&CompletionEvent, NULL, NULL);
	if (Irp == NULL)
		return -ENOMEM;

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) socket->wsk_socket->Dispatch)->WskBind(
		socket->wsk_socket,
		myaddr,
		0,
		Irp);

	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}
	IoFreeIrp(Irp);
	return winsock_to_linux_error(Status);
}

static NTSTATUS ControlSocket(
	__in PWSK_SOCKET	WskSocket,
	__in ULONG			RequestType,
	__in ULONG		    ControlCode,
	__in ULONG			Level,
	__in SIZE_T			InputSize,
	__in_opt PVOID		InputBuffer,
	__in SIZE_T			OutputSize,
	__out_opt PVOID		OutputBuffer,
	__out_opt SIZE_T	*OutputSizeReturned
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status;

	if (wsk_state != WSK_INITIALIZED || !WskSocket)
		return -EINVAL;

	Irp = wsk_new_irp(&CompletionEvent, NULL, NULL);
	if (Irp == NULL)
		return -ENOMEM;

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskControlSocket(
				WskSocket,
				RequestType,		// WskSetOption, 
				ControlCode,		// SIO_WSK_QUERY_RECEIVE_BACKLOG, 
				Level,				// IPPROTO_IPV6,
				InputSize,			// sizeof(optionValue),
				InputBuffer,		// NULL, 
				OutputSize,			// sizeof(int), 
				OutputBuffer,		// &backlog, 
				OutputSizeReturned, // NULL,
				Irp);


	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	return Status;
}

int kernel_setsockopt(struct socket *sock, int level, int optname, char *optval,
		      unsigned int optlen)
{
	NTSTATUS status;
	ULONG flag;

	if (sock == NULL)
		return -EINVAL;

	switch (level) {
	case SOL_TCP:
		switch (optname) {
		case TCP_NODELAY:
			if (optlen < 1)
				return -EINVAL;

			sock->no_delay = *optval;
			break;
		default:
			return -EOPNOTSUPP;
		}
		break;

	case SOL_SOCKET:
		switch (optname) {
		case SO_REUSEADDR:
			if (optlen < 1)
				return -EINVAL;

			flag = *optval;	
			status = ControlSocket(sock->wsk_socket, WskSetOption, SO_REUSEADDR, SOL_SOCKET, sizeof(flag), &flag, 0, NULL, NULL);

			return winsock_to_linux_error(status);

		default:
			return -EOPNOTSUPP;
		}

	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

struct proto_ops winsocket_ops = {
	.bind = wsk_bind,
	.listen = wsk_listen,
	.connect = wsk_connect,
	.sendpage = wsk_sendpage,
	.getname = wsk_getname
};

static void wsk_sock_state_change(struct sock *sk)
{
}

	/* Unimplemented at the moment. DRBD is patched to
	 * call windrbd_update_socket_buffer_sizes() to notify
	 * us. Reason is that there seems to be no callback
	 * when the receive buffer size is also changed.
	 */

static void wsk_sock_write_space(struct sock *sk)
{
}

static int sock_create_linux_socket(struct socket **out, unsigned short type)
{
	struct socket *socket;

	socket = kzalloc(sizeof(*socket), GFP_KERNEL);
	if (!socket)
		return -ENOMEM;

	socket->sk = kzalloc(sizeof(*socket->sk), GFP_KERNEL);
	if (!socket->sk) {
		kfree(socket);
		return -ENOMEM; 
	}

	/* Note that fields that are to be initialized to 0 or NULL
	 * are omitted here, we're doing kzalloc ...
	 */
	socket->error_status = 0;

	kref_init(&socket->kref);
	spin_lock_init(&socket->send_buf_counters_lock);
	spin_lock_init(&socket->accept_socket_lock);
	KeInitializeEvent(&socket->data_sent, SynchronizationEvent, FALSE);
	socket->num_sends_inflight = 0;
	KeInitializeEvent(&socket->accept_event, SynchronizationEvent, FALSE);
	mutex_init(&socket->wsk_mutex);
	socket->ops = &winsocket_ops;

	get_registry_int(L"enable_receiver_cache", &socket->receiver_cache_enabled, 1);
	init_waitqueue_head(&socket->buffer_available);
	init_waitqueue_head(&socket->data_available);
	init_waitqueue_head(&socket->connected_waitqueue);
	init_waitqueue_head(&socket->receive_waitqueue);

	socket->have_printed_status = false;

/* TODO: also for SOCK_DGRAM but not for printk socket. printk at the
 * moment the only one using SOCK_DGRAM but this may change...
 */
	if (type != SOCK_STREAM)
		socket->receiver_cache_enabled = false;

	if (socket->receiver_cache_enabled) {
		get_registry_int(L"receive_buffer_size", &socket->receive_buffer_size, RECEIVE_BUFFER_DEFAULT_SIZE);
		if (socket->receive_buffer_size < 4096)
			socket->receive_buffer_size = 4096;
		if (socket->receive_buffer_size > 4*1024*1024)
			socket->receive_buffer_size = 4*1024*1024;
		socket->receive_buffer = kmalloc(socket->receive_buffer_size, GFP_KERNEL);
		if (socket->receive_buffer == NULL) {
			printk("Warning: could not allocate memory for socket receive buffer (size is %d), receiver cache disabled\n", socket->receive_buffer_size);
			socket->receiver_cache_enabled = false;
		} else {
			socket->write_index = 0;
			socket->read_index = 0;
//			init_completion(&socket->receiver_thread_completion);
			spin_lock_init(&socket->receive_lock);
		}
	}

	socket->sk->sk_sndbuf = 4*1024*1024;
	socket->sk->sk_rcvbuf = 4*1024*1024;
	socket->sk->sk_wmem_queued = 0;
	socket->sk->sk_socket = socket;
	socket->sk->sk_sndtimeo = 10*HZ;
	socket->sk->sk_rcvtimeo = 10*HZ;
	socket->sk->sk_state_change = wsk_sock_state_change;
	socket->sk->sk_write_space = wsk_sock_write_space;
	rwlock_init(&socket->sk->sk_callback_lock);

	if (socket->receiver_cache_enabled) {
		socket->receive_thread_should_run = true;
				/* This matches the kref_put at the end of
				 * the receiver thread. We must have it here
				 * before the thread is started because the
				 * socket might be freed before the thread
				 * actually starts.
				 */
		kref_get(&socket->kref);

// printk("About to start receive_cache for socket %p...\n", socket);
		kthread_run(socket_receive_thread, socket, "receive_cache");
	}

	*out = socket;

	return 0;
}

static NTSTATUS WSKAPI wsk_incoming_connection (
    _In_  PVOID         SocketContext,
    _In_  ULONG         Flags,
    _In_  PSOCKADDR     LocalAddress,
    _In_  PSOCKADDR     RemoteAddress,
    _In_opt_  PWSK_SOCKET AcceptSocket,
    _Outptr_result_maybenull_ PVOID *AcceptSocketContext,
    _Outptr_result_maybenull_ CONST WSK_CLIENT_CONNECTION_DISPATCH **AcceptSocketDispatch
)
{
	struct socket *socket = (struct socket*) SocketContext;
	int err;

	if (socket->accept_wsk_sockets == NULL) {
		printk("Warning: incoming_connection() without listen() called.\n");
		return -EINVAL;
	}

	err = put_accept_socket(socket, AcceptSocket);

	if (err < 0) {
		close_wsk_socket(AcceptSocket);
		socket->dropped_accept_sockets++;

		return STATUS_INSUFFICIENT_RESOURCES;
	}
	KeSetEvent(&socket->accept_event, IO_NO_INCREMENT, FALSE);

	if (socket->sk->sk_state_change)
		socket->sk->sk_state_change(socket->sk);

	if (AcceptSocketContext)
		*AcceptSocketContext = NULL;
	if (AcceptSocketDispatch)
		*AcceptSocketDispatch = NULL;

	return STATUS_SUCCESS;
}

static struct _WSK_CLIENT_LISTEN_DISPATCH listen_dispatch = {
	wsk_incoming_connection,
	NULL,
	NULL
};

static int wsk_sock_create_kern(void *net_namespace,
	ADDRESS_FAMILY		family,
	USHORT			type,
	ULONG			protocol,
	ULONG			Flags,
	struct socket  		**out)
{
	struct _WSK_SOCKET *wsk_socket;
	struct socket *socket;
	int err;

	if (net_namespace != &init_net)
		return -EINVAL;

// printk("into sock_create_linux_socket ..\n");
	err = sock_create_linux_socket(&socket, type);
	if (err < 0)
		return err;

	if (Flags == WSK_FLAG_LISTEN_SOCKET)
		err = CreateSocket(family, type, protocol,
				socket, &listen_dispatch, Flags, &wsk_socket);
	else
		err = CreateSocket(family, type, protocol,
				NULL, NULL, Flags, &wsk_socket);

	if (err < 0) {
		sock_free_linux_socket(socket);
		return err;
	}

	socket->wsk_socket = wsk_socket;
	socket->wsk_flags = Flags;
	*out = socket;

	return 0;
}

int sock_create_kern(struct net *net, int family, int type, int proto, struct socket **res)
{
	ULONG Flags;

	switch (type) {
	case SOCK_DGRAM:
		Flags = WSK_FLAG_DATAGRAM_SOCKET;
		break;

	case SOCK_STREAM:
		Flags = WSK_FLAG_CONNECTION_SOCKET;
		break;

	case SOCK_LISTEN:	/* windrbd specific */
		Flags = WSK_FLAG_LISTEN_SOCKET;
		type = SOCK_STREAM;
		break;

	default:
		return -EINVAL;
	}
	return wsk_sock_create_kern(net, family, type, proto, Flags, res);
}

void sock_release(struct socket *sock)
{
	if (sock == NULL)
		return;

		/* In case it is not closed already ... */
	close_socket(sock);
	sock_free_linux_socket(sock);
}

void windrbd_update_socket_buffer_sizes(struct socket *socket)
{
	NTSTATUS status;

	if (socket == NULL)
		return;

	if (socket->sk->sk_userlocks & SOCK_SNDBUF_LOCK) {
                KeSetEvent(&socket->data_sent, IO_NO_INCREMENT, FALSE);
		socket->sk->sk_userlocks &= ~SOCK_SNDBUF_LOCK;
	}
	if (socket->sk->sk_userlocks & SOCK_RCVBUF_LOCK) {
                status = ControlSocket(socket->wsk_socket, WskSetOption, SO_RCVBUF, SOL_SOCKET, sizeof(socket->sk->sk_rcvbuf), &socket->sk->sk_rcvbuf, 0, NULL, NULL);
                if (status != STATUS_SUCCESS)
                        printk(KERN_WARNING "Could not set receive buffer size to %d, status is %x\n", socket->sk->sk_rcvbuf, status);
		socket->sk->sk_userlocks &= ~SOCK_RCVBUF_LOCK;
	}
}

/* TODO: Currently does nothing */

int sock_set_keepalive(struct sock *socket)
{
	return 0;
}

void tcp_sock_set_nodelay(struct sock *sk)
{
	char val = 1;
	(void) kernel_setsockopt(sk->sk_socket, SOL_TCP, TCP_NODELAY, &val, sizeof(val));
}

void tcp_sock_set_cork(struct sock *sk, bool on)
{
}

void tcp_sock_set_quickack(struct sock *sk, int val)
{
}

/* Ignored on Windows */
void sk_set_memalloc(struct sock *sk)
{
}

static void *init_wsk_thread;

/* This is a separate thread, since it blocks until Windows has finished
 * booting. It initializes everything we need and then exits. You can
 * ignore the return value.
 */

static void __attribute__((stdcall)) windrbd_init_wsk_thread(void *unused)
{
	NTSTATUS status;

        /* We have to do that here in a separate thread, else Windows
	 * will deadlock on booting.
         */
        status = SocketsInit();

        if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Failed to initialize socket layer, status is %x.\n", status);
			/* and what now? */
	} else {
		printk("WSK initialized.\n");
	}
}

NTSTATUS windrbd_init_wsk(void)
{
	NTSTATUS status;

	spin_lock_init(&completions_lock);
	KeInitializeEvent(&net_initialized_event, NotificationEvent, FALSE);

	status = windrbd_create_windows_thread(windrbd_init_wsk_thread, NULL, &init_wsk_thread);

	if (!NT_SUCCESS(status))
		printk("Couldn't create thread for initializing socket layer: windrbd_create_windows_thread failed with status 0x%x\n", status);

	return status;
}

	/* Under normal conditions, the thread already terminated long ago.
	 * Wait for its termination in case it is still running.
	 */

void windrbd_shutdown_wsk(void)
{
        NTSTATUS status;

        status = windrbd_cleanup_windows_thread(init_wsk_thread);

        if (!NT_SUCCESS(status))
                printk("windrbd_cleanup_windows_thread failed with status %x\n", status);

	/* Call this only if all sockets are closed/currently being closed.
	 * It waits until all sockets are closed, possibly forever.
	 */

	SocketsDeinit();
}


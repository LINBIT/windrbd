/* Uncomment this if you want more debug output (disable for releases) */
#define DEBUG 1

#ifdef RELEASE
#ifdef DEBUG
#undef DEBUG
#endif
#endif

#include "drbd_windows.h"
#include "windrbd_threads.h"
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/tcp.h>

/* Protects from API functions being called before the WSK provider is
 * initialized (see SocketsInit).
 */
/* TODO: resource deallocation via goto's */

/* TODO: store type of wsk socket (WSK_FLAG_XXX) in socket and check it..
 * the Dispatcher cast is dangerous.
 */

#define WSK_DEINITIALIZED	0
#define WSK_DEINITIALIZING	1
#define WSK_INITIALIZING	2
#define WSK_INITIALIZED		3

struct net init_net;

static LONG wsk_state = WSK_DEINITIALIZED;

static struct _KEVENT net_initialized_event;

static WSK_REGISTRATION		g_WskRegistration;
static WSK_PROVIDER_NPI		g_WskProvider;
static WSK_CLIENT_DISPATCH	g_WskDispatch = { MAKE_WSK_VERSION(1, 0), 0, NULL };

static int winsock_to_linux_error(NTSTATUS status)
{
/*	if (status != STATUS_SUCCESS)
		printk("got status %x\n", status);
*/

	switch (status) {
	case STATUS_SUCCESS:
		return 0;
	case STATUS_CONNECTION_RESET:
		return -ECONNRESET;
	case STATUS_CONNECTION_DISCONNECTED:
		return -ENOTCONN;
	case STATUS_CONNECTION_ABORTED:
		return -ECONNABORTED;
	case STATUS_IO_TIMEOUT:
	case STATUS_TIMEOUT:
		return -EAGAIN;
	case STATUS_INVALID_DEVICE_STATE:
		return -EINVAL;	/* -ENOTCONN? */
	case STATUS_NETWORK_UNREACHABLE:
		return -ENETUNREACH;
	case STATUS_HOST_UNREACHABLE:
		return -EHOSTUNREACH;
	case STATUS_CONNECTION_REFUSED:
		return -ECONNREFUSED;
	default:
		dbg("Unknown status %x, returning -EIO.\n", status);
		return -EIO;
	}
}

static NTSTATUS NTAPI completion_fire_event(
	__in PDEVICE_OBJECT	DeviceObject,
	__in PIRP			Irp,
	__in PKEVENT		CompletionEvent
)
{
	/* Must not printk in here, will loop forever. Hence also no
	 * ASSERT.
	 */

	KeSetEvent(CompletionEvent, IO_NO_INCREMENT, FALSE);
	
	return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS NTAPI completion_free_irp(
	__in PDEVICE_OBJECT	DeviceObject,
	__in PIRP			Irp,
	__in PKEVENT		CompletionEvent
)
{
	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;  /* meaning do not touch the irp */
}

	/* Creates a new IRP for use with wsk functions. If CompletionEvent
	 * is non-NULL, it is initialized and completion_fire_event (which
	 * signals the event) is used as completion routine, else
	 * completion_free_irp is used (which just frees the irp).
	 */

static struct _IRP *wsk_new_irp(struct _KEVENT *CompletionEvent)
{
	struct _IRP *irp;

	irp = IoAllocateIrp(1, FALSE);
	if (irp == NULL) {
		dbg("IoAllocateIrp returned NULL, out of IRPs?\n");
		return NULL;
	}

	if (CompletionEvent) {
		KeInitializeEvent(CompletionEvent, SynchronizationEvent, FALSE);
		IoSetCompletionRoutine(irp, completion_fire_event, CompletionEvent, TRUE, TRUE, TRUE);
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
    NTSTATUS Status = STATUS_SUCCESS;

    WskBuffer->Offset = 0;
    WskBuffer->Length = BufferSize;

    WskBuffer->Mdl = IoAllocateMdl(Buffer, BufferSize, FALSE, FALSE, NULL);
    if (!WskBuffer->Mdl) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    try {
	// DW-1223: Locking with 'IoWriteAccess' affects buffer, which causes infinite I/O from ntfs when the buffer is from mdl of write IRP.
	// we need write access for receiver, since buffer will be filled.
	MmProbeAndLockPages(WskBuffer->Mdl, KernelMode, bWriteAccess?IoWriteAccess:IoReadAccess);
    } except(EXCEPTION_EXECUTE_HANDLER) {
	if (WskBuffer->Mdl != NULL) {
	    IoFreeMdl(WskBuffer->Mdl);
	}
	if (may_printk)
		printk(KERN_ERR "MmProbeAndLockPages failed. exception code=0x%x\n", GetExceptionCode());
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    return Status;
}

static VOID FreeWskBuffer(
__in PWSK_BUF WskBuffer,
int may_printk
)
{
	if (WskBuffer->Mdl->MdlFlags & MDL_PAGES_LOCKED) {
		MmUnlockPages(WskBuffer->Mdl);
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
};

static void have_sent(struct socket *socket, size_t length)
{
	ULONG_PTR flags;

	spin_lock_irqsave(&socket->send_buf_counters_lock, flags);
	socket->sk->sk_wmem_queued -= length;
	spin_unlock_irqrestore(&socket->send_buf_counters_lock, flags);

	KeSetEvent(&socket->data_sent, IO_NO_INCREMENT, FALSE);
}

static NTSTATUS NTAPI SendPageCompletionRoutine(
	__in PDEVICE_OBJECT	DeviceObject,
	__in PIRP		Irp,
	__in struct send_page_completion_info *completion

)
{ 
	int may_printk = completion->page != NULL; /* called from SendPage */
	size_t length;

	if (Irp->IoStatus.Status != STATUS_SUCCESS) {
		int new_status = winsock_to_linux_error(Irp->IoStatus.Status);

		if (may_printk && completion->socket->error_status != 0 &&
		    completion->socket->error_status != new_status)
			dbg(KERN_WARNING "Last error status of socket was %d, now got %d (ntstatus %x)\n", completion->socket->error_status, new_status, Irp->IoStatus.Status);

		completion->socket->error_status = new_status;
	} else {
			/* Only for connectionless sockets: clear error
			 * status (they may "repair" themselves).
			 */
		if (completion->socket->wsk_flags == WSK_FLAG_DATAGRAM_SOCKET)
			completion->socket->error_status = 0;
	}

	length = completion->wsk_buffer->Length;
		/* Also unmaps the pages of the containg Mdl */

	FreeWskBuffer(completion->wsk_buffer, may_printk);
	kfree(completion->wsk_buffer);

	have_sent(completion->socket, length);

	if (completion->page)
		put_page(completion->page); /* Might free the page if connection is already down */
	if (completion->data_buffer)
		kfree(completion->data_buffer);
	kfree(completion);
	
	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

static int wait_for_sendbuf(struct socket *socket, size_t want_to_send)
{
	ULONG_PTR flags;
	LARGE_INTEGER timeout;
	NTSTATUS status;
	void *wait_objects[2];
	int num_objects;

	while (1) {
		spin_lock_irqsave(&socket->send_buf_counters_lock, flags);

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
//				return -EAGAIN; /* hangs Win7 VM? */
				return -ETIMEDOUT;
			default:
				dbg("KeWaitForMultipleObjects returned unexpected error %x\n", status);
				return winsock_to_linux_error(status);
			}
		} else {
			socket->sk->sk_wmem_queued += want_to_send;
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
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

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

void SocketsDeinit(void)
{
	if (InterlockedCompareExchange(&wsk_state, WSK_INITIALIZED, WSK_DEINITIALIZING) != WSK_INITIALIZED)
		return;
	WskReleaseProviderNPI(&g_WskRegistration);
	WskDeregister(&g_WskRegistration);

	InterlockedExchange(&wsk_state, WSK_DEINITIALIZED);
}

static int CreateSocket(
	__in ADDRESS_FAMILY		AddressFamily,
	__in USHORT			SocketType,
	__in ULONG			Protocol,
	__in PVOID			SocketContext,
	__in struct _WSK_CLIENT_LISTEN_DISPATCH *Dispatch,
	__in ULONG			Flags,
	struct _WSK_SOCKET		**out
)
{
	KEVENT			CompletionEvent = { 0 };
	PIRP			Irp = NULL;
	PWSK_SOCKET		WskSocket = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	/* NO _printk HERE, WOULD LOOP */
	if (wsk_state != WSK_INITIALIZED || out == NULL)
		return -EINVAL;

	Irp = wsk_new_irp(&CompletionEvent);
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

	/* Use this only to close a newly created wsk_socket which
	 * does not have a Linux socket yet (e.g. in accept when
	 * creating Linux socket fails).
	 */

static void close_wsk_socket(struct _WSK_SOCKET *wsk_socket)
{
	struct _IRP *Irp;

dbg("1\n");
	if (wsk_state != WSK_INITIALIZED || wsk_socket == NULL)
		return;

	Irp = wsk_new_irp(NULL);
	if (Irp == NULL)
		return;

	(void) ((PWSK_PROVIDER_BASIC_DISPATCH) wsk_socket->Dispatch)->WskCloseSocket(wsk_socket, Irp);
dbg("2\n");
}


	/* We do not wait for completion here, errors are ignored.
	 */

static void close_socket(struct socket *socket)
{
	struct _IRP *Irp;

dbg("1 socket is %p\n", socket);
	if (wsk_state != WSK_INITIALIZED || socket == NULL)
		return;

	if (socket->is_closed) {
		dbg("Socket already closed, refusing to close it again.\n");
		return;
	}

	Irp = wsk_new_irp(NULL);
	if (Irp == NULL)
		return;

		/* TODO: Gracefully disconnect socket first? With what
		 * timeout? Disconnect seems to work now (Linux detects
		 * disconnect on Windows peer with about 200-300ms delay),
		 * so not sure if that is neccessary. Current solution
		 * however does an 'abortive' disconnect (whatever that
		 * means).
		 */

	if (socket->wsk_socket != NULL) {
		mutex_lock(&socket->wsk_mutex);

		(void) ((PWSK_PROVIDER_BASIC_DISPATCH) socket->wsk_socket->Dispatch)->WskCloseSocket(socket->wsk_socket, Irp);
		socket->wsk_socket = NULL;

		mutex_unlock(&socket->wsk_mutex);
	}

	if (socket->accept_wsk_socket != NULL) {
		close_wsk_socket(socket->accept_wsk_socket);
		socket->accept_wsk_socket = NULL;
	}
	socket->error_status = 0;
	socket->is_closed = 1;	/* TODO: can it be reopened? Then we need to reset this flag. */
dbg("2 socket is %p\n", socket);
}

static int wsk_getname(struct socket *socket, struct sockaddr *uaddr, int peer)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	status = STATUS_UNSUCCESSFUL;

	if (peer == 0)
		return -EOPNOTSUPP;

	if (wsk_state != WSK_INITIALIZED || socket == NULL || socket->wsk_socket == NULL)
		return -EINVAL;

	Irp = wsk_new_irp(&CompletionEvent);
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

	if (status == STATUS_SUCCESS)
		return sizeof(*uaddr);

	return winsock_to_linux_error(status);
}

static int wsk_connect(struct socket *socket, struct sockaddr *vaddr, int sockaddr_len, int flags)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

dbg("1 socket is %p\n", socket);
		/* TODO: check/implement those: */
	(void) sockaddr_len;
	(void) flags;

	if (wsk_state != WSK_INITIALIZED || socket == NULL || socket->wsk_socket == NULL || vaddr == NULL)
		return -EINVAL;

	Irp = wsk_new_irp(&CompletionEvent);
	if (Irp == NULL)
		return -ENOMEM;

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) socket->wsk_socket->Dispatch)->WskConnect(
		socket->wsk_socket,
		vaddr,
		0,
		Irp);

	if (Status == STATUS_PENDING) {
		LARGE_INTEGER	nWaitTime;
		nWaitTime = RtlConvertLongToLargeInteger(-1 * socket->sk->sk_sndtimeo * 1000 * 10);

		if ((Status = KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, &nWaitTime)) == STATUS_TIMEOUT)
		{
			dbg("Timeout (%lld/%d) expired, cancelling connect.\n", nWaitTime, socket->sk->sk_sndtimeo);
			IoCancelIrp(Irp);
			KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		}
	}

	if (Status == STATUS_SUCCESS)
	{
		Status = Irp->IoStatus.Status;
		if (Status == STATUS_SUCCESS)
			socket->sk->sk_state = TCP_ESTABLISHED;
	}
	if (Status != STATUS_SUCCESS)
		dbg("WskConnect failed with status = %x\n", Status);

	IoFreeIrp(Irp);

dbg("2 socket is %p, returning %d\n", socket, winsock_to_linux_error(Status));
	return winsock_to_linux_error(Status);
}

static int sock_create_linux_socket(struct socket **out);

int kernel_accept(struct socket *socket, struct socket **newsock, int io_flags)
{
	int err;
	struct _WSK_SOCKET *wsk_socket;
	struct socket *accept_socket;
	KIRQL flags;

dbg("1 socket is %p\n", socket);
	if (wsk_state != WSK_INITIALIZED || socket == NULL || socket->wsk_socket == NULL)
		return -EINVAL;

retry:
	spin_lock_irqsave(&socket->accept_socket_lock, flags);
	if (socket->accept_wsk_socket == NULL) {
		spin_unlock_irqrestore(&socket->accept_socket_lock, flags);
		if ((io_flags & O_NONBLOCK) != 0)
			return -EWOULDBLOCK;

			/* TODO: handle signals */
		KeWaitForSingleObject(&socket->accept_event, Executive, KernelMode, FALSE, NULL);
		goto retry;
	}
	wsk_socket = socket->accept_wsk_socket;
	socket->accept_wsk_socket = NULL;
	spin_unlock_irqrestore(&socket->accept_socket_lock, flags);

	err = sock_create_linux_socket(&accept_socket);
	if (err < 0)
		close_wsk_socket(wsk_socket);
	else {
		accept_socket->wsk_socket = wsk_socket;
		accept_socket->sk->sk_state = TCP_ESTABLISHED;
		accept_socket->sk->sk_state_change = socket->sk->sk_state_change;
		accept_socket->sk->sk_user_data = socket->sk->sk_user_data;
		*newsock = accept_socket;
	}

dbg("2 socket is %p\n", socket);
	return err;
}

	/* TODO: Or use the ControlSocket function */

static int wsk_set_event_callbacks(struct socket *socket, int mask)
{
	KEVENT CompletionEvent;
	PIRP Irp;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	WSK_EVENT_CALLBACK_CONTROL callbackControl;

	if (wsk_state != WSK_INITIALIZED || socket == NULL || socket->wsk_socket == NULL)
		return -EINVAL;

	Irp = wsk_new_irp(&CompletionEvent);
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

static int wsk_listen(struct socket *socket, int len)
{
	NTSTATUS status;

	(void) len;

	if (wsk_state != WSK_INITIALIZED || socket == NULL || socket->wsk_socket == NULL)
		return -EINVAL;

	return wsk_set_event_callbacks(socket, WSK_EVENT_ACCEPT);
}

int kernel_sock_shutdown(struct socket *sock, enum sock_shutdown_cmd how)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER	nWaitTime;

		/* TODO: one day ... */
	(void) how;

	if (wsk_state != WSK_INITIALIZED || sock == NULL || sock->wsk_socket == NULL)
		return -EINVAL;

	sock->sk->sk_state = 0;
	close_socket(sock);

	return 0;
}


	/* TODO: maybe one day we also eliminate this function. It
	 * is currently only used for sending the first packet.
	 * Even more now when we do not have send buf implemented here..
	 *
	 * Update: According to Lars all Linux kernel send functions
	 * are 'non-blocking' in the sense that they just fill the
	 * TCP/IP (or UDP) send buffer and return. They only block
	 * if the send buffer is full.
	 *
	 * merge this function with SendTo(), making it non-blocking
	 */

	/* TODO: implement MSG_MORE? */


int kernel_sendmsg(struct socket *socket, struct msghdr *msg, struct kvec *vec,
                   size_t num, size_t len)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesSent;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	ULONG Flags = 0;

// dbg("socket is %p\n", socket);

	if (wsk_state != WSK_INITIALIZED || !socket || !socket->wsk_socket || !vec || vec[0].iov_base == NULL || ((int) vec[0].iov_len == 0))
		return -EINVAL;

	if (num != 1)
		return -EOPNOTSUPP;

	Status = InitWskBuffer(vec[0].iov_base, vec[0].iov_len, &WskBuffer, FALSE, TRUE);
	if (!NT_SUCCESS(Status)) {
		return winsock_to_linux_error(Status);
	}

	Irp = wsk_new_irp(&CompletionEvent);
	if (Irp == NULL) {
		FreeWskBuffer(&WskBuffer, 1);
		return -ENOMEM;
	}

	if (socket->no_delay)
		Flags |= WSK_FLAG_NODELAY;
	else
		Flags &= ~WSK_FLAG_NODELAY;

	mutex_lock(&socket->wsk_mutex);

	if (socket->wsk_socket == NULL) {
		mutex_unlock(&socket->wsk_mutex);
		FreeWskBuffer(&WskBuffer, 1);
		return winsock_to_linux_error(Status);
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) socket->wsk_socket->Dispatch)->WskSend(
		socket->wsk_socket,
		&WskBuffer,
		Flags,
		Irp);

	mutex_unlock(&socket->wsk_mutex);

	if (Status == STATUS_PENDING)
	{
		LARGE_INTEGER	nWaitTime;
		LARGE_INTEGER	*pTime;

		if (socket->sk->sk_sndtimeo <= 0 || socket->sk->sk_sndtimeo == MAX_SCHEDULE_TIMEOUT)
		{
			pTime = NULL;
		}
		else
		{
			nWaitTime.QuadPart = -1 * socket->sk->sk_sndtimeo * 10 * 1000 * 1000 / HZ;
			pTime = &nWaitTime;
		}
		{
			struct      task_struct *thread = current;
			PVOID       waitObjects[2];
			int         wObjCount = 1;

			waitObjects[0] = (PVOID) &CompletionEvent;

			Status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);
			switch (Status)
			{
			case STATUS_TIMEOUT:
				IoCancelIrp(Irp);
				KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
				BytesSent = -EAGAIN;
				break;

			case STATUS_WAIT_0:
				if (NT_SUCCESS(Irp->IoStatus.Status))
				{
					BytesSent = (LONG)Irp->IoStatus.Information;
				}
				else
				{
					printk("tx error(%x) wsk(0x%p)\n",Irp->IoStatus.Status, socket->wsk_socket);
					switch (Irp->IoStatus.Status)
					{
						case STATUS_IO_TIMEOUT:
							BytesSent = -EAGAIN;
							break;
						case STATUS_INVALID_DEVICE_STATE:
							BytesSent = -EAGAIN;
							break;
						default:
							BytesSent = -ECONNRESET;
							break;
					}
				}
				break;

			//case STATUS_WAIT_1: // common: sender or send_bufferinf thread's kill signal
			//	IoCancelIrp(Irp);
			//	KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
			//	BytesSent = -EINTR;
			//	break;

			default:
				printk(KERN_ERR "Wait failed. status 0x%x\n", Status);
				BytesSent = winsock_to_linux_error(Status);
			}
		}
	}
	else
	{
		if (Status == STATUS_SUCCESS)
		{
			BytesSent = (LONG) Irp->IoStatus.Information;
			printk("WskSend No pending: but sent(%d)!\n", BytesSent);
		}
		else
		{
			printk("WskSend error(0x%x)\n", Status);
			BytesSent = winsock_to_linux_error(Status);
		}
	}


	IoFreeIrp(Irp);
	FreeWskBuffer(&WskBuffer, 1);

// dbg("returning %d\n", BytesSent);
	return BytesSent;
}

ssize_t wsk_sendpage(struct socket *socket, struct page *page, int offset, size_t len, int flags)
{
	struct _IRP *Irp;
	struct _WSK_BUF *WskBuffer;
	struct send_page_completion_info *completion;
	NTSTATUS status;
	int err;

// dbg("socket is %p\n", socket);
	if (wsk_state != WSK_INITIALIZED || !socket || !socket->wsk_socket || !page || ((int) len <= 0))
		return -EINVAL;

	if (socket->error_status != 0)
		return socket->error_status;

	get_page(page);		/* we might sleep soon, do this before */

	err = wait_for_sendbuf(socket, len);
	if (err < 0)
		goto out_put_page;

	WskBuffer = kzalloc(sizeof(*WskBuffer), 0, 'DRBD');
	if (WskBuffer == NULL) {
		err = -ENOMEM;
		goto out_have_sent;
	}

	completion = kzalloc(sizeof(*completion), 0, 'DRBD');
	if (completion == NULL) {
		err = -ENOMEM;
		goto out_free_wsk_buffer;
	}

// printk("page: %p page->addr: %p page->size: %d offset: %d len: %d page->kref.refcount: %d\n", page, page->addr, page->size, offset, len, page->kref.refcount);

	status = InitWskBuffer((void*) (((unsigned char *) page->addr)+offset), len, WskBuffer, FALSE, TRUE);
	if (!NT_SUCCESS(status)) {
		err = -ENOMEM;
		goto out_free_completion;
	}

	completion->page = page;
	completion->wsk_buffer = WskBuffer;
	completion->socket = socket;

	Irp = IoAllocateIrp(1, FALSE);
	if (Irp == NULL) {
		err = -ENOMEM;
		goto out_free_wsk_buffer_mdl;
	}
	IoSetCompletionRoutine(Irp, SendPageCompletionRoutine, completion, TRUE, TRUE, TRUE);

	if (socket->no_delay)
		flags |= WSK_FLAG_NODELAY;
	else
		flags &= ~WSK_FLAG_NODELAY;


	mutex_lock(&socket->wsk_mutex);

	if (socket->wsk_socket == NULL) {
		err = -ENOTCONN;
		goto out_unlock_mutex;
	}
	status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) socket->wsk_socket->Dispatch)->WskSend(
		socket->wsk_socket,
		WskBuffer,
		flags,
		Irp);

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

		return len;

	case STATUS_SUCCESS:
		return (LONG) Irp->IoStatus.Information;
	}
	err = winsock_to_linux_error(status);
	if (err != 0 && err != -ENOMEM)
		socket->error_status = err;

		/* Resources are freed by completion routine. */
// dbg("returning %d\n", err);
	return err;

out_unlock_mutex:
	mutex_unlock(&socket->wsk_mutex);
out_free_wsk_buffer_mdl:
	FreeWskBuffer(WskBuffer, 1);
out_free_completion:
	kfree(completion);
out_free_wsk_buffer:
	kfree(WskBuffer);
out_have_sent:
	have_sent(socket, len);
out_put_page:
	put_page(page);

	if (err != 0 && err != -ENOMEM)
		socket->error_status = err;
// dbg("returning %d\n", err);
	return err;
}

/* Do not use printk's in here, will loop forever... */

int SendTo(struct socket *socket, void *Buffer, size_t BufferSize, PSOCKADDR RemoteAddress)
{
	struct _IRP *irp;
	struct _WSK_BUF *WskBuffer;
	struct send_page_completion_info *completion;

		/* We copy what we send to a tmp buffer, so
		 * caller may free or use otherwise what we
		 * have got in Buffer.
		 */

	char *tmp_buffer;
	NTSTATUS status;
	int err;

	if (wsk_state != WSK_INITIALIZED || !socket || !socket->wsk_socket || !Buffer || !BufferSize)
		return -EINVAL;

	if (socket->error_status != 0)
		return socket->error_status;

	err = wait_for_sendbuf(socket, BufferSize);
	if (err < 0)
		return err;

	WskBuffer = kzalloc(sizeof(*WskBuffer), 0, 'DRBD');
	if (WskBuffer == NULL) {
		have_sent(socket, BufferSize);
		return -ENOMEM;
	}

	completion = kzalloc(sizeof(*completion), 0, 'DRBD');
	if (completion == NULL) {
		have_sent(socket, BufferSize);
		kfree(WskBuffer);
		return -ENOMEM;
	}

	tmp_buffer = kmalloc(BufferSize, 0, 'TMPB');
	if (tmp_buffer == NULL) {
		have_sent(socket, BufferSize);
		kfree(completion);
		kfree(WskBuffer);
		return -ENOMEM;
	}
	memcpy(tmp_buffer, Buffer, BufferSize);

	status = InitWskBuffer(tmp_buffer, BufferSize, WskBuffer, FALSE, FALSE);
	if (!NT_SUCCESS(status)) {
		have_sent(socket, BufferSize);
		kfree(completion);
		kfree(WskBuffer);
		kfree(tmp_buffer);
		return -ENOMEM;
	}

	completion->data_buffer = tmp_buffer;
	completion->wsk_buffer = WskBuffer;
	completion->socket = socket;

	irp = IoAllocateIrp(1, FALSE);
	if (irp == NULL) {
		have_sent(socket, BufferSize);
		kfree(completion);
		kfree(WskBuffer);
		kfree(tmp_buffer);
		FreeWskBuffer(WskBuffer, 0);
		return -ENOMEM;
	}
	IoSetCompletionRoutine(irp, SendPageCompletionRoutine, completion, TRUE, TRUE, TRUE);

	status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH) socket->wsk_socket->Dispatch)->WskSendTo(
		socket->wsk_socket,
		WskBuffer,
		0,
		RemoteAddress,
		0,
		NULL,
		irp);

		/* Again if not yet sent, pretend that it has been sent,
		 * followup calls to SendTo() on that socket will report
		 * errors. This is how Linux behaves.
		 */

	if (status == STATUS_PENDING)
		status = STATUS_SUCCESS;

	return status == STATUS_SUCCESS ? BufferSize : winsock_to_linux_error(status);
}

int kernel_recvmsg(struct socket *socket, struct msghdr *msg, struct kvec *vec,
                   size_t num, size_t len, int flags)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesReceived;
	NTSTATUS	Status;
	ULONG		wsk_flags;

	struct      task_struct *thread = current;
	PVOID       waitObjects[2];
	int         wObjCount = 1;

// dbg("socket is %p\n", socket);
	if (wsk_state != WSK_INITIALIZED || !socket || !socket->wsk_socket || !vec || vec[0].iov_base == NULL || ((int) vec[0].iov_len == 0))
		return -EINVAL;

	if (num != 1) {
dbg("num is %d\n", num);
		return -EOPNOTSUPP;
}

	if (socket->error_status != 0) {
dbg("socket->error_status is %d\n", socket->error_status);
		return socket->error_status;
}


	Status = InitWskBuffer(vec[0].iov_base, vec[0].iov_len, &WskBuffer, TRUE, TRUE);
	if (!NT_SUCCESS(Status)) {
dbg("InitWskBuffer failed, Status is %x\n", Status);
		return winsock_to_linux_error(Status);
	}

	Irp = wsk_new_irp(&CompletionEvent);
	if (Irp == NULL) {
dbg("new_irp failed\n");
		FreeWskBuffer(&WskBuffer, 1);
		return -ENOMEM;
	}

	wsk_flags = 0;
	if (flags | MSG_WAITALL)
		wsk_flags |= WSK_FLAG_WAITALL;

	mutex_lock(&socket->wsk_mutex);

	if (socket->wsk_socket == NULL) {
dbg("wsk_socket closed meanwhile\n");
		mutex_unlock(&socket->wsk_mutex);
		FreeWskBuffer(&WskBuffer, 1);
		return -ENOTCONN;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) socket->wsk_socket->Dispatch)->WskReceive(
				socket->wsk_socket,
				&WskBuffer,
				wsk_flags,
				Irp);
	mutex_unlock(&socket->wsk_mutex);

    if (Status == STATUS_PENDING)
    {
        LARGE_INTEGER	nWaitTime;
        LARGE_INTEGER	*pTime;

        if (socket->sk->sk_rcvtimeo <= 0 || socket->sk->sk_rcvtimeo == MAX_SCHEDULE_TIMEOUT)
        {
            pTime = 0;
        }
        else
        {
            nWaitTime.QuadPart = -1LL * socket->sk->sk_rcvtimeo * 1000 * 10 * 1000 / HZ;
            pTime = &nWaitTime;
        }

        waitObjects[0] = (PVOID) &CompletionEvent;
        if (thread->has_sig_event)
        {
            waitObjects[1] = (PVOID) &thread->sig_event;
            wObjCount = 2;
        } 

        Status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);
        switch (Status)
        {
        case STATUS_WAIT_0: // waitObjects[0] CompletionEvent
            if (Irp->IoStatus.Status == STATUS_SUCCESS)
            {
                BytesReceived = (LONG) Irp->IoStatus.Information;
if (BytesReceived == 0)
dbg("BytesReceived is 0, socket closed by peer?\n");
            }
            else
            {
dbg("receive completed with error %x\n", Irp->IoStatus.Status);
		BytesReceived = winsock_to_linux_error(Irp->IoStatus.Status);
            }
            break;

        case STATUS_WAIT_1:
dbg("receive interrupted by signal\n");
            flush_signals(current);
            BytesReceived = -EINTR;
            break;

        case STATUS_TIMEOUT:
dbg("receive timed out\n");
            BytesReceived = -EAGAIN;
            break;

        default:
dbg("wait_event returned error %x\n", Status);
            BytesReceived = winsock_to_linux_error(Status);
            break;
        }
    }
	else
	{
		if (Status == STATUS_SUCCESS)
		{
			BytesReceived = (LONG) Irp->IoStatus.Information;
dbg("WskReceive returned immediately, data (%d bytes) is available\n", BytesReceived);
		}
		else
		{
dbg("WskReceive error status=%x\n", Status);
			BytesReceived = winsock_to_linux_error(Status);
		}
	}

	if (BytesReceived == -EINTR || BytesReceived == -EAGAIN)
	{
		// cancel irp in wsk subsystem
		IoCancelIrp(Irp);
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		if (Irp->IoStatus.Information > 0)
		{
				/* When network is interrupted while we
				 * are serving a Primary Diskless server
				 * we want DRBD to know that the network
				 * is down. Do not deliver the data to
				 * DRBD, it should cancel the receiver
				 * instead (else it would get stuck in
				 * NetworkFailure). This is probably a
				 * DRBD bug, since Linux (userland) recv
				 * would deliver EINTR only if no data
				 * is available.
				 */

		/* Deliver what we have in case we timed out. */

			if (BytesReceived == -EAGAIN) {
dbg("Timed out, but there is data (%d bytes) returning it.\n", Irp->IoStatus.Information);
				BytesReceived = Irp->IoStatus.Information;
			} else {
dbg("Receiving cancelled (errno is %d) but data available (%d bytes, returning it).\n", BytesReceived, Irp->IoStatus.Information);
				BytesReceived = Irp->IoStatus.Information;
			}
		}
	}

	IoFreeIrp(Irp);
	FreeWskBuffer(&WskBuffer, 1);

	if (BytesReceived < 0 && BytesReceived != -EINTR && BytesReceived != -EAGAIN) {
		socket->error_status = BytesReceived;
dbg("setting error status to %d\n", socket->error_status);
}

// dbg("returning %d\n", BytesReceived);
	return BytesReceived;
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
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	(void) sockaddr_len;	/* TODO: check this parameter */

	if (wsk_state != WSK_INITIALIZED || socket == NULL || socket->wsk_socket == NULL || myaddr == NULL)
		return -EINVAL;

	Irp = wsk_new_irp(&CompletionEvent);
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
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (wsk_state != WSK_INITIALIZED || !WskSocket)
		return -EINVAL;

	Irp = wsk_new_irp(&CompletionEvent);
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

static void wsk_sock_statechange(struct sock *sk)
{
}

static int sock_create_linux_socket(struct socket **out)
{
	struct socket *socket;

	socket = kzalloc(sizeof(*socket), 0, '3WDW');
	if (!socket)
		return -ENOMEM;

	socket->sk = kzalloc(sizeof(*socket->sk), 0, 'KARI');
	if (!socket->sk) {
		kfree(socket);
		return -ENOMEM; 
	}

	socket->error_status = 0;

	spin_lock_init(&socket->send_buf_counters_lock);
	spin_lock_init(&socket->accept_socket_lock);
	KeInitializeEvent(&socket->data_sent, SynchronizationEvent, FALSE);
	KeInitializeEvent(&socket->accept_event, SynchronizationEvent, FALSE);
	mutex_init(&socket->wsk_mutex);
	socket->ops = &winsocket_ops;

	socket->sk->sk_sndbuf = 4*1024*1024;
	socket->sk->sk_rcvbuf = 4*1024*1024;
	socket->sk->sk_wmem_queued = 0;
	socket->sk->sk_socket = socket;
	socket->sk->sk_sndtimeo = 10*HZ;
	socket->sk->sk_rcvtimeo = 10*HZ;
	socket->sk->sk_state_change = wsk_sock_statechange;
	rwlock_init(&socket->sk->sk_callback_lock);

	*out = socket;

	return 0;
}

	/* Use this only if socket is valid but socket->wsk_socket is
	 * not.
	 */

static void sock_free_linux_socket(struct socket *socket)
{
	if (socket == NULL)
		return;

	kfree(socket->sk);
	kfree(socket);
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
	KIRQL flags;
	struct _WSK_SOCKET *socket_to_close = NULL;

	spin_lock_irqsave(&socket->accept_socket_lock, flags);
	if (socket->accept_wsk_socket != NULL) {
		dbg("dropped incoming connection wsk_socket is old: %p new: %p socket is %p.\n", socket->accept_wsk_socket, AcceptSocket, socket);

		socket_to_close = socket->accept_wsk_socket;
		socket->dropped_accept_sockets++;
	}
	socket->accept_wsk_socket = AcceptSocket;
	spin_unlock_irqrestore(&socket->accept_socket_lock, flags);

	if (socket_to_close != NULL)
		close_wsk_socket(socket_to_close);

	KeSetEvent(&socket->accept_event, IO_NO_INCREMENT, FALSE);

	if (socket->sk->sk_state_change)
		socket->sk->sk_state_change(socket->sk);

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
	NTSTATUS status;

if (type == SOCK_STREAM) dbg("1\n");
	if (net_namespace != &init_net)
		return -EINVAL;

	err = sock_create_linux_socket(&socket);
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

if (type == SOCK_STREAM) dbg("2 socket is %p\n", socket);

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

static NTSTATUS receive_a_lot(void *unused)
{
	struct socket *s, *s2;
	int err;
	struct sockaddr_in my_addr;
	static char bigbuffer[1024*128];
	size_t bytes_received;

        struct kvec iov = {
                .iov_base = bigbuffer,
                .iov_len = sizeof(bigbuffer),
        };
        struct msghdr msg = {
                .msg_flags = MSG_WAITALL
        };

	err = sock_create_kern(&init_net, AF_INET, SOCK_LISTEN, IPPROTO_TCP, &s);

	if (err < 0) {
		printk("sock_create_kern returned %d\n", err);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	my_addr.sin_family = AF_INET;
	my_addr.sin_addr.s_addr = 0;
	my_addr.sin_port = htons(5678);

        err = s->ops->bind(s, (struct sockaddr *)&my_addr, sizeof(my_addr));
	if (err < 0) {
		printk("bind returned %d\n", err);
		sock_release(s);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

        err = s->ops->listen(s, 10);
	if (err < 0) {
		printk("listen returned %d\n", err);
		sock_release(s);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	err = kernel_accept(s, &s2, 0);
	if (err < 0) {
		printk("accept returned %d\n", err);
		sock_release(s);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	printk("connection accepted\n");

	bytes_received = 0;
	while (1) {
		err = kernel_recvmsg(s2, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
		if (err < 0) {
			printk("receive returned %d\n", err);
			break;
		}
		if (err != iov.iov_len) {
			printk("short receive (%d, expected %d)\n", err, iov.iov_len);
			break;
		}
		bytes_received += err;
		if ((bytes_received % (1024*1024)) == 0)
			printk("%lld bytes received\n", bytes_received);
	}
	sock_release(s);
	sock_release(s2);

	return STATUS_SUCCESS;
}

static void *init_wsk_thread;

static void *r_thread;

/* This is a separate thread, since it blocks until Windows has finished
 * booting. It initializes everything we need and then exits. You can
 * ignore the return value.
 */

static NTSTATUS windrbd_init_wsk_thread(void *unused)
{
	NTSTATUS status;
	int err;

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

#if 0
	status = windrbd_create_windows_thread(receive_a_lot, NULL, &r_thread);
#endif

	return status;
}

NTSTATUS windrbd_init_wsk(void)
{
	HANDLE h;
	NTSTATUS status;

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


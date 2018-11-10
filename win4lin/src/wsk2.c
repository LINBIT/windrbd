#include "drbd_windows.h"
#include "windrbd_threads.h"
#include "wsk2.h"

/* TODO: change the API in here to that of Linux kernel (so
 * we don't need to patch the tcp transport file.
 */

WSK_REGISTRATION			g_WskRegistration;
static WSK_PROVIDER_NPI		g_WskProvider;
static WSK_CLIENT_DISPATCH	g_WskDispatch = { MAKE_WSK_VERSION(1, 0), 0, NULL };
LONG						g_SocketsState = DEINITIALIZED;

static NTSTATUS NTAPI CompletionRoutine(
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

static NTSTATUS InitWskData(
	__out PIRP*		pIrp,
	__out PKEVENT	CompletionEvent,
	__in  BOOLEAN	bRawIrp
)
{
	// DW-1316 use raw irp.
	/* TODO: is this still needed? CloseSocket uses it, but why? */
	if (bRawIrp) {
		*pIrp = ExAllocatePoolWithTag(NonPagedPool, IoSizeOfIrp(1), 'FFDW');
		IoInitializeIrp(*pIrp, IoSizeOfIrp(1), 1);
	}
	else {
		*pIrp = IoAllocateIrp(1, FALSE);
	}

	if (!*pIrp) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(CompletionEvent, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(*pIrp, CompletionRoutine, CompletionEvent, TRUE, TRUE, TRUE);

	return STATUS_SUCCESS;
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

// if (may_printk)
// printk("IoAllocateMdl(%p, %d, ...) -> %p\n", Buffer, BufferSize, WskBuffer->Mdl);

    try {
	// DW-1223: Locking with 'IoWriteAccess' affects buffer, which causes infinite I/O from ntfs when the buffer is from mdl of write IRP.
	// we need write access for receiver, since buffer will be filled.
	MmProbeAndLockPages(WskBuffer->Mdl, KernelMode, bWriteAccess?IoWriteAccess:IoReadAccess);
    } except(EXCEPTION_EXECUTE_HANDLER) {
	if (WskBuffer->Mdl != NULL) {
	    IoFreeMdl(WskBuffer->Mdl);
	}
	if (may_printk)
		WDRBD_ERROR("MmProbeAndLockPages failed. exception code=0x%x\n", GetExceptionCode());
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
	socket->send_buf_cur -= length;
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
		if (may_printk && completion->socket->error_status != STATUS_SUCCESS &&
		    completion->socket->error_status != Irp->IoStatus.Status)
			printk(KERN_WARNING "Last error status of socket was %x, now got %x\n", completion->socket->error_status, Irp->IoStatus.Status);

		completion->socket->error_status = Irp->IoStatus.Status;
	}
	length = completion->wsk_buffer->Length;
		/* Also unmaps the pages of the containg Mdl */

// if (may_printk)
// printk("MmUnlockPages(%p)\n", completion->wsk_buffer->Mdl);

	FreeWskBuffer(completion->wsk_buffer, may_printk);
	kfree(completion->wsk_buffer);

// if (may_printk)
// printk("in completion status is %x\n", Irp->IoStatus.Status);

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

	while (1) {
		spin_lock_irqsave(&socket->send_buf_counters_lock, flags);

		if (socket->send_buf_cur > socket->send_buf_max) {
			spin_unlock_irqrestore(&socket->send_buf_counters_lock, flags);
			timeout.QuadPart = -1 * socket->sk_sndtimeo * 10 * 1000 * 1000 / HZ;
			status = KeWaitForSingleObject(&socket->data_sent, Executive, KernelMode, FALSE, &timeout);

			if (status == STATUS_TIMEOUT)
				return -ETIMEDOUT;
		} else {
			socket->send_buf_cur += want_to_send;
			spin_unlock_irqrestore(&socket->send_buf_counters_lock, flags);
			return 0;
		}
			/* TODO: if socket closed meanwhile return an error */
			/* TODO: need socket refcount for doing so */
	}
}

//
// Library initialization routine
//

NTSTATUS NTAPI SocketsInit()
{
	WSK_CLIENT_NPI	WskClient = { 0 };
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	if (InterlockedCompareExchange(&g_SocketsState, INITIALIZING, DEINITIALIZED) != DEINITIALIZED)
		return STATUS_ALREADY_REGISTERED;

	WskClient.ClientContext = NULL;
	WskClient.Dispatch = &g_WskDispatch;

	Status = WskRegister(&WskClient, &g_WskRegistration);
	if (!NT_SUCCESS(Status)) {
		InterlockedExchange(&g_SocketsState, DEINITIALIZED);
		return Status;
	}

	WDRBD_INFO("WskCaptureProviderNPI start.\n");
	Status = WskCaptureProviderNPI(&g_WskRegistration, WSK_INFINITE_WAIT, &g_WskProvider);
	WDRBD_INFO("WskCaptureProviderNPI done.\n"); // takes long time! msg out after MVL loaded.

	if (!NT_SUCCESS(Status)) {
		WDRBD_ERROR("WskCaptureProviderNPI() failed with status 0x%08X\n", Status);
		WskDeregister(&g_WskRegistration);
		InterlockedExchange(&g_SocketsState, DEINITIALIZED);
		return Status;
	}

	InterlockedExchange(&g_SocketsState, INITIALIZED);
	return STATUS_SUCCESS;
}

//
// Library deinitialization routine
//

VOID NTAPI SocketsDeinit()
{
	if (InterlockedCompareExchange(&g_SocketsState, INITIALIZED, DEINITIALIZING) != INITIALIZED)
		return;
	WskReleaseProviderNPI(&g_WskRegistration);
	WskDeregister(&g_WskRegistration);

	InterlockedExchange(&g_SocketsState, DEINITIALIZED);
}

PWSK_SOCKET
NTAPI
CreateSocket(
	__in ADDRESS_FAMILY		AddressFamily,
	__in USHORT			SocketType,
	__in ULONG			Protocol,
	__in PVOID			SocketContext,
	__in PWSK_CLIENT_LISTEN_DISPATCH Dispatch,
	__in ULONG			Flags
)
{
	KEVENT			CompletionEvent = { 0 };
	PIRP			Irp = NULL;
	PWSK_SOCKET		WskSocket = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	/* NO _printk HERE, WOULD LOOP */
	if (g_SocketsState != INITIALIZED)
	{
		return NULL;
	}

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}

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

	WskSocket = NT_SUCCESS(Status) ? (PWSK_SOCKET) Irp->IoStatus.Information : NULL;
	IoFreeIrp(Irp);

	return (PWSK_SOCKET) WskSocket;
}

NTSTATUS
NTAPI
CloseSocket(
	__in PWSK_SOCKET WskSocket
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER	nWaitTime;
	nWaitTime.QuadPart = (-1 * 1000 * 10000);   // wait 1000ms relative 

	if (g_SocketsState != INITIALIZED || !WskSocket)
		return STATUS_INVALID_PARAMETER;

	Status = InitWskData(&Irp, &CompletionEvent, TRUE);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}
	Status = ((PWSK_PROVIDER_BASIC_DISPATCH) WskSocket->Dispatch)->WskCloseSocket(WskSocket, Irp);
	if (Status == STATUS_PENDING) {
		Status = KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, &nWaitTime);
		if (Status == STATUS_TIMEOUT) { // DW-1316 detour WskCloseSocket hang in Win7/x86.
			WDRBD_WARN("Timeout... Cancel WskCloseSocket:%p. maybe required to patch WSK Kernel\n", WskSocket);
			IoCancelIrp(Irp);
			// DW-1388: canceling must be completed before freeing the irp.
			KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		}
		Status = Irp->IoStatus.Status;
	}
	IoFreeIrp(Irp);

	return Status;
}

NTSTATUS
NTAPI
Connect(
	__in PWSK_SOCKET	WskSocket,
	__in PSOCKADDR		RemoteAddress
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !RemoteAddress)
		return STATUS_INVALID_PARAMETER;

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskConnect(
		WskSocket,
		RemoteAddress,
		0,
		Irp);

	if (Status == STATUS_PENDING) {
		LARGE_INTEGER	nWaitTime;
	/* TODO: hard coding timeout to 1 second is most likely wrong. */
		nWaitTime = RtlConvertLongToLargeInteger(-1 * 1000 * 1000 * 10);
		if ((Status = KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, &nWaitTime)) == STATUS_TIMEOUT)
		{
			IoCancelIrp(Irp);
			KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		}
	}

	if (Status == STATUS_SUCCESS)
	{
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	return Status;
}

NTSTATUS NTAPI
Disconnect(
	__in PWSK_SOCKET	WskSocket
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER	nWaitTime;
	nWaitTime.QuadPart = (-1 * 1000 * 10000);   // wait 1000ms relative 
	
	if (g_SocketsState != INITIALIZED || !WskSocket)
		return STATUS_INVALID_PARAMETER;

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}
	
	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskDisconnect(
		WskSocket,
		NULL,
		0,//WSK_FLAG_ABORTIVE,=> when disconnecting, ABORTIVE was going to standalone, and then we removed ABORTIVE
		Irp);

	if (Status == STATUS_PENDING) {
		Status = KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, &nWaitTime);
		if(STATUS_TIMEOUT == Status) { // DW-712 timeout process for fast closesocket in congestion mode, instead of WSK_FLAG_ABORTIVE
			WDRBD_INFO("Timeout... Cancel Disconnect socket:%p\n",WskSocket);
			IoCancelIrp(Irp);
			KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		} 

		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	return Status;
}

char *GetSockErrorString(NTSTATUS status)
{
	char *ErrorString;
	switch (status)
	{
		case STATUS_CONNECTION_RESET:
			ErrorString = "CONNECTION_RESET";
			break;
		case STATUS_CONNECTION_DISCONNECTED:
			ErrorString = "CONNECTION_DISCONNECTED";
			break;
		case STATUS_CONNECTION_ABORTED:
			ErrorString = "CONNECTION_ABORTED";
			break;
		case STATUS_IO_TIMEOUT:
			ErrorString = "IO_TIMEOUT";
			break;
		case STATUS_INVALID_DEVICE_STATE:
			ErrorString = "INVALID_DEVICE_STATE";
			break;
		default:
			ErrorString = "SOCKET_IO_ERROR";
			break;
	}
	return ErrorString;
}

	/* TODO: maybe one day we also eliminate this function. It
	 * is currently only used for sending the first packet.
	 * Even more now when we do not have send buf implemented here..
	 */

LONG
NTAPI
Send(
	struct socket *socket,
	__in PWSK_SOCKET	WskSocket,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesSent = SOCKET_ERROR; // DRBC_CHECK_WSK: SOCKET_ERROR be mixed EINVAL?
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || ((int) BufferSize <= 0))
		return SOCKET_ERROR;

	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer, FALSE, TRUE);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		FreeWskBuffer(&WskBuffer, 1);
		return SOCKET_ERROR;
	}

	Flags |= WSK_FLAG_NODELAY;

	mutex_lock(&socket->wsk_mutex);

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskSend(
		WskSocket,
		&WskBuffer,
		Flags,
		Irp);

	mutex_unlock(&socket->wsk_mutex);

	if (Status == STATUS_PENDING)
	{
		LARGE_INTEGER	nWaitTime;
		LARGE_INTEGER	*pTime;

		if (Timeout <= 0 || Timeout == MAX_SCHEDULE_TIMEOUT)
		{
			pTime = NULL;
		}
		else
		{
			nWaitTime = RtlConvertLongToLargeInteger(-1 * Timeout * 1000 * 10);
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
					WDRBD_WARN("tx error(%s) wsk(0x%p)\n", GetSockErrorString(Irp->IoStatus.Status), WskSocket);
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
				WDRBD_ERROR("Wait failed. status 0x%x\n", Status);
				BytesSent = SOCKET_ERROR;
			}
		}
	}
	else
	{
		if (Status == STATUS_SUCCESS)
		{
			BytesSent = (LONG) Irp->IoStatus.Information;
			WDRBD_WARN("(%s) WskSend No pending: but sent(%d)!\n", current->comm, BytesSent);
		}
		else
		{
			WDRBD_WARN("(%s) WskSend error(0x%x)\n", current->comm, Status);
			BytesSent = SOCKET_ERROR;
		}
	}


	IoFreeIrp(Irp);
// printk("MmUnlockPages(%p)\n", WskBuffer.Mdl);
	FreeWskBuffer(&WskBuffer, 1);

	return BytesSent;
}

int winsock_to_linux_error(NTSTATUS status)
{
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
		return -EAGAIN;
	case STATUS_INVALID_DEVICE_STATE:
		return -EINVAL;
	default:
		// printk("Unknown status %x, returning -EIO.\n", status);
		return -EIO;
	}
}

LONG
NTAPI
SendPage(
	__in struct socket *socket,
	__in struct page	*page,
	__in ULONG		offset,
	__in ULONG		len,
	__in ULONG		flags	
)
{
	struct _IRP *Irp;
	struct _WSK_BUF *WskBuffer;
	struct send_page_completion_info *completion;
	NTSTATUS status;
	int err;

	if (g_SocketsState != INITIALIZED || !socket || !socket->sk || !page || ((int) len <= 0))
		return -EINVAL;

	if (socket->error_status != STATUS_SUCCESS)
		return winsock_to_linux_error(socket->error_status);

	err = wait_for_sendbuf(socket, len);
	if (err < 0)
		return err;

	WskBuffer = kzalloc(sizeof(*WskBuffer), 0, 'DRBD');
	if (WskBuffer == NULL) {
		have_sent(socket, len);
		return -ENOMEM;
	}

	completion = kzalloc(sizeof(*completion), 0, 'DRBD');
	if (completion == NULL) {
		have_sent(socket, len);
		kfree(WskBuffer);
		return -ENOMEM;
	}

// printk("page: %p page->addr: %p page->size: %d offset: %d len: %d page->kref.refcount: %d\n", page, page->addr, page->size, offset, len, page->kref.refcount);

	status = InitWskBuffer((void*) (((unsigned char *) page->addr)+offset), len, WskBuffer, FALSE, TRUE);
	if (!NT_SUCCESS(status)) {
		have_sent(socket, len);
		kfree(completion);
		kfree(WskBuffer);
		return -ENOMEM;
	}

	get_page(page);
	completion->page = page;
	completion->wsk_buffer = WskBuffer;
	completion->socket = socket;

	Irp = IoAllocateIrp(1, FALSE);
	if (Irp == NULL) {
		have_sent(socket, len);
		put_page(page);
		kfree(completion);
		kfree(WskBuffer);
// printk("MmUnlockPages(%p)\n", WskBuffer->Mdl);
		FreeWskBuffer(WskBuffer, 1);
		return -ENOMEM;
	}
	IoSetCompletionRoutine(Irp, SendPageCompletionRoutine, completion, TRUE, TRUE, TRUE);

	if (socket->no_delay)
		flags |= WSK_FLAG_NODELAY;
	else
		flags &= ~WSK_FLAG_NODELAY;

// printk("1\n");

	mutex_lock(&socket->wsk_mutex);
	status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) socket->sk->Dispatch)->WskSend(
		socket->sk,
		WskBuffer,
		flags,
		Irp);
	mutex_unlock(&socket->wsk_mutex);

// printk("2 status is %x\n", status);

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

	default:
		return winsock_to_linux_error(status);
	}
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

	if (g_SocketsState != INITIALIZED || !socket || !socket->sk || !Buffer || !BufferSize)
		return -EINVAL;

	if (socket->error_status != STATUS_SUCCESS)
		return winsock_to_linux_error(socket->error_status);

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

	status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH) socket->sk->Dispatch)->WskSendTo(
		socket->sk,
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

LONG NTAPI Receive(
	struct socket *socket,
	__in  PWSK_SOCKET	WskSocket,
	__out PVOID			Buffer,
	__in  ULONG			BufferSize,
	__in  ULONG			Flags,
	__in ULONG			Timeout
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesReceived = SOCKET_ERROR;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

    struct      task_struct *thread = current;
    PVOID       waitObjects[2];
    int         wObjCount = 1;

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
		return SOCKET_ERROR;

	if ((int) BufferSize <= 0)
	{
		return SOCKET_ERROR;
	}

	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer, TRUE, TRUE);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);

	if (!NT_SUCCESS(Status)) {
// printk("MmUnlockPages(%p)\n", WskBuffer.Mdl);
		FreeWskBuffer(&WskBuffer, 1);
		return SOCKET_ERROR;
	}

	mutex_lock(&socket->wsk_mutex);
	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskReceive(
				WskSocket,
				&WskBuffer,
				Flags,
				Irp);
	mutex_unlock(&socket->wsk_mutex);

    if (Status == STATUS_PENDING)
    {
        LARGE_INTEGER	nWaitTime;
        LARGE_INTEGER	*pTime;

        if (Timeout <= 0 || Timeout == MAX_SCHEDULE_TIMEOUT)
        {
            pTime = 0;
        }
        else
        {
            nWaitTime = RtlConvertLongToLargeInteger(-1 * Timeout * 1000 * 10);
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
            }
            else
            {
				WDRBD_INFO("RECV(%s) wsk(0x%p) multiWait err(0x%x:%s)\n", thread->comm, WskSocket, Irp->IoStatus.Status, GetSockErrorString(Irp->IoStatus.Status));
				if(Irp->IoStatus.Status)
                {
                    BytesReceived = -ECONNRESET;
                }
            }
            break;

        case STATUS_WAIT_1:
            BytesReceived = -EINTR;
            break;

        case STATUS_TIMEOUT:
            BytesReceived = -EAGAIN;
            break;

        default:
            BytesReceived = SOCKET_ERROR;
            break;
        }
    }
	else
	{
		if (Status == STATUS_SUCCESS)
		{
			BytesReceived = (LONG) Irp->IoStatus.Information;
			WDRBD_INFO("(%s) Rx No pending and data(%d) is avail\n", current->comm, BytesReceived);
		}
		else
		{
			WDRBD_TRACE("WskReceive Error Status=0x%x\n", Status); // EVENT_LOG!
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
				printk("Timed out, but there is data (%d bytes) returning it.\n", Irp->IoStatus.Information);
				BytesReceived = Irp->IoStatus.Information;
			} else {
				printk("Receiving canceled (errno is %d) but data available (%d bytes, will be discarded).\n", BytesReceived, Irp->IoStatus.Information);
			}
		}
	}

	IoFreeIrp(Irp);
// printk("MmUnlockPages(%p)\n", WskBuffer.Mdl);
	FreeWskBuffer(&WskBuffer, 1);

	return BytesReceived;
}

/* Must not printk() from in here, might loop forever */
NTSTATUS
NTAPI
Bind(
	__in PWSK_SOCKET	WskSocket,
	__in PSOCKADDR		LocalAddress
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !LocalAddress)
		return STATUS_INVALID_PARAMETER;

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskBind(
		WskSocket,
		LocalAddress,
		0,
		Irp);

	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}
	IoFreeIrp(Irp);
	return Status;
}

NTSTATUS
NTAPI
ControlSocket(
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

	if (g_SocketsState != INITIALIZED || !WskSocket)
		return SOCKET_ERROR;

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		WDRBD_ERROR("InitWskData() failed with status 0x%08X\n", Status);
		return SOCKET_ERROR;
	}

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

NTSTATUS
NTAPI
GetRemoteAddress(
	__in PWSK_SOCKET	WskSocket,
	__out PSOCKADDR	pRemoteAddress
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskGetRemoteAddress(WskSocket, pRemoteAddress, Irp);
	if (Status != STATUS_SUCCESS)
	{
		if (Status == STATUS_PENDING) {
			KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
			Status = Irp->IoStatus.Status;
		}

		if (Status != STATUS_SUCCESS)
		{
			if (Status != STATUS_INVALID_DEVICE_STATE)
			{
				WDRBD_TRACE("STATUS_INVALID_DEVICE_STATE....\n");
			}
			else if (Status != STATUS_FILE_FORCED_CLOSED)
			{
				WDRBD_TRACE("STATUS_FILE_FORCED_CLOSED....\n");
			}
			else
			{
				WDRBD_TRACE("0x%x....\n", Status);
			}
		}
	}
	IoFreeIrp(Irp);
	return Status;
}


NTSTATUS
NTAPI
SetEventCallbacks(
__in PWSK_SOCKET Socket,
__in LONG                      mask
)
{
    KEVENT                     CompletionEvent = { 0 };
    PIRP                       Irp = NULL;
    PWSK_SOCKET                WskSocket = NULL;
    NTSTATUS           Status = STATUS_UNSUCCESSFUL;

    if (g_SocketsState != INITIALIZED)
    {
        return Status;
    }

    Status = InitWskData(&Irp, &CompletionEvent,FALSE);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    WSK_EVENT_CALLBACK_CONTROL callbackControl;
    callbackControl.NpiId = &NPI_WSK_INTERFACE_ID;

    // Set the event flags for the event callback functions that
    // are to be enabled on the socket
    callbackControl.EventMask = mask;

    // Initiate the control operation on the socket
    Status =
        ((PWSK_PROVIDER_BASIC_DISPATCH)Socket->Dispatch)->WskControlSocket(
        Socket,
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
    return Status;
}

int sock_create_kern(
	PVOID                   net_namespace,
	ADDRESS_FAMILY		AddressFamily,
	USHORT			SocketType,
	ULONG			Protocol,
	PVOID			SocketContext,
	PWSK_CLIENT_LISTEN_DISPATCH Dispatch,
	ULONG			Flags,
	struct socket  		**out)
{
	int err;
	struct socket *socket;

	(void)net_namespace;
	err = 0;
	socket = kzalloc(sizeof(struct socket), 0, '3WDW');
	if (!socket) {
		err = -ENOMEM; 
		goto out;
	}

	socket->sk = CreateSocket(AddressFamily, SocketType, Protocol,
			SocketContext, Dispatch, Flags);

	if (socket->sk == NULL) {
		err = -ENOMEM;
		kfree(socket);
		goto out;
	}
	socket->error_status = STATUS_SUCCESS;
	socket->send_buf_max = 4*1024*1024;
	socket->send_buf_cur = 0;
	spin_lock_init(&socket->send_buf_counters_lock);
	KeInitializeEvent(&socket->data_sent, SynchronizationEvent, FALSE);
	mutex_init(&socket->wsk_mutex);

	*out = socket;

out:
	return err;
}

static void *init_wsk_thread;

/* This is a separate thread, since it blocks until Windows has finished
 * booting. It initializes everything we need and then exits. You can
 * ignore the return value.
 */

static NTSTATUS windrbd_init_wsk_thread(void *unused)
{
	NTSTATUS status;

        /* We have to do that here, else Windows will deadlock
         * on booting.
         */
        status = SocketsInit();

	/* No printk's here, we're still booting. Windows will BSOD if we
	 * do a printk over network here.
	 */
        if (!NT_SUCCESS(status))
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Failed to initialize socket layer, status is %x.\n", status);
	else
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "WSK initialized, terminating thread.\n");

	return status;
}

NTSTATUS windrbd_init_wsk(void)
{
	HANDLE h;
	NTSTATUS status;

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

		/* socketsdeinit() ? */

        if (!NT_SUCCESS(status))
                printk("windrbd_cleanup_windows_thread failed with status %x\n", status);
}


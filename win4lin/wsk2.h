#pragma once
#include <ntddk.h>
#include <wsk.h>
#include "drbd_windows.h"

/* TODO: one day we should convert the APIs here to be kernel
 * compatible and revert the drbd_transport_wtcp.c to be based on
 * the original drbd_transport_tcp.c (with some small patches)
 */

#define SOCKET_ERROR -1

enum
{
	DEINITIALIZED,
	DEINITIALIZING,
	INITIALIZING,
	INITIALIZED
};

NTSTATUS NTAPI SocketsInit();
VOID NTAPI SocketsDeinit();

NTSTATUS
InitWskBuffer(
	__in  PVOID		Buffer,
	__in  ULONG		BufferSize,
	__out PWSK_BUF	WskBuffer,
	__in  BOOLEAN	bWriteAccess
	);

NTSTATUS
InitWskData(
	__out PIRP*		pIrp,
	__out PKEVENT	CompletionEvent,
	__in  BOOLEAN	bRawIrp
	);

NTSTATUS 
InitWskDataAsync(
	__out PIRP*		pIrp,
	__in  BOOLEAN	bRawIrp
	);

VOID
ReInitWskData(
	__out PIRP*		pIrp,
	__out PKEVENT	CompletionEvent
	);

VOID
FreeWskBuffer(
	__in PWSK_BUF WskBuffer
	);

VOID
FreeWskData(
	__in PIRP pIrp
	);

PWSK_SOCKET
NTAPI
  CreateSocket(
    __in ADDRESS_FAMILY	AddressFamily,
    __in USHORT			SocketType,
    __in ULONG			Protocol,
    __in PVOID			SocketContext,
    __in PWSK_CLIENT_LISTEN_DISPATCH Dispatch,
    __in ULONG			Flags
    );

NTSTATUS
NTAPI
  CloseSocket(
	__in PWSK_SOCKET WskSocket
	);

NTSTATUS
NTAPI
  Connect(
	__in PWSK_SOCKET	WskSocket,
	__in PSOCKADDR		RemoteAddress
	);

extern
NTSTATUS NTAPI
Disconnect(
	__in PWSK_SOCKET	WskSocket
	);

LONG
NTAPI
  Send(
	__in PWSK_SOCKET	WskSocket,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout
	);

LONG
NTAPI
SendPage(
        __in struct socket	*socket,
        __in struct page        *page,
        __in ULONG              offset,
        __in ULONG              len,
        __in ULONG              Flags
);

int SendTo(struct socket *socket, void *Buffer, size_t BufferSize, PSOCKADDR RemoteAddress);

LONG
NTAPI
Receive(
	__in  PWSK_SOCKET	WskSocket,
	__out PVOID			Buffer,
	__in  ULONG			BufferSize,
	__in  ULONG			Flags,
	__in ULONG			Timeout
	);

NTSTATUS
NTAPI
Bind(
	__in PWSK_SOCKET	WskSocket,
	__in PSOCKADDR		LocalAddress
	);

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
);

NTSTATUS
NTAPI
GetRemoteAddress(
__in PWSK_SOCKET	WskSocket,
__out PSOCKADDR	pRemoteAddress
);

#define HTONS(n)		(((((unsigned short)(n) & 0xFFu  )) << 8) | \
				(((unsigned short) (n) & 0xFF00u) >> 8))

#define TC_PRIO_INTERACTIVE_BULK	1
#define TC_PRIO_INTERACTIVE		1

extern void sock_release(void  *sock);

#define HTON_SHORT(n) (((((unsigned short)(n) & 0xFFu  )) << 8) | \
    (((unsigned short)(n)& 0xFF00u) >> 8))

char *GetSockErrorString(NTSTATUS status);

int sock_create_kern(
	PVOID                   net_namespace,
	ADDRESS_FAMILY		AddressFamily,
	USHORT			SocketType,
	ULONG			Protocol,
	PVOID			SocketContext,
	PWSK_CLIENT_LISTEN_DISPATCH Dispatch,
	ULONG			Flags,
	struct socket		**out);

NTSTATUS
NTAPI
SetEventCallbacks(
       __in PWSK_SOCKET Socket,
       __in LONG                       mask
);

char *get_ip(char *buf, struct sockaddr_storage_win *addr);

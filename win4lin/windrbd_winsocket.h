#ifndef _WSK2_H
#define _WSK2_H

#include <ntddk.h>
#include <wsk.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/socket.h>

/* struct sockaddr_storage: we now use the definition from ws2def.h */

/* TODO: one day we should convert the APIs here to be kernel
 * compatible and revert the drbd_transport_wtcp.c to be based on
 * the original drbd_transport_tcp.c (with some small patches)
 */

int SendTo(struct socket *socket, void *Buffer, size_t BufferSize, PSOCKADDR RemoteAddress);

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

#define TC_PRIO_INTERACTIVE_BULK	1
#define TC_PRIO_INTERACTIVE		1

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

#endif

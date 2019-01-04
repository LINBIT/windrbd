#ifndef _WSK2_H
#define _WSK2_H

#include <ntddk.h>
#include <wsk.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#define _K_SS_MAXSIZE	128 
struct sockaddr_storage_win {
	unsigned short	ss_family;		/* address family */
	char	__data[_K_SS_MAXSIZE - sizeof(unsigned short)];
}; 

struct socket {
	struct _WSK_SOCKET *wsk_socket;

	int sk_sndtimeo;
	int sk_rcvtimeo;

	int no_delay:1;

	NTSTATUS error_status;

	size_t send_buf_max;
	size_t send_buf_cur;
	spinlock_t send_buf_counters_lock;
	KEVENT data_sent;

	struct mutex wsk_mutex;

	char name[32];
};

char * get_ip4(char *buf, struct sockaddr_in *sockaddr);
char * get_ip6(char *buf, struct sockaddr_in6 *sockaddr);

/* TODO: one day we should convert the APIs here to be kernel
 * compatible and revert the drbd_transport_wtcp.c to be based on
 * the original drbd_transport_tcp.c (with some small patches)
 */

#define SOCKET_ERROR -1

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

	/* TODO: static */
NTSTATUS CloseSocket(struct _WSK_SOCKET *WskSocket);

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

struct page;

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

#define TC_PRIO_INTERACTIVE_BULK	1
#define TC_PRIO_INTERACTIVE		1

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

#endif

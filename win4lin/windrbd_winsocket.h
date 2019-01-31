#ifndef _WSK2_H
#define _WSK2_H

#include <ntddk.h>
#include <wsk.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/net.h>

/* struct sockaddr_storage: we now use the definition from ws2def.h */

/* TODO: this file should go away. Well, almost ... */

int SendTo(struct socket *socket, void *Buffer, size_t BufferSize, PSOCKADDR RemoteAddress);

#define TC_PRIO_INTERACTIVE_BULK	1
#define TC_PRIO_INTERACTIVE		1

void platform_update_socket_buffer_sizes(struct socket *socket);

#endif

#ifndef _LINUX_NET_H
#define _LINUX_NET_H

#include <linux/socket.h>

struct socket;

int kernel_sendmsg(struct socket *sock, struct msghdr *msg, struct kvec *vec,
		   size_t num, size_t len);
int kernel_recvmsg(struct socket *sock, struct msghdr *msg, struct kvec *vec,
		   size_t num, size_t len, int flags);

#endif

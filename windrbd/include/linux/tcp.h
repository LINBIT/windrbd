#ifndef _UAPI_LINUX_TCP_H
#define _UAPI_LINUX_TCP_H

#include <linux/tcp_states.h>

#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */

void tcp_sock_set_nodelay(struct sock *sk);
void tcp_sock_set_cork(struct sock *sk, bool on);
void tcp_sock_set_quickack(struct sock *sk, int val);

#endif

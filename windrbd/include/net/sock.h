#ifndef __NET_SOCK_H
#define __NET_SOCK_H

#include <net/net_namespace.h>
#include <linux/net/sock.h>

void sk_set_memalloc(struct sock *sk);

static inline
struct net *sock_net(const struct sock *unused)
{
	return &init_net;
}

#endif

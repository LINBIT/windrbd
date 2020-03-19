#ifndef _NETLINK_H
#define _NETLINK_H

#define NETLINK_CB(skb)		(*(struct netlink_skb_parms*)&((skb)->cb))

#endif


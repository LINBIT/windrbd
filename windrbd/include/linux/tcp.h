#ifndef _UAPI_LINUX_TCP_H
#define _UAPI_LINUX_TCP_H

#include <linux/tcp_states.h>
#include <uapi/linux/pkt_sched.h>

/* Defined in ReactOS: */
// #define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */

/* TODO: those are referenced by drbd_transport_tcp but currently not
 * written.
 */

struct tcp_sock {
	u32 rcv_nxt; /* the ack # by SYNACK. For
		      * FastOpen it's the seq#
		      * after data-in-SYN.
		      */
	u32 copied_seq;	/* Head of yet unread data */
	u32 write_seq;	/* Tail(+1) of data held in tcp send buffer */
	u32 snd_una;	/* First byte we want an ack for */
};

void tcp_sock_set_nodelay(struct sock *sk);
void tcp_sock_set_cork(struct sock *sk, bool on);
void tcp_sock_set_quickack(struct sock *sk, int val);

/* See net/sock.h */
#define tcp_sk(sk) &((sk)->t)

#endif

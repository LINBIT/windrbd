#ifndef _LINUX_NET_SOCK_H
#define _LINUX_NET_SOCK_H

struct sock;

#include <linux/tcp.h>
#include <linux/spinlock.h>

#define SOCK_SNDBUF_LOCK	1
#define SOCK_RCVBUF_LOCK	2

struct socket;

struct sock {
        int sk_sndtimeo;
        int sk_rcvtimeo;

        int sk_state;

	size_t sk_sndbuf;
	int sk_wmem_queued;
	size_t sk_rcvbuf;

	int sk_userlocks;

	void *sk_user_data;
	void (*sk_state_change)(struct sock *sk);
	void (*sk_data_ready)(struct sock *sk);
	void (*sk_write_space)(struct sock *sk);

	spinlock_t sk_callback_lock;
	struct socket *sk_socket;

	/* TODO: those are used by drbd_transport_tcp but not implemented
	 * in WinDRBD.
	 */

	unsigned char sk_reuse:4;
	gfp_t sk_allocation;
	__u32 sk_priority;

	struct tcp_sock t;
	/* TODO: what is this? */
	bool sk_use_task_frag;
};

#endif


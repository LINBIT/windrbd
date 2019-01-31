#ifndef _LINUX_NET_SOCK_H
#define _LINUX_NET_SOCK_H

#define SOCK_SNDBUF_LOCK	1
#define SOCK_RCVBUF_LOCK	2

struct socket;

struct sock {
        int sk_sndtimeo;
        int sk_rcvtimeo;
		/* TODO: does not exist on Linux */
        int sk_connecttimeo;

        int sk_state;

	size_t sk_sndbuf;
	int sk_wmem_queued;
	size_t sk_rcvbuf;

	int sk_userlocks;

	void *sk_user_data;
	void (*sk_state_change)(struct sock *sk);
	rwlock_t sk_callback_lock;

	struct socket *sk_socket;
};

#endif


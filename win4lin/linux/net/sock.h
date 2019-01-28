#ifndef _LINUX_NET_SOCK_H
#define _LINUX_NET_SOCK_H

struct sock {
        int sk_sndtimeo;
        int sk_rcvtimeo;
		/* TODO: does not exist on Linux */
        int sk_connecttimeo;

        int sk_state;
};

#endif


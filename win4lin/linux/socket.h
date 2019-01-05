#ifndef _LINUX_SOCKET_H
#define _LINUX_SOCKET_H

#include "windrbd_winsocket.h"
#include <linux/uio.h>	/* for struct kvec */

/* msg flags. Most (but not all) of them unimplemented. */

#if 0
#define MSG_OOB		1
#define MSG_PEEK	2
#endif
#define MSG_DONTROUTE	4
#if 0
#define MSG_TRYHARD     4       /* Synonym for MSG_DONTROUTE for DECnet */
#define MSG_CTRUNC	8
#endif
#define MSG_PROBE	0x10	/* Do not send. Only probe path f.e. for MTU */
#if 0
#define MSG_TRUNC	0x20
#endif
#define MSG_DONTWAIT	0x40	/* Nonblocking io		 */
#if 0
#define MSG_EOR         0x80	/* End of record */
#endif
#define MSG_WAITALL	0x100	/* Wait for a full request */
#if 0
#define MSG_FIN         0x200
#define MSG_SYN		0x400
#define MSG_CONFIRM	0x800	/* Confirm path validity */
#define MSG_RST		0x1000
#define MSG_ERRQUEUE	0x2000	/* Fetch message from error queue */
#endif
#define MSG_NOSIGNAL	0x4000	/* Do not generate SIGPIPE */
#define MSG_MORE	0x8000	/* Sender will send more */
#if 0
#define MSG_WAITFORONE	0x10000	/* recvmmsg(): block until 1+ packets avail */
#define MSG_SENDPAGE_NOTLAST 0x20000 /* sendpage() internal : not the last page */
#define MSG_BATCH	0x40000 /* sendmmsg(): more messages coming */
#define MSG_EOF         MSG_FIN
#define MSG_NO_SHARED_FRAGS 0x80000 /* sendpage() internal : page frags are not shared */
#endif

/* This is somewhere inside arch, we for now only need it here. */

typedef size_t __kernel_size_t;

/* most of these are unused in DRBD, except msg_flags */

struct msghdr {
	void		*msg_name;	/* ptr to socket address structure */
	int		msg_namelen;	/* size of socket address structure */
#if 0
	struct iov_iter	msg_iter;	/* data */
#endif
	void		*msg_control;	/* ancillary data */
	__kernel_size_t	msg_controllen;	/* ancillary data buffer length */
	unsigned int	msg_flags;	/* flags on received message */
#if 0
	struct kiocb	*msg_iocb;	/* ptr to iocb for async requests */
#endif
};

#endif

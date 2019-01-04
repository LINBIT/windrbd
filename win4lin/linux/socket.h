#ifndef _LINUX_SOCKET_H
#define _LINUX_SOCKET_H

#include "wsk2.h"
#include <linux/uio.h>	/* for struct kvec */

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

#ifndef __LINUX_UIO_H
#define __LINUX_UIO_H

struct kvec {
	void *iov_base; /* and that should *never* hold a userland pointer */
	size_t iov_len;
};

#endif

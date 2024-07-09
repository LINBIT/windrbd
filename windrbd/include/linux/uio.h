#ifndef __LINUX_UIO_H
#define __LINUX_UIO_H

#include <linux/bvec.h>

struct iov_iter {
	/* TODO: implement */
};

struct kvec {
	void *iov_base; /* and that should *never* hold a userland pointer */
	size_t iov_len;
};

#define ITER_SOURCE	1	// == WRITE
#define ITER_DEST	0	// == READ

	/* TODO: implement */
void iov_iter_bvec(struct iov_iter *i, unsigned int direction, const struct bio_vec *bvec, unsigned long nr_segs, size_t count);

#endif

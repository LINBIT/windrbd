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

static inline void iov_iter_bvec(struct iov_iter *i, unsigned int direction, const struct bio_vec *bvec, unsigned long nr_segs, size_t count)
{
}

/* something like: */
#if 0
void iov_iter_bvec(struct iov_iter *i, unsigned int direction,
			const struct bio_vec *bvec, unsigned long nr_segs,
			size_t count)
{
	WARN_ON(direction & ~(READ | WRITE));
	*i = (struct iov_iter){
		.iter_type = ITER_BVEC,
		.data_source = direction,
		.bvec = bvec,
		.nr_segs = nr_segs,
		.iov_offset = 0,
		.count = count
	};
}
#endif


#endif

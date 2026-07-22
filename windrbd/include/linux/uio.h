#ifndef __LINUX_UIO_H
#define __LINUX_UIO_H

#include <linux/bvec.h>

enum iter_type {
	/* iter types */
	ITER_UBUF,
	ITER_IOVEC,
	ITER_BVEC,
	ITER_KVEC,
	ITER_XARRAY,
	ITER_DISCARD,
};

struct iov_iter {
	u8 iter_type;
	bool nofault;
	bool data_source;
	size_t iov_offset;
	/*
	 * Hack alert: overlay ubuf_iovec with iovec + count, so
	 * that the members resolve correctly regardless of the type
	 * of iterator used. This means that you can use:
	 *
	 * &iter->__ubuf_iovec or iter->__iov
	 *
	 * interchangably for the user_backed cases, hence simplifying
	 * some of the cases that need to deal with both.
	 */
	union {
		struct {
			union {
				/* use iter_iov() to get the current vec */
				const struct iovec *__iov;
				const struct kvec *kvec;
				const struct bio_vec *bvec;
				struct xarray *xarray;
				void __user *ubuf;
			};
			size_t count;
		};
	};
	union {
		ULONG_PTR nr_segs;
		loff_t xarray_start;
	};
};

struct kvec {
	void *iov_base; /* and that should *never* hold a userland pointer */
	size_t iov_len;
};

#define ITER_SOURCE	1	// == WRITE
#define ITER_DEST	0	// == READ

static inline void iov_iter_bvec(struct iov_iter *i, unsigned int direction, const struct bio_vec *bvec, ULONG_PTR nr_segs, size_t count)
{
	*i = (struct iov_iter){
		.iter_type = ITER_BVEC,
		.data_source = direction,
		.bvec = bvec,
		.nr_segs = nr_segs,
		.iov_offset = 0,
		.count = count
	};
}

static inline void iov_iter_kvec(struct iov_iter *i, unsigned int direction,
			const struct kvec *kvec, unsigned long nr_segs,
			size_t count)
{
	*i = (struct iov_iter){
		.iter_type = ITER_KVEC,
		.data_source = direction,
		.kvec = kvec,
		.nr_segs = nr_segs,
		.iov_offset = 0,
		.count = count
	};
}

#endif

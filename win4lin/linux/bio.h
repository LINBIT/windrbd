#ifndef BIO_H
#define BIO_H

#include <linux/mempool.h>
#include <linux/bvec.h>
#include <linux/blkdev.h>

/* Since this code assumes that a 'page' is always PAGE_SIZE (which
 * is not true for WinDRBD for performance reasons) we are using
 * the old implementation that simply iterates through the biovec
 * elements.
 */

#if 0

static inline bool bio_no_advance_iter(struct bio *bio)
{
	return bio_op(bio) == REQ_OP_DISCARD ||
	       bio_op(bio) == REQ_OP_SECURE_ERASE ||
	       bio_op(bio) == REQ_OP_WRITE_SAME ||
	       bio_op(bio) == REQ_OP_WRITE_ZEROES;
}

static inline void bio_advance_iter(struct bio *bio, struct bvec_iter *iter,
				    unsigned bytes)
{
	iter->bi_sector += bytes >> 9;

	if (bio_no_advance_iter(bio))
		iter->bi_size -= bytes;
	else
		bvec_iter_advance(bio->bi_io_vec, iter, bytes);
		/* TODO: It is reasonable to complete bio with error here. */
}

#define bio_iter_iovec(bio, iter)				\
	bvec_iter_bvec((bio)->bi_io_vec, (iter))

#define __bio_for_each_segment(bvl, bio, iter, start)			\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = bio_iter_iovec((bio), (iter))), 1);		\
	     bio_advance_iter((bio), &(iter), (bvl).bv_len))

#define bio_for_each_segment(bvl, bio, iter)				\
	__bio_for_each_segment(bvl, bio, iter, (bio)->bi_iter)

#define bio_iter_last(bvec, iter) ((iter).bi_size == (bvec).bv_len)

#endif

static inline void bioset_exit(struct bio_set *b)
{
	bioset_free(b);
}

#endif

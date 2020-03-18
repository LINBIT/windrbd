#ifndef _BVEC_H
#define _BVEC_H

#include <linux/blkdev.h>

#define __bvec_iter_bvec(bvec, iter)	(&(bvec)[(iter).bi_idx])

/* multi-page (mp_bvec) helpers */
#define mp_bvec_iter_page(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_page)

#define mp_bvec_iter_len(bvec, iter)				\
	min((iter).bi_size,					\
	    __bvec_iter_bvec((bvec), (iter))->bv_len - (iter).bi_bvec_done)

#define mp_bvec_iter_offset(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_offset + (iter).bi_bvec_done)

#define mp_bvec_iter_page_idx(bvec, iter)			\
	(mp_bvec_iter_offset((bvec), (iter)) / PAGE_SIZE)

static inline bool bvec_iter_advance(const struct bio_vec *bv,
		struct bvec_iter *iter, unsigned bytes)
{
	unsigned int idx = iter->bi_idx;

	if (bytes > iter->bi_size) {
		printk("Warning: Attempted to advance past end of bvec iter\n");
		iter->bi_size = 0;
		return false;
	}

	iter->bi_size -= bytes;
	bytes += iter->bi_bvec_done;

	while (bytes && bytes >= bv[idx].bv_len) {
		bytes -= bv[idx].bv_len;
		idx++;
	}

	iter->bi_idx = idx;
	iter->bi_bvec_done = bytes;
	return true;
}

#define __bvec_iter_bvec(bvec, iter)	(&(bvec)[(iter).bi_idx])

#define mp_bvec_iter_len(bvec, iter)				\
	min((iter).bi_size,					\
	    __bvec_iter_bvec((bvec), (iter))->bv_len - (iter).bi_bvec_done)

#define mp_bvec_iter_offset(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_offset + (iter).bi_bvec_done)

#define bvec_iter_offset(bvec, iter)				\
	(mp_bvec_iter_offset((bvec), (iter)) % PAGE_SIZE)

#define bvec_iter_len(bvec, iter)				\
	min_t(unsigned, mp_bvec_iter_len((bvec), (iter)),		\
	      PAGE_SIZE - bvec_iter_offset((bvec), (iter)))

#define bvec_iter_page(bvec, iter)				\
	(mp_bvec_iter_page((bvec), (iter)) +			\
	 mp_bvec_iter_page_idx((bvec), (iter)))

#define bvec_iter_bvec(bvec, iter)				\
((struct bio_vec) {						\
	.bv_page	= bvec_iter_page((bvec), (iter)),	\
	.bv_len		= bvec_iter_len((bvec), (iter)),	\
	.bv_offset	= bvec_iter_offset((bvec), (iter)),	\
})

#endif

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

/* Makes DRBD compute max bio size as 1 MB */

#define BIO_MAX_VECS 256

/*
 * Check whether this bio carries any data or not. A NULL bio is allowed.
 */
static inline bool bio_has_data(struct bio *bio)
{
	if (bio &&
	    bio->bi_iter.bi_size &&
	    bio_op(bio) != REQ_OP_DISCARD &&
	    bio_op(bio) != REQ_OP_SECURE_ERASE &&
	    bio_op(bio) != REQ_OP_WRITE_ZEROES)
		return true;

	return false;
}

static inline bool bio_no_advance_iter(struct bio *bio)
{
/* TODO: writesame? This is in DRBD 9.0 but not in DRBD 9.1 ... */
#if 0
	return bio_op(bio) == REQ_OP_DISCARD ||
	       bio_op(bio) == REQ_OP_SECURE_ERASE ||
	       bio_op(bio) == REQ_OP_WRITE_SAME ||
	       bio_op(bio) == REQ_OP_WRITE_ZEROES;
#endif
	return bio_op(bio) == REQ_OP_DISCARD ||
	       bio_op(bio) == REQ_OP_SECURE_ERASE ||
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

/* TODO: this is mainly unimplemented: */

struct bio_set {
	mempool_t *bio_pool;
};

extern struct bio *bio_clone(struct bio *, gfp_t x);
extern struct bio_set *bioset_create(unsigned int, unsigned int);
extern void bioset_free(struct bio_set *);

#define bio_clone_fast(bio, gfp, bio_set) bio_clone(bio, gfp)

#if (defined DRBD_9_1) || (defined DRBD_9_2)
extern struct bio *bio_alloc(struct block_device *bdev,
		unsigned short nr_vecs, blk_opf_t opf, gfp_t gfp_mask);
extern struct bio *bio_alloc_bioset(struct block_device *bdev, unsigned short nr_vecs,
			     blk_opf_t opf, gfp_t gfp_mask,
			     struct bio_set *bs);
extern struct bio *bio_alloc_clone(struct block_device *bdev, struct bio *bio_src,
		gfp_t gfp, struct bio_set *bs);

#else
extern struct bio *bio_alloc(gfp_t, int);
extern struct bio *bio_alloc_bioset(gfp_t gfp_mask, int nr_iovecs, struct bio_set *unused);
#endif

	/* Old interface for use in WinDRBD only */
extern struct bio *bio_alloc_old(gfp_t, int);

static inline int bioset_init(struct bio_set *bs, unsigned int size, unsigned int front_pad, int flags)
{
	bs->bio_pool = NULL;
	return 0;
}

static inline void bioset_exit(struct bio_set *b)
{
}

#define bio_iovec(bio)		bio_iter_iovec((bio), (bio)->bi_iter)

#define BIO_POOL_SIZE 2

enum {
	BIOSET_NEED_BVECS = 1,
	BIOSET_NEED_RESCUER = 2,
	BIOSET_PERCPU_CACHE = 4,
};

static inline void bio_get(struct bio *bio)
{
	atomic_inc(&bio->bi_cnt);
}

extern void bio_put(struct bio *);

extern void bio_free(struct bio *bio);
// extern int bio_add_page(struct bio *bio, struct page *page, unsigned int len,unsigned int offset);
extern int bio_add_page_debug(struct bio *bio, struct page *page, unsigned int len,unsigned int offset, const char *file, int line, const char *func);

#define bio_add_page(bio, page, len, offset) \
    bio_add_page_debug(bio, page, len, offset, __FILE__, __LINE__, __func__) 
#define __bio_add_page(bio, page, len, offset) \
    bio_add_page_debug(bio, page, len, offset, __FILE__, __LINE__, __func__) 

extern void bio_endio(struct bio *bio);

static inline void bio_set_dev(struct bio *bio, struct block_device *bdev)
{
	bio->bi_bdev = bdev;
}

#endif

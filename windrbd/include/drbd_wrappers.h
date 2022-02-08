#ifndef _DRBD_WRAPPERS_H
#define _DRBD_WRAPPERS_H

#include "compat.h"
#include <linux/version.h>
#include <linux/net.h>
#include "linux/rbtree.h"
#include "linux/idr.h"
#include "drbd_wingenl.h"
#include "drbd_windows.h"

#include "linux/backing-dev.h"
#include <linux/blkdev.h>

#ifndef pr_fmt
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt
#endif

/* {{{ pr_* macros */
/* some very old kernels don't have them, or at least not all of them */
#ifndef pr_emerg
#define pr_emerg(fmt, ...) \
		printk(KERN_EMERG pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_alert
#define pr_alert(fmt, ...) \
		printk(KERN_ALERT pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_crit
#define pr_crit(fmt, ...) \
		printk(KERN_CRIT pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_err
#define pr_err(fmt, ...) \
		printk(KERN_ERR pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_warning
#define pr_warning(fmt, ...) \
		printk(KERN_WARNING pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_warn
#define pr_warn pr_warning
#endif
#ifndef pr_notice
#define pr_notice(fmt, ...) \
		printk(KERN_NOTICE pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_info
#define pr_info(fmt, ...) \
		printk(KERN_INFO pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_cont
#define pr_cont(fmt, ...) \
		printk(KERN_CONT fmt, __VA_ARGS__)
#endif

/* pr_devel() should produce zero code unless DEBUG is defined */
#ifndef pr_devel
#ifdef DEBUG
#define pr_devel(fmt, ...) \
		printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#else
#define pr_devel(fmt, ...) \
		no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#endif
#endif
/* }}} pr_* macros */

#define REQ_SYNC		(1ULL << __REQ_SYNC)
#define REQ_DISCARD		(1ULL << __REQ_DISCARD)
#define REQ_FUA			(1ULL << __REQ_FUA)
#define REQ_FLUSH		(1ULL << __REQ_FLUSH)


/* The history of blkdev_issue_flush()

   It had 2 arguments before fbd9b09a177a481eda256447c881f014f29034fe,
   after it had 4 arguments. (With that commit came BLKDEV_IFL_WAIT)

   It had 4 arguments before dd3932eddf428571762596e17b65f5dc92ca361b,
   after it got 3 arguments. (With that commit came BLKDEV_DISCARD_SECURE
   and BLKDEV_IFL_WAIT disappeared again.) */
#ifndef BLKDEV_IFL_WAIT
#ifndef BLKDEV_DISCARD_SECURE
/* before fbd9b09a177 */
#endif
/* after dd3932eddf4 no define at all */
#else
/* between fbd9b09a177 and dd3932eddf4 */
#define blkdev_issue_flush(b, gfpf, s)	blkdev_issue_flush(b, gfpf, s, BLKDEV_IFL_WAIT)
#endif


static inline unsigned short queue_logical_block_size(struct request_queue *q)
{
	unsigned short retval = 512;
	if (q && q->logical_block_size)
		retval = q->logical_block_size;
	return retval;
}

static inline sector_t bdev_logical_block_size(struct block_device *bdev)
{
	return queue_logical_block_size(bdev_get_queue(bdev));
}

static inline unsigned int queue_max_hw_sectors(struct request_queue *q)
{
	return q->max_hw_sectors;
}

static inline unsigned int queue_max_sectors(struct request_queue *q)
{
	return q->max_hw_sectors;
}

static inline void blk_queue_logical_block_size(struct request_queue *q, unsigned short size)
{
	q->logical_block_size = size;
}

#define blk_queue_split(bio) do { } while (0)

#ifndef COMPAT_QUEUE_LIMITS_HAS_DISCARD_ZEROES_DATA
static inline unsigned int queue_discard_zeroes_data(struct request_queue *q)
{
	return 0;
}
#endif

static  inline int drbd_always_getpeername(struct socket *sock, struct sockaddr *uaddr)
{
#ifdef COMPAT_SOCK_OPS_RETURNS_ADDR_LEN
	return sock->ops->getname(sock, uaddr, 2);
#else
	int len = 0;
	int err = sock->ops->getname(sock, uaddr, &len, 2);
	return err ?: len;
#endif
}

#ifndef COMPAT_HAVE_BDEV_DISCARD_ALIGNMENT
static inline int bdev_discard_alignment(struct block_device *bdev)
{
	return 0;
}
#endif

#define MAKE_REQUEST_TYPE void
#define MAKE_REQUEST_RETURN return

#define __bitwise__

#ifndef COMPAT_HAVE_FMODE_T
typedef unsigned __bitwise__ fmode_t;
#endif

#ifndef COMPAT_HAVE_BLKDEV_GET_BY_PATH
/* see kernel 2.6.37,
 * d4d7762 block: clean up blkdev_get() wrappers and their users
 * e525fd8 block: make blkdev_get/put() handle exclusive access
 * and kernel 2.6.28
 * 30c40d2 [PATCH] propagate mode through open_bdev_excl/close_bdev_excl
 * Also note that there is no FMODE_EXCL before
 * 86d434d [PATCH] eliminate use of ->f_flags in block methods
 */
#ifndef COMPAT_HAVE_OPEN_BDEV_EXCLUSIVE
#ifndef FMODE_EXCL
#define FMODE_EXCL 0
#endif
static inline
struct block_device *open_bdev_exclusive(const char *path, fmode_t mode, void *holder)
{
}
static inline
void close_bdev_exclusive(struct block_device *bdev, fmode_t mode)
{

}
#endif
static inline int drbd_blkdev_put(struct block_device *bdev, fmode_t mode)
{
	// DW-1109: put ref count and delete bdev if ref gets 0
	struct block_device *b = bdev->bd_parent ? bdev->bd_parent : bdev;
	kref_put(&b->kref, delete_block_device);
	/* blkdev_put seems to not have useful return values,
	 * close_bdev_exclusive is void. */
	return 0;
}
static inline int blkdev_put(struct block_device *bdev, fmode_t mode)
{
	return drbd_blkdev_put(bdev, mode);
}
#endif

#define drbd_bio_uptodate(bio) bio_flagged(bio, BIO_UPTODATE)

typedef u8 blk_status_t;
#define BLK_STS_OK 0
#define BLK_STS_NOTSUPP         ((blk_status_t)1)
#define BLK_STS_MEDIUM          ((blk_status_t)7)
#define BLK_STS_RESOURCE        ((blk_status_t)9)
#define BLK_STS_IOERR           ((blk_status_t)10)

static int blk_status_to_errno(blk_status_t status)
{
        return  status == BLK_STS_OK ? 0 :
                status == BLK_STS_RESOURCE ? -ENOMEM :
                status == BLK_STS_NOTSUPP ? -EOPNOTSUPP :
                -EIO;
}
static inline blk_status_t errno_to_blk_status(int errno)
{
        blk_status_t status =
                errno == 0 ? BLK_STS_OK :
                errno == -ENOMEM ? BLK_STS_RESOURCE :
                errno == -EOPNOTSUPP ? BLK_STS_NOTSUPP :
                BLK_STS_IOERR;

        return status;
}

#define FAULT_TEST_FLAG     ((ULONG_PTR)0x11223344)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define part_inc_in_flight(A, B) part_inc_in_flight(A)
#define part_dec_in_flight(A, B) part_dec_in_flight(A)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
/* Before 2.6.23 (with 20c2df83d25c6a95affe6157a4c9cac4cf5ffaac) kmem_cache_create had a
   ctor and a dtor */
#define kmem_cache_create(N,S,A,F,C) kmem_cache_create(N,S,A,F,C,NULL)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static inline void sg_set_page(struct scatterlist *sg, struct page *page,
			       unsigned int len, unsigned int offset)
{
	sg->page   = page;
	sg->offset = offset;
	sg->length = len;
}

#define sg_init_table(S,N) ({})

#endif

/* how to get to the kobj of a gendisk.
 * see also upstream commits
 * edfaa7c36574f1bf09c65ad602412db9da5f96bf
 * ed9e1982347b36573cd622ee5f4e2a7ccd79b3fd
 * 548b10eb2959c96cef6fc29fc96e0931eeb53bc5
 */
#ifndef dev_to_disk
# define disk_to_kobj(disk) (&(disk)->kobj)
#else
# ifndef disk_to_dev
#  define disk_to_dev(disk) (&(disk)->dev)
# endif
# define disk_to_kobj(disk) (&disk_to_dev(disk)->kobj)
#endif

/* see 7eaceac block: remove per-queue plugging */
#ifdef blk_queue_plugged
static inline void drbd_plug_device(struct request_queue *q)
{
	spin_lock_irq(q->queue_lock);

/* XXX the check on !blk_queue_plugged is redundant,
 * implicitly checked in blk_plug_device */

	if (!blk_queue_plugged(q)) {
		blk_plug_device(q);
		del_timer(&q->unplug_timer);
		/* unplugging should not happen automatically... */
	}
	spin_unlock_irq(q->queue_lock);
}
#else
static inline void drbd_plug_device(struct request_queue *q)
{
}
#endif


#ifndef COMPAT_HAVE_SOCK_SHUTDOWN
#define COMPAT_HAVE_SOCK_SHUTDOWN 1
#endif


#ifndef COMPAT_HAVE_UMH_WAIT_PROC
/* On Jul 17 2007 with commit 86313c4 usermodehelper: Tidy up waiting,
 * UMH_WAIT_PROC was added as an enum value of 1.
 * On Mar 23 2012 with commit 9d944ef3 that got changed to a define of 2. */
#define UMH_WAIT_PROC 1
#endif

/* see upstream commit 2d3854a37e8b767a51aba38ed6d22817b0631e33 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#ifndef cpumask_bits
#define nr_cpu_ids NR_CPUS
#define nr_cpumask_bits nr_cpu_ids

typedef cpumask_t cpumask_var_t[1];
#define cpumask_bits(maskp) ((unsigned long*)(maskp))
#define cpu_online_mask &(cpu_online_map)

#endif
/* see upstream commit 0281b5dc0350cbf6dd21ed558a33cccce77abc02 */
#ifdef CONFIG_CPUMASK_OFFSTACK
static inline int zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	return alloc_cpumask_var(mask, flags | __GFP_ZERO);
}
#else
static inline int zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	cpumask_clear(*mask);
	return 1;
}
#endif
/* see upstream commit cd8ba7cd9be0192348c2836cb6645d9b2cd2bfd2 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
/* As macro because RH has it in 2.6.18-128.4.1.el5, but not exported to modules !?!? */
#define set_cpus_allowed_ptr(P, NM) set_cpus_allowed(P, *NM)
#endif
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define __bitmap_parse(BUF, BUFLEN, ISUSR, MASKP, NMASK) \
	backport_bitmap_parse(BUF, BUFLEN, ISUSR, MASKP, NMASK)

#define CHUNKSZ                         32
#define nbits_to_hold_value(val)        fls(val)
#define unhex(c)                        (isdigit(c) ? (c - '0') : (toupper(c) - 'A' + 10))

static inline int backport_bitmap_parse(const char *buf, unsigned int buflen,
		int is_user, unsigned long *maskp,
		int nmaskbits)
{
	int c, old_c, totaldigits, ndigits, nchunks, nbits;
	u32 chunk;
	const char __user *ubuf = buf;

	bitmap_zero(maskp, nmaskbits);

	nchunks = nbits = totaldigits = c = 0;
	do {
		chunk = ndigits = 0;

		/* Get the next chunk of the bitmap */
		while (buflen) {
			old_c = c;
			if (is_user) {
				if (__get_user(c, ubuf++))
					return -EFAULT;
			}
			else
				c = *buf++;
			buflen--;
			if (isspace(c))
				continue;

			/*
			 * If the last character was a space and the current
			 * character isn't '\0', we've got embedded whitespace.
			 * This is a no-no, so throw an error.
			 */
			if (totaldigits && c && isspace(old_c))
				return -EINVAL;

			/* A '\0' or a ',' signal the end of the chunk */
			if (c == '\0' || c == ',')
				break;

			if (!isxdigit(c))
				return -EINVAL;

			/*
			 * Make sure there are at least 4 free bits in 'chunk'.
			 * If not, this hexdigit will overflow 'chunk', so
			 * throw an error.
			 */
			if (chunk & ~((1UL << (CHUNKSZ - 4)) - 1))
				return -EOVERFLOW;

			chunk = (chunk << 4) | unhex(c);
			ndigits++; totaldigits++;
		}
		if (ndigits == 0)
			return -EINVAL;
		if (nchunks == 0 && chunk == 0)
			continue;

		bitmap_shift_left(maskp, maskp, CHUNKSZ, nmaskbits);
		*maskp |= chunk;
		nchunks++;
		nbits += (nchunks == 1) ? nbits_to_hold_value(chunk) : CHUNKSZ;
		if (nbits > nmaskbits)
			return -EOVERFLOW;
	} while (buflen && c == ',');

	return 0;
}
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define BDI_async_congested BDI_write_congested
#define BDI_sync_congested  BDI_read_congested
#endif

/* see upstream commits
 * 2d3a4e3666325a9709cc8ea2e88151394e8f20fc (in 2.6.25-rc1)
 * 59b7435149eab2dd06dd678742faff6049cb655f (in 2.6.26-rc1)
 * this "backport" does not close the race that lead to the API change,
 * but only provides an equivalent function call.
 */
#ifndef COMPAT_HAVE_PROC_CREATE_DATA

#endif

#ifndef COMPAT_HAVE_BLK_QUEUE_MAX_HW_SECTORS
static inline void blk_queue_max_hw_sectors(struct request_queue *q, unsigned int max)
{
	q->max_hw_sectors = max;
}
#elif defined(COMPAT_USE_BLK_QUEUE_MAX_SECTORS_ANYWAYS)
	/* For kernel versions 2.6.31 to 2.6.33 inclusive, even though
	 * blk_queue_max_hw_sectors is present, we actually need to use
	 * blk_queue_max_sectors to set max_hw_sectors. :-(
	 * RHEL6 2.6.32 chose to be different and already has eliminated
	 * blk_queue_max_sectors as upstream 2.6.34 did.
	 */
#define blk_queue_max_hw_sectors(q, max)	blk_queue_max_sectors(q, max)
#endif

#ifndef COMPAT_HAVE_BLK_QUEUE_MAX_SEGMENTS
static inline void blk_queue_max_segments(struct request_queue *q, unsigned short max_segments)
{
}
#endif

/* REQ_* and BIO_RW_* flags have been moved around in the tree,
 * and have finally been "merged" with
 * 7b6d91daee5cac6402186ff224c3af39d79f4a0e and
 * 7cc015811ef8992dfcce314d0ed9642bc18143d1
 * We communicate between different systems,
 * so we have to somehow semantically map the bi_rw flags
 * bi_rw (some kernel version) -> data packet flags -> bi_rw (other kernel version)
 */

/* RHEL 6.1 backported FLUSH/FUA as BIO_RW_FLUSH/FUA
 * and at that time also introduced the defines BIO_FLUSH/FUA.
 * There is also REQ_FLUSH/FUA, but these do NOT share
 * the same value space as the bio rw flags, yet.
 */
#ifdef BIO_FLUSH

#define DRBD_REQ_FLUSH		(1UL << BIO_RW_FLUSH)
#define DRBD_REQ_FUA		(1UL << BIO_RW_FUA)
#define DRBD_REQ_HARDBARRIER	(1UL << BIO_RW_BARRIER)
#define DRBD_REQ_DISCARD	(1UL << BIO_RW_DISCARD)
#define DRBD_REQ_SYNC		(1UL << BIO_RW_SYNCIO)
#define DRBD_REQ_UNPLUG		(1UL << BIO_RW_UNPLUG)

#elif defined(REQ_FLUSH)	/* introduced in 2.6.36,
				 * now equivalent to bi_rw */

#define DRBD_REQ_SYNC		REQ_SYNC
#define DRBD_REQ_FLUSH		REQ_FLUSH
#define DRBD_REQ_FUA		REQ_FUA
#define DRBD_REQ_DISCARD	REQ_DISCARD
/* REQ_HARDBARRIER has been around for a long time,
 * without being directly related to bi_rw.
 * so the ifdef is only usful inside the ifdef REQ_FLUSH!
 * commit 7cc0158 (v2.6.36-rc1) made it a bi_rw flag, ...  */
#ifdef REQ_HARDBARRIER
#define DRBD_REQ_HARDBARRIER	REQ_HARDBARRIER
#else
/* ... but REQ_HARDBARRIER was removed again in 02e031c (v2.6.37-rc4). */
#define DRBD_REQ_HARDBARRIER	0
#endif

/* again: testing on this _inside_ the ifdef REQ_FLUSH,
 * see 721a960 block: kill off REQ_UNPLUG */
#ifdef REQ_UNPLUG
#define DRBD_REQ_UNPLUG		REQ_UNPLUG
#else
#define DRBD_REQ_UNPLUG		0
#endif

#ifdef REQ_WRITE_SAME
#define DRBD_REQ_WSAME         REQ_WRITE_SAME
#endif

#else				/* "older", and hopefully not
				 * "partially backported" kernel */

#if defined(BIO_RW_SYNC)
/* see upstream commits
 * 213d9417fec62ef4c3675621b9364a667954d4dd,
 * 93dbb393503d53cd226e5e1f0088fe8f4dbaa2b8
 * later, the defines even became an enum ;-) */
#define DRBD_REQ_SYNC		(1UL << BIO_RW_SYNC)
#define DRBD_REQ_UNPLUG		(1UL << BIO_RW_SYNC)
#else
/* cannot test on defined(BIO_RW_SYNCIO), it may be an enum */
#define DRBD_REQ_SYNC		(1UL << BIO_RW_SYNCIO)
#define DRBD_REQ_UNPLUG		(1UL << BIO_RW_UNPLUG)
#endif

#define DRBD_REQ_FLUSH		(1UL << BIO_RW_BARRIER)
/* REQ_FUA has been around for a longer time,
 * without a direct equivalent in bi_rw. */
#define DRBD_REQ_FUA		(1UL << BIO_RW_BARRIER)
#define DRBD_REQ_HARDBARRIER	(1UL << BIO_RW_BARRIER)

/* we don't support DISCARDS yet, anyways.
 * cannot test on defined(BIO_RW_DISCARD), it may be an enum */
#define DRBD_REQ_DISCARD	0
#endif
#ifndef DRBD_REQ_WSAME
#define DRBD_REQ_WSAME          0
#endif

#define REQ_WRITE			REQ_OP_WRITE
/* https://msdn.microsoft.com/en-us/library/windows/hardware/ff549235(v=vs.85).aspx */
#define DRBD_REQ_PREFLUSH	REQ_PREFLUSH

/* this results in:
	bi_rw   -> dp_flags

< 2.6.28
	SYNC	-> SYNC|UNPLUG
	BARRIER	-> FUA|FLUSH
	there is no DISCARD
2.6.28
	SYNC	-> SYNC|UNPLUG
	BARRIER	-> FUA|FLUSH
	DISCARD	-> DISCARD
2.6.29
	SYNCIO	-> SYNC
	UNPLUG	-> UNPLUG
	BARRIER	-> FUA|FLUSH
	DISCARD	-> DISCARD
2.6.36
	SYNC	-> SYNC
	UNPLUG	-> UNPLUG
	FUA	-> FUA
	FLUSH	-> FLUSH
	DISCARD	-> DISCARD
--------------------------------------
	dp_flags   -> bi_rw
< 2.6.28
	SYNC	-> SYNC (and unplug)
	UNPLUG	-> SYNC (and unplug)
	FUA	-> BARRIER
	FLUSH	-> BARRIER
	there is no DISCARD,
	it will be silently ignored on the receiving side.
2.6.28
	SYNC	-> SYNC (and unplug)
	UNPLUG	-> SYNC (and unplug)
	FUA	-> BARRIER
	FLUSH	-> BARRIER
	DISCARD -> DISCARD
	(if that fails, we handle it like any other IO error)
2.6.29
	SYNC	-> SYNCIO
	UNPLUG	-> UNPLUG
	FUA	-> BARRIER
	FLUSH	-> BARRIER
	DISCARD -> DISCARD
2.6.36
	SYNC	-> SYNC
	UNPLUG	-> UNPLUG
	FUA	-> FUA
	FLUSH	-> FLUSH
	DISCARD	-> DISCARD
*/

#ifndef REQ_NOIDLE
/* introduced in aeb6faf (2.6.30), relevant for CFQ */
#define REQ_NOIDLE 0
#endif

#ifndef KREF_INIT
#define KREF_INIT(N) { ATOMIC_INIT(N) }
#endif

#define _adjust_ra_pages(qrap, brap) do { \
	if (qrap != brap) { \
		drbd_info(device, "Adjusting my ra_pages to backing device's (%lu -> %lu)\n", qrap, brap); \
		qrap = brap; \
	} \
} while(0)

#ifdef COMPAT_HAVE_POINTER_BACKING_DEV_INFO
#define bdi_from_device(device) (device->ldev->backing_bdev->bd_disk->queue->backing_dev_info)
#define init_bdev_info(bdev_info, drbd_congested, device) do { \
	(bdev_info)->congested_fn = drbd_congested; \
	(bdev_info)->congested_data = device; \
} while(0)
#define adjust_ra_pages(q, b) _adjust_ra_pages((q)->backing_dev_info->ra_pages, (b)->backing_dev_info->ra_pages)
#else
#define bdi_rw_congested(BDI) bdi_rw_congested(&BDI)
#define bdi_congested(BDI, BDI_BITS) bdi_congested(&BDI, (BDI_BITS))
#define bdi_from_device(device) (&device->ldev->backing_bdev->bd_disk->queue->backing_dev_info)
#define init_bdev_info(bdev_info, drbd_congested, device) do { \
	(bdev_info).congested_fn = drbd_congested; \
	(bdev_info).congested_data = device; \
} while(0)
#define adjust_ra_pages(q, b) _adjust_ra_pages((q)->backing_dev_info.ra_pages, (b)->backing_dev_info.ra_pages)
#endif

#ifndef CONFIG_DYNAMIC_DEBUG
/* At least in 2.6.34 the function macro dynamic_dev_dbg() is broken when compiling
   without CONFIG_DYNAMIC_DEBUG. It has 'format' in the argument list, it references
   to 'fmt' in its body. */
#ifdef dynamic_dev_dbg
#undef dynamic_dev_dbg
#define dynamic_dev_dbg(dev, fmt, ...)                               \
        do { if (0) dev_printk(KERN_DEBUG, dev, fmt, ##__VA_ARGS__); } while (0)
#endif
#define dynamic_dev_dbg(dev, fmt, ...)   
#endif

#ifndef min_not_zero
#define min_not_zero(x, y) (x == 0 ? y : ((y == 0) ? x : min(x, y)))
#endif

/* Introduced with 2.6.26. See include/linux/jiffies.h */
#ifndef time_is_before_eq_jiffies
#define time_is_before_jiffies(a) time_after(jiffies, a)
#define time_is_after_jiffies(a) time_before(jiffies, a)
#define time_is_before_eq_jiffies(a) time_after_eq(jiffies, a)
#define time_is_after_eq_jiffies(a) time_before_eq(jiffies, a)
#endif

#ifndef time_in_range
#define time_in_range(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before_eq(a,c))
#endif

#ifdef COMPAT_BIO_SPLIT_HAS_BIO_SPLIT_POOL_PARAMETER
#define bio_split(bi, first_sectors) bio_split(bi, bio_split_pool, first_sectors)
#endif

#ifndef COMPAT_HAVE_BIOSET_CREATE_FRONT_PAD
/* see comments in compat/tests/have_bioset_create_front_pad.c */
#ifdef COMPAT_BIOSET_CREATE_HAS_THREE_PARAMETERS
#define bioset_create(pool_size, front_pad)	bioset_create(pool_size, pool_size, 1)
#else
#endif
#endif


#if !(defined(COMPAT_HAVE_RB_AUGMENT_FUNCTIONS) && \
      defined(AUGMENTED_RBTREE_SYMBOLS_EXPORTED))

/*
 * Make sure the replacements for the augmented rbtree helper functions do not
 * clash with functions the kernel implements but does not export.
 */
#define rb_augment_f drbd_rb_augment_f
#define rb_augment_path drbd_rb_augment_path
#define rb_augment_insert drbd_rb_augment_insert
#define rb_augment_erase_begin drbd_rb_augment_erase_begin
#define rb_augment_erase_end drbd_rb_augment_erase_end

typedef void (*rb_augment_f)(struct rb_node *node, void *data);

static inline void rb_augment_path(struct rb_node *node, rb_augment_f func, void *data)
{
	struct rb_node *parent;

up:
	func(node, data);
	parent = rb_parent(node);
	if (!parent)
		return;

	if (node == parent->rb_left && parent->rb_right)
		func(parent->rb_right, data);
	else if (parent->rb_left)
		func(parent->rb_left, data);

	node = parent;
	goto up;
}

/*
 * after inserting @node into the tree, update the tree to account for
 * both the new entry and any damage done by rebalance
 */
static inline void rb_augment_insert(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node->rb_left)
		node = node->rb_left;
	else if (node->rb_right)
		node = node->rb_right;

	rb_augment_path(node, func, data);
}

/*
 * before removing the node, find the deepest node on the rebalance path
 * that will still be there after @node gets removed
 */
static inline struct rb_node *rb_augment_erase_begin(struct rb_node *node)
{
	struct rb_node *deepest;

	if (!node->rb_right && !node->rb_left)
		deepest = rb_parent(node);
	else if (!node->rb_right)
		deepest = node->rb_left;
	else if (!node->rb_left)
		deepest = node->rb_right;
	else {
		deepest = rb_next(node);
		if (deepest->rb_right)
			deepest = deepest->rb_right;
		else if (rb_parent(deepest) != node)
			deepest = rb_parent(deepest);
	}

	return deepest;
}

/*
 * after removal, update the tree to account for the removed entry
 * and any rebalance damage.
 */
static inline void rb_augment_erase_end(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node)
		rb_augment_path(node, func, data);
}
#endif

/*
 * In commit c4945b9e (v2.6.39-rc1), the little-endian bit operations have been
 * renamed to be less weird.
 */
#ifndef COMPAT_HAVE_FIND_NEXT_ZERO_BIT_LE
#define find_next_zero_bit_le(addr, size, offset) \
	generic_find_next_zero_le_bit(addr, size, offset)
#define find_next_bit_le(addr, size, offset) \
	generic_find_next_le_bit(addr, size, offset)
#define test_bit_le(nr, addr) \
	generic_test_le_bit(nr, addr)
#define __test_and_set_bit_le(nr, addr) \
	generic___test_and_set_le_bit(nr, addr)
#define __test_and_clear_bit_le(nr, addr) \
	generic___test_and_clear_le_bit(nr, addr)
#endif

#ifndef IDR_GET_NEXT_EXPORTED
/* Body in compat/idr.c */
extern void *idr_get_next(struct idr *idp, int *nextidp);
#endif

#ifndef RCU_INITIALIZER
#define RCU_INITIALIZER(v) (typeof(*(v)) *)(v)
#endif
#ifndef RCU_INIT_POINTER
#define RCU_INIT_POINTER(p, v) \
	do { \
		p = RCU_INITIALIZER(v); \
    	} while (0)
#endif

/* #ifndef COMPAT_HAVE_LIST_ENTRY_RCU */
#ifndef list_entry_rcu
#ifndef rcu_dereference_raw
/* see c26d34a rcu: Add lockdep-enabled variants of rcu_dereference() */
#define rcu_dereference_raw(p) rcu_dereference(p)
#endif
#define list_entry_rcu(ptr, type, member)   \
	 container_of((type *)rcu_dereference_raw(ptr), type, member)
#endif

#ifndef list_next_entry
/* introduced in 008208c (v3.13-rc1) */
#define list_next_entry(type, pos, member) \
        list_entry((pos)->member.next, type, member)
#endif

/*
 * Introduced in 930631ed (v2.6.19-rc1).
 */
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

/*
 * IS_ALIGNED() was added to <linux/kernel.h> in mainline commit 0c0e6195 (and
 * improved in f10db627); 2.6.24-rc1.
 */
#ifndef IS_ALIGNED
#define IS_ALIGNED(x, a) (((x) & ((a) - 1)) == 0)
#endif

/*
 * NLA_TYPE_MASK and nla_type() were added to <linux/netlink.h> in mainline
 * commit 8f4c1f9b; v2.6.24-rc1.  Before that, none of the nlattr->nla_type
 * flags had a special meaning.
 */

#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK ~0

static inline int nla_type(const struct nlattr *nla)
{
}

#endif

/*
 * nlmsg_hdr was added to <linux/netlink.h> in mainline commit b529ccf2
 * (v2.6.22-rc1).
 */

#ifndef COMPAT_HAVE_NLMSG_HDR
static inline struct nlmsghdr *nlmsg_hdr(const struct sk_buff *skb)
{
	return (struct nlmsghdr *)skb->data;
}
#endif

/*
 * genlmsg_reply() was added to <net/genetlink.h> in mainline commit 81878d27
 * (v2.6.20-rc2).
 */

#ifndef COMPAT_HAVE_GENLMSG_REPLY

static inline int genlmsg_reply(struct sk_buff *skb, struct genl_info *info)
{
	return genlmsg_unicast(skb, info);
}
#endif

/*
 * genlmsg_msg_size() and genlmsg_total_size() were added to <net/genetlink.h>
 * in mainline commit 17db952c (v2.6.19-rc1).
 */

#ifndef COMPAT_HAVE_GENLMSG_MSG_SIZE
#endif

/*
 * genlmsg_new() was added to <net/genetlink.h> in mainline commit 3dabc715
 * (v2.6.20-rc2).
 */

#ifndef COMPAT_HAVE_GENLMSG_NEW
extern struct sk_buff *genlmsg_new(size_t payload, gfp_t flags);
#else
#include <net/genetlink.h>

static inline struct sk_buff *genlmsg_new(size_t payload, gfp_t flags)
{
	return nlmsg_new(genlmsg_total_size(payload), flags);
}
#endif

extern void *genlmsg_put(struct sk_buff *skb, u32 pid, u32 seq,
		           struct genl_family *family, int flags, u8 cmd);

extern void *genlmsg_put_reply(struct sk_buff *skb,
                         struct genl_info *info,
                         struct genl_family *family,
                         int flags, u8 cmd);

/*
 * compat_genlmsg_multicast() got a gfp_t parameter in mainline commit d387f6ad
 * (v2.6.19-rc1).
 */

static inline int genlmsg_multicast(struct sk_buff *skb, u32 pid,
					   unsigned int group, gfp_t flags)
{
    /* Only declaration needed */
}

/*
 * Dynamic generic netlink multicast groups were introduced in mainline commit
 * 2dbba6f7 (v2.6.23-rc1).  Before that, netlink had a fixed number of 32
 * multicast groups.  Use an arbitrary hard-coded group number for that case.
 */

#ifndef COMPAT_HAVE_CTRL_ATTR_MCAST_GROUPS

struct genl_multicast_group {
	struct genl_family	*family;	/* private */
        struct list_head	list;		/* private */
        char			name[GENL_NAMSIZ];
	u32			id;
};

static inline int genl_register_mc_group(struct genl_family *family,
					 struct genl_multicast_group *grp)
{
	grp->id = 1;
	return 0;
}

static inline void genl_unregister_mc_group(struct genl_family *family,
					    struct genl_multicast_group *grp)
{
}

#endif

/*
 * kref_sub() was introduced in mainline commit ecf7ace9 (v2.6.38-rc1).
 */
#ifndef COMPAT_HAVE_KREF_SUB
static inline void kref_sub(struct kref *kref, unsigned int count,
			    void (*release) (struct kref *kref))
{
	while (count--)
		kref_put(kref, release);
}
#endif

/*
 * list_for_each_entry_continue_rcu() was introduced in mainline commit
 * 254245d2 (v2.6.33-rc1).
 */
#ifndef list_for_each_entry_continue_rcu
#define list_for_each_entry_continue_rcu(type, pos, head, member)             \
	for (pos = list_entry_rcu(pos->member.next, type, member); \
	     &pos->member != (head);    \
	     pos = list_entry_rcu(pos->member.next, type, member))
#endif

#ifndef COMPAT_HAVE_IS_ERR_OR_NULL
//#define	IS_ERR_OR_NULL(p) (!p)
// move to windfows.h 
#endif

#ifndef COMPAT_HAVE_KREF_GET_UNLESS_ZERO
static __inline int kref_get_unless_zero(struct kref *kref)
{
    return 0;
}
#endif

#ifndef COMPAT_HAVE_THREE_PARAMATER_HLIST_FOR_EACH_ENTRY
#undef hlist_for_each_entry
#define hlist_for_each_entry(type, pos, head, member)				\
	for (pos = hlist_entry((head)->first, type, member);	\
	     pos;							\
	     pos = hlist_entry((pos)->member.next, type, member))
#endif

#ifndef COMPAT_HAVE_PRANDOM_U32
static int random32_win()
{
    int buf;
    get_random_bytes(&buf, 4);
    return buf;
}
static inline u32 prandom_u32(void)
{
    return random32_win();
}
#endif

#ifdef COMPAT_HAVE_NETLINK_CB_PORTID
#define NETLINK_CB_PORTID(skb) NETLINK_CB(skb).portid
#else
#define NETLINK_CB_PORTID(skb) ((struct netlink_callback *)((void *)&skb))->nlh->nlmsg_pid
#endif

#ifndef COMPAT_HAVE_PROC_PDE_DATA
#define PDE_DATA(inode) PDE(inode)->data
#endif

#ifndef list_first_entry
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#endif

#ifndef list_first_entry_or_null
#define list_first_entry_or_null(ptr, type, member) \
	(list_empty(ptr) ? NULL : list_first_entry(ptr, type, member))
#endif

#ifndef COMPAT_HAVE_IDR_ALLOC
static inline int idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp_mask)
{
	int rv, got;

printk("IDR 1\n");
	if (!idr_pre_get(idr, gfp_mask))
		return -ENOMEM;
	rv = idr_get_new_above(idr, ptr, start, &got);
	if (rv < 0)
		return rv;

	if (got >= end) {
		idr_remove(idr, got);
		return -ENOSPC;
	}

	return got;
}
#endif

#ifndef BLKDEV_ISSUE_ZEROOUT_EXPORTED
/* Was introduced with 2.6.34 */
extern int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
				sector_t nr_sects, gfp_t gfp_mask, bool discard);
#else
/* synopsis changed a few times, though */
#ifdef COMPAT_BLKDEV_ISSUE_ZEROOUT_BLKDEV_IFL_WAIT
#define blkdev_issue_zeroout(BDEV, SS, NS, GFP, discard) \
	blkdev_issue_zeroout(BDEV, SS, NS, GFP, BLKDEV_IFL_WAIT)
#elif !defined(COMPAT_BLKDEV_ISSUE_ZEROOUT_DISCARD)
#define blkdev_issue_zeroout(BDEV, SS, NS, GFP, discard) \
	blkdev_issue_zeroout(BDEV, SS, NS, GFP)
#endif
#endif


#ifndef COMPAT_HAVE_GENL_LOCK
static inline void genl_lock(void)  { }
static inline void genl_unlock(void)  { }
#endif


# define queue_flag_set_unlocked(F, Q)				\
    do {							\
        if ((F) != -1)					\
            __set_bit(F, &(Q)->queue_flags);		\
    } while(0)

# define queue_flag_clear_unlocked(F, Q)			\
    do {							\
        if ((F) != -1)					\
            clear_bit(F, &(Q)->queue_flags);	\
    } while (0)
# ifndef blk_queue_discard
#  define blk_queue_discard(q)   (0)
#  define QUEUE_FLAG_DISCARD    (-1)
# endif

# ifndef blk_queue_secdiscard
#  define blk_queue_secdiscard(q)   (0)
#  define QUEUE_FLAG_SECDISCARD    (-1)
# endif

#define QUEUE_FLAG_STABLE_WRITES 15	/* don't modify blks until WB is done */

#ifndef COMPAT_HAVE_BLK_SET_STACKING_LIMITS
static inline void blk_set_stacking_limits(struct queue_limits *lim)
{
# ifdef COMPAT_QUEUE_LIMITS_HAS_DISCARD_ZEROES_DATA
	lim->discard_zeroes_data = 1;
# endif
}
#endif

#ifndef COMPAT_HAVE_RCU_DEREFERENCE_PROTECTED
#define rcu_dereference_protected(p, c) (p)
#endif

#ifndef list_next_rcu
#define list_next_rcu(list)	(*((struct list_head **)(&(list)->next)))
#endif

#ifndef list_first_or_null_rcu
#define list_first_or_null_rcu(conn, ptr, type, member) \
    do {    \
        struct list_head *__ptr = (ptr);    \
        struct list_head *__next = (__ptr->next);    \
        if (likely(__ptr != __next))    \
            conn = list_entry_rcu(__next, type, member);   \
        else   \
           conn = NULL;    \
    }while (0)
#endif

#ifndef COMPAT_HAVE_GENERIC_START_IO_ACCT
#ifndef __disk_stat_inc
struct hd_struct;
static inline void generic_start_io_acct(int rw, unsigned long sectors,
					 struct hd_struct *part)
{
	// DbgPrint("generic_start_io_acct\n");
}

static inline void generic_end_io_acct(int rw, struct hd_struct *part,
				  unsigned long start_time)
{
	// DbgPrint("generic_end_io_acct\n");
}
#endif /* __disk_stat_inc */
#endif /* COMPAT_HAVE_GENERIC_START_IO_ACCT */


#ifndef COMPAT_HAVE_WB_CONGESTED_ENUM
#define WB_async_congested BDI_async_congested
#define WB_sync_congested BDI_sync_congested
#endif

static int idr_has_entry(int id, void *p, void *data)
{
	return 1;
}

static inline bool idr_is_empty(struct idr *idr)
{
	return !idr_for_each(idr, idr_has_entry, NULL);
}


#ifndef COMPAT_HAVE_ATOMIC_DEC_IF_POSITIVE
static inline int atomic_dec_if_positive(atomic_t *v)
{
        int c, old, dec;
        c = atomic_read(v);
        for (;;) {
                dec = c - 1;
                if (unlikely(dec < 0))
                        break;
                old = atomic_cmpxchg((v), c, dec);
                if (likely(old == c))
                        break;
                c = old;
        }
        return dec;
}
#endif

#ifndef COMPAT_HAVE_BIO_CLONE_FAST
#define bio_clone_fast(bio, gfp, bio_set) bio_clone(bio, gfp)
#endif

#define bio_set_dev(bio, bdev) (bio)->bi_bdev = bdev

/* This is currently not supported by WinDRBD */
#define BLKDEV_ZERO_NOUNMAP (false)

/* nla_parse_nested got a new parameter in 150c76aa (drbd-kernel-compat)
 * which we ignore.
 */
#define nla_parse_nested(tb, maxtype, nla, policy, extack) \
       nla_parse_nested(tb, maxtype, nla, policy)

struct netlink_ext_ack;

static inline int nla_parse_nested_deprecated(struct nlattr *tb[], int maxtype,
					      const struct nlattr *nla,
					      const struct nla_policy *policy,
					      struct netlink_ext_ack *extack)
{
	return nla_parse_nested(tb, maxtype, nla, policy, extack);
}

#define REQ_OP_WRITE_ZEROES (-3u)

#define PageSlab(p) (0)

/* timer interface before v4.16 */
#define DRBD_TIMER_FN_ARG ULONG_PTR data
#define DRBD_TIMER_ARG2OBJ(OBJ, MEMBER) (struct drbd_##OBJ *) data
#define drbd_timer_setup(OBJ, MEMBER, TIMER_FN) setup_timer(&OBJ->MEMBER, TIMER_FN, (ULONG_PTR)OBJ)
#define DRBD_TIMER_CALL_ARG(OBJ, MEMBER) (ULONG_PTR) OBJ

/* taken from commits 020981 and 32e13cff of drbd-kernel-compat */

#ifndef COMPAT_HAVE_BIOSET_INIT
#ifndef COMPAT_HAVE_BIO_CLONE_FAST
# define bio_clone_fast(bio, gfp, bio_set) bio_clone(bio, gfp)
#else
# define bio_clone_fast(BIO, GFP, P) bio_clone_fast(BIO, GFP, *P)
#endif

#define DRBD_MEMPOOL_T mempool_t *
#define DRBD_BIO_SET   bio_set *

#if defined(COMPAT_HAVE_BIOSET_NEED_BVECS)
#define bioset_init(BS, S, FP, F) __bioset_init(BS, S, FP, F)
#else
#define bioset_init(BS, S, FP, F) __bioset_init(BS, S, FP, 0)
#endif
static inline int
__bioset_init(struct bio_set **bs, unsigned int size, unsigned int front_pad, int flags)
{
	*bs = bioset_create(size, front_pad);
	return *bs == NULL ? -ENOMEM : 0;
}
static inline bool
bioset_initialized(struct bio_set **bs)
{
	return *bs != NULL;
}
#else
#define DRBD_MEMPOOL_T mempool_t
#define DRBD_BIO_SET   bio_set
#endif

/* This is currently not supported by windrbd */
#define DRBD_REQ_NOUNMAP        0

#endif


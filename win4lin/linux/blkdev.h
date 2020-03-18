#ifndef BLKDEV_H
#define BLKDEV_H

#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT 9
#endif
#ifndef SECTOR_SIZE
#define SECTOR_SIZE (1 << SECTOR_SHIFT)
#endif

#define bio_op(bio) \
	((bio)->bi_opf & REQ_OP_MASK)

#include <linux/timer.h>

/* originally in linux/blk_types.h */
typedef unsigned int blk_qc_t;
#define BLK_QC_T_NONE		-1U
#define BLK_QC_T_EAGAIN		-2U
#define BLK_QC_T_SHIFT		16
#define BLK_QC_T_INTERNAL	(1U << 31)

/* originally in linux/blk_types.h */
typedef u8 blk_status_t;
#define	BLK_STS_OK 0
#define BLK_STS_NOTSUPP		((blk_status_t)1)
#define BLK_STS_TIMEOUT		((blk_status_t)2)
#define BLK_STS_NOSPC		((blk_status_t)3)
#define BLK_STS_TRANSPORT	((blk_status_t)4)
#define BLK_STS_TARGET		((blk_status_t)5)
#define BLK_STS_NEXUS		((blk_status_t)6)
#define BLK_STS_MEDIUM		((blk_status_t)7)
#define BLK_STS_PROTECTION	((blk_status_t)8)
#define BLK_STS_RESOURCE	((blk_status_t)9)
#define BLK_STS_IOERR		((blk_status_t)10)

extern int blkdev_issue_write_same(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, struct page *page);
extern int blkdev_issue_discard(struct block_device *bdev, sector_t sector,
        sector_t nr_sects, gfp_t gfp_mask, ULONG_PTR flags);

#define REQ_OP_BITS	8
#define REQ_OP_MASK	((1 << REQ_OP_BITS) - 1)

enum req_flag_bits {
	__REQ_FAILFAST_DEV =	/* no driver retries of device errors */
		REQ_OP_BITS,
	__REQ_FAILFAST_TRANSPORT, /* no driver retries of transport errors */
	__REQ_FAILFAST_DRIVER,	/* no driver retries of driver errors */
	__REQ_SYNC,		/* request is sync (sync write or read) */
	__REQ_META,		/* metadata io request */
	__REQ_PRIO,		/* boost priority in cfq */
	__REQ_NOMERGE,		/* don't touch this for merging */
	__REQ_IDLE,		/* anticipate more IO after this one */
	__REQ_INTEGRITY,	/* I/O includes block integrity payload */
	__REQ_FUA,		/* forced unit access */
	__REQ_PREFLUSH,		/* request for cache flush */
	__REQ_RAHEAD,		/* read ahead, can fail anytime */
	__REQ_BACKGROUND,	/* background IO */
	__REQ_NOWAIT,           /* Don't wait if request will block */
	__REQ_NOWAIT_INLINE,	/* Return would-block error inline */
	/*
	 * When a shared kthread needs to issue a bio for a cgroup, doing
	 * so synchronously can lead to priority inversions as the kthread
	 * can be trapped waiting for that cgroup.  CGROUP_PUNT flag makes
	 * submit_bio() punt the actual issuing to a dedicated per-blkcg
	 * work item to avoid such priority inversions.
	 */
	__REQ_CGROUP_PUNT,

	/* command specific flags for REQ_OP_WRITE_ZEROES: */
	__REQ_NOUNMAP,		/* do not free blocks when zeroing */

	__REQ_HIPRI,

	/* for driver use */
	__REQ_DRV,
	__REQ_SWAP,		/* swapping request. */
	__REQ_NR_BITS,		/* stops here */
};

#define REQ_FAILFAST_DEV	(1ULL << __REQ_FAILFAST_DEV)
#define REQ_FAILFAST_TRANSPORT	(1ULL << __REQ_FAILFAST_TRANSPORT)
#define REQ_FAILFAST_DRIVER	(1ULL << __REQ_FAILFAST_DRIVER)
#define REQ_SYNC		(1ULL << __REQ_SYNC)
#define REQ_META		(1ULL << __REQ_META)
#define REQ_PRIO		(1ULL << __REQ_PRIO)
#define REQ_NOMERGE		(1ULL << __REQ_NOMERGE)
#define REQ_IDLE		(1ULL << __REQ_IDLE)
#define REQ_INTEGRITY		(1ULL << __REQ_INTEGRITY)
#define REQ_FUA			(1ULL << __REQ_FUA)
#define REQ_PREFLUSH		(1ULL << __REQ_PREFLUSH)
#define REQ_RAHEAD		(1ULL << __REQ_RAHEAD)
#define REQ_BACKGROUND		(1ULL << __REQ_BACKGROUND)
#define REQ_NOWAIT		(1ULL << __REQ_NOWAIT)
#define REQ_NOWAIT_INLINE	(1ULL << __REQ_NOWAIT_INLINE)
#define REQ_CGROUP_PUNT		(1ULL << __REQ_CGROUP_PUNT)

#define REQ_NOUNMAP		(1ULL << __REQ_NOUNMAP)
#define REQ_HIPRI		(1ULL << __REQ_HIPRI)

#define REQ_DRV			(1ULL << __REQ_DRV)
#define REQ_SWAP		(1ULL << __REQ_SWAP)

enum req_opf {
	/* read sectors from the device */
	REQ_OP_READ		= 0,
	/* write sectors to the device */
	REQ_OP_WRITE		= 1,
	/* flush the volatile write cache */
	REQ_OP_FLUSH		= 2,
	/* discard sectors */
	REQ_OP_DISCARD		= 3,
	/* securely erase sectors */
	REQ_OP_SECURE_ERASE	= 5,
	/* reset a zone write pointer */
	REQ_OP_ZONE_RESET	= 6,
	/* write the same sector many times */
	REQ_OP_WRITE_SAME	= 7,
	/* reset all the zone present on the device */
	REQ_OP_ZONE_RESET_ALL	= 8,
	/* write the zero filled sector many times */
	REQ_OP_WRITE_ZEROES	= 9,
	/* Open a zone */
	REQ_OP_ZONE_OPEN	= 10,
	/* Close a zone */
	REQ_OP_ZONE_CLOSE	= 11,
	/* Transition a zone to full */
	REQ_OP_ZONE_FINISH	= 12,

	/* SCSI passthrough using struct scsi_request */
	REQ_OP_SCSI_IN		= 32,
	REQ_OP_SCSI_OUT		= 33,
	/* Driver private requests */
	REQ_OP_DRV_IN		= 34,
	REQ_OP_DRV_OUT		= 35,

	REQ_OP_LAST,
};

#include <linux/bio.h>

#endif

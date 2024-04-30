#ifndef BLKDEV_H
#define BLKDEV_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/blk_types.h>
#include <linux/rcupdate.h>
#include <linux/completion.h>
#include <linux/rwsem.h>
#include <linux/kobject.h>
#include <linux/part_stat.h>
#include <linux/module.h>
#include <linux/genhd.h>

#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT 9
#endif
#ifndef SECTOR_SIZE
#define SECTOR_SIZE (1 << SECTOR_SHIFT)
#endif

#define BDEVNAME_SIZE	32	/* Largest string for a blockdev identifier */

#define bio_op(bio) \
	((bio)->bi_opf & REQ_OP_MASK)

typedef int (congested_fn)(void *, int);

struct backing_dev_info {
	ULONG_PTR ra_pages; /* max readahead in PAGE_CACHE_SIZE units */
	ULONG_PTR state;	/* Always use atomic bitops on this */
	congested_fn *congested_fn; /* Function pointer if device is md/dm */
	void *congested_data;   /* Pointer to aux data for congested func */
};

struct queue_limits {
	unsigned int		max_hw_sectors;
	unsigned int            max_discard_sectors;
	unsigned int            max_write_same_sectors;
	unsigned int		max_write_zeroes_sectors;
	unsigned int            discard_granularity;
	unsigned int		discard_zeroes_data;
	unsigned int		seg_boundary_mask;
	unsigned int		physical_block_size;
	unsigned int		logical_block_size;
	unsigned int		alignment_offset;
	unsigned int		io_min;
	unsigned int		io_opt;
};

struct request_queue {
	void * queuedata;
	struct backing_dev_info *backing_dev_info;
	spinlock_t *queue_lock;
	unsigned short logical_block_size;
	ULONG_PTR queue_flags;
	struct queue_limits limits; 
};

/* obsolete, don't use in new code */
static inline void bio_set_op_attrs(struct bio *bio, unsigned op,
		unsigned op_flags)
{
	bio->bi_opf = op | op_flags;
}

static inline bool op_is_write(unsigned int op)
{
	return (op & 1);
}

#define bio_data_dir(bio) \
	(op_is_write(bio_op(bio)) ? WRITE : READ)

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

static inline void blk_queue_flag_set(unsigned int flag, struct request_queue *q)
{
	set_bit(flag, &q->queue_flags);
}

static inline void blk_queue_flag_clear(unsigned int flag, struct request_queue *q)
{
	clear_bit(flag, &q->queue_flags);
}

static inline void blk_queue_max_write_same_sectors(struct request_queue *q,
				      unsigned int max_write_same_sectors)
{
	if (max_write_same_sectors > 0)
		printk("Warning: attempt to set max_write_same_sectors > 0 (%d)\n", max_write_same_sectors);
	
		/* We force it to 0, since write same is not supported. */
	q->limits.max_write_same_sectors = 0;
}

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

/*
 * blk_plug permits building a queue of related requests by holding the I/O
 * fragments for a short period. This allows merging of sequential requests
 * into single larger request. As the requests are moved from a per-task list to
 * the device's request_queue in a batch, this results in improved scalability
 * as the lock contention for request_queue lock is reduced.
 *
 * It is ok not to disable preemption when adding the request to the plug list
 * or when attempting a merge, because blk_schedule_flush_list() will only flush
 * the plug list when the task sleeps by itself. For details, please see
 * schedule() where blk_schedule_flush_plug() is called.
 */
struct blk_plug {
	ULONG_PTR magic; /* detect uninitialized use-cases */
	struct list_head list; /* requests */
	struct list_head mq_list; /* blk-mq requests */
	struct list_head cb_list; /* md requires an unplug callback */
};

struct blk_plug_cb;
typedef void (*blk_plug_cb_fn)(struct blk_plug_cb *, bool);
struct blk_plug_cb {
	struct list_head list;
	blk_plug_cb_fn callback;
	void *data;
};

extern struct blk_plug_cb *blk_check_plugged(blk_plug_cb_fn unplug, void *data, int size);

#include <linux/bio.h>

struct windows_block_device {
	struct _DEVICE_OBJECT DeviceObject;
};

struct fault_injection {
	int nr_requests_to_failure;
	int nr_requests;
};

struct inode;

/* TODO: this is used as device extension for the DRBD devices and
   also as block device for the backing devices. This is probably
   not a good idea.
 */

struct block_device {
	// If the block device descriptor refers to a disk partition,
	// the bd_contains field points to the descriptor of the
	// block device associated with the whole disk
	// Otherwise, if the block device descriptor refers to a whole disk
	// the bd_contains field points to the block device descriptor itself ...
	// FROM Understanding the Linux Kernel, 3rd Edition
	struct block_device *	bd_parent;			// DW-1109: it points the block device whose bd_contains points me.
	struct block_device *	bd_contains;
	struct gendisk * bd_disk;
	struct request_queue *	bd_queue;	/* TODO: initialize that !! */
	unsigned int bd_block_size;	/* Size of one sector (?) */
	unsigned long long d_size;
	struct kref kref;

	struct inode *bd_inode;

	struct disk_stats bd_stats;

	int minor;	/* in case drbd_device is still NULL we need to shadow it here */
	struct drbd_device *drbd_device;
	struct _DEVICE_OBJECT *windows_device;	/* If that is a backing dev, the target device to send the I/O IRPs to. If this is a DRBD device, the device created by bdget()) */

		/* TODO: those two will go away again */
	struct _DEVICE_OBJECT *upper_windows_device; /* If upper device, this is the device created in AddDevice of the PnP request. */
	struct _DEVICE_OBJECT *attached_windows_device; /* If upper device, this is the device returned by IoAttachDeviceToDeviceStack in AddDevice of the PnP request. */
	struct _FILE_OBJECT *file_object; /* As returned by IoGetDeviceObjectPointer() */
	UNICODE_STRING path_to_device;
	UNICODE_STRING mount_point;
	bool is_mounted;
	bool is_bootdevice;
		/* TODO: test this should go away */
	bool my_auto_promote;
		/* Only for lower device. For upper device, see
		 * w_remove_lock in block_device_reference (windows
		 * device struct).
		 */

	IO_REMOVE_LOCK remove_lock;
	struct block_device_reference *ref;

	struct list_head backing_devices_list;
	bool mechanically_locked; /* MEDIA_REMOVAL ioctl */
	void *pnp_notification_entry;

		/* Those are used by windrbd_get_volsize() internally */
	struct _IO_STATUS_BLOCK vol_size_io_status;
	struct _GET_LENGTH_INFORMATION vol_size_length_information;
	struct mutex vol_size_mutex;

	/* Fault injection
	 *
         * Set this to approx. 1000 to fail on meta data. Set this to
         * 10000 to fail on Sync. Set this to 100000 (and do I/O) to
         * fail on user space I/O request.
         */

	struct fault_injection inject_on_completion;
	struct fault_injection inject_on_request;

	/* Flags controlling end of this bdev: */
	bool powering_down;	/* Regular windows shutdown, cancel all waiters */
	bool delete_pending;	/* bdput called. waiting for REMOVE_DEVICE PnP IRP */
	bool about_to_delete;	/* REMOVE_DEVICE, no more I/O */
	bool ejected;		/* EJECTED event, no more I/O TODO: ?? */

	struct _KEVENT primary_event;	/* Set whenever Primary */
	struct _KEVENT capacity_event;	/* Set whenever size > 0 */
	struct _KEVENT device_removed_event;	/* Set by REMOVE_DEVICE to signal bdput we're gone */
	struct _KEVENT device_started_event; /* Set on receving IRP_MN_START_DEVICE PnP request (drbdadm primary waits for this) */
	struct _KEVENT device_ejected_event; /* Set on receving IRP_MN_EJECT_DEVICE PnP request (drbdadm secondary waits for this) */
	struct _KEVENT bus_device_iterated; /* Set on bus device receving IRP_QUERY_DEVICE_RELATIONS PnP request for a to be deleted blockdev (drbdadm secondary waits for this) */
	struct _KEVENT io_not_suspended; /* Cleared by windrbd suspend_io (so that I/O is suspended). Needed to suspend I/O from outside DRBD in order to fix the busy resync bug (sync does not finished on ongoing application I/O) */
	spinlock_t suspend_lock; /* Protecting toggeling of io_not_suspended */

	/* Used for debugging handle leaks */
	int num_openers;

	/* Nonzero when this is a DISK device (with partitions on it) */
	bool is_disk_device;

	/* For HLK test. */
	bool suprise_removal;

	/* This spinlock ensures that IoCompleteRequest (see bio_finished)
	 * is called sequentially.
	 */
	spinlock_t complete_request_spinlock;

	/* Workqueues for I/O. I/O sometimes happens in DPC (something
	 * like a bottom half) and must not sleep (else BSOD). Call
	 * drbd_make_request in this workqueue instead.
	 */

	struct workqueue_struct *io_workqueue;

	/* Wait queue for waiting for all bios completed. This solves
	 * a BSOD on disconnect while sync. To be called at the 
	 * beginning of conn_disconnect() (see drbd_receiver.c).
	 */

	struct wait_queue_head bios_event;

	/* Num pending counts. Must be 0 when disconnecting.
	 */

	atomic_t num_bios_pending;
	atomic_t num_irps_pending;

	/* The simple write cache: list of pending bios */
	struct list_head write_cache;
	spinlock_t write_cache_lock;
	struct task_struct *bdflush_thread;
	int bdflush_should_run;

	struct wait_queue_head bdflush_event;
	struct completion bdflush_terminated;

	struct kobject kobj;
	bool is_backing_device;

		/* These are parameters for faking a GPT table at
		 * the beginning and the end. Usually these should
		 * be zero but will be 34 for GPT fake. The pointers
		 * contain GPT data for before and after.
		 */
	sector_t data_shift, appended_sectors;
	char *disk_prolog, *disk_epilog;

	bool has_guids;
	char disk_guid[16];
	char partition_guid[16];

		/* Cache the boot sector. If size changed we cannot
		 * re read the boot sector from DRBD since it suspends
		 * I/O during size change. So cache it here. */
	bool have_read_bootsector;
	char boot_sector[512];

	spinlock_t virtual_partition_table_lock;

		/* This members allow I/O to be "corked": collect
		 * I/O requests (=bios) and submit them as a single
		 * driver call to the backing device. This should
		 * perform better (1 4Meg request vs. 1000 4K requests)
		 * Right now one needs to call bdev_cork_io() and
		 * bdev_uncork_io() manually.
		 */

	bool corked;
	spinlock_t cork_spinlock;
	struct list_head corked_list;

	spinlock_t in_flight_bios_lock;
	struct list_head in_flight_bios;
};

	/* Starting with version 0.7.1, this is the device extension
	 * of the windows device object (for the upper device). This
	 * is because the struct block_device lives longer than the
	 * windows device now (windows device only exists as long
	 * as we are primary, to avoid caching side effects).
	 */

#define BLOCK_DEVICE_UPPER_MAGIC 0xa56e3bd1
#define BLOCK_DEVICE_ATTACHED_MAGIC 0x706fde13

struct block_device_reference {
	int magic;
	struct block_device *bdev;
		/* For upper device this must only live as long as
		 * the windows device lives. Else driver verifier
		 * will complain when doing primary / secondary /primary.
		 */
	IO_REMOVE_LOCK w_remove_lock;
};

struct block_device_operations {
	struct module *owner;
	blk_qc_t (*submit_bio) (struct bio*);
	int (*open) (struct block_device *, fmode_t);
	void (*release) (struct gendisk *, fmode_t);
};

#define QUEUE_FLAG_STABLE_WRITES 15	/* don't modify blks until WB is done */
#define QUEUE_FLAG_DISCARD	8	/* supports DISCARD */

#define blk_queue_discard(q)	test_bit(QUEUE_FLAG_DISCARD, &(q)->queue_flags)

/* TODO: hardcoding this here .. we do not have sysfs (yet) */
static inline int queue_discard_zeroes_data(const struct request_queue *unused)
{
	return 1;
}

#define disk_to_dev(disk) \
	(disk)->part0

/**
 * bio_start_io_acct - start I/O accounting for bio based drivers
 * @bio:	bio to start account for
 *
 * Returns the start time that should be passed back to bio_end_io_acct().
 * TODO: not implemented.
 */
static inline ULONG_PTR bio_start_io_acct(struct bio *bio)
{
	return 0;
}

/**
 * bio_end_io_acct - end I/O accounting for bio based drivers
 * @bio:	bio to end account for
 * @start:	start time returned by bio_start_io_acct()
 * TODO: not implemented.
 */
static inline void bio_end_io_acct(struct bio *bio, ULONG_PTR start_time)
{
}

/* TODO: this function does not exist any more (kernel 6.8) */
extern int generic_make_request(struct bio *bio);

static inline int submit_bio(struct bio *bio)
{
	return generic_make_request(bio);
}

static inline int submit_bio_noacct(struct bio *bio)
{
	return generic_make_request(bio);
}

static inline unsigned int queue_physical_block_size(const struct request_queue *q)
{
	/* TODO: initialize that: */
	return q->limits.physical_block_size;
}

static inline unsigned queue_logical_block_size(const struct request_queue *q)
{
	int retval = 512;

	if (q && q->limits.logical_block_size)
		retval = q->limits.logical_block_size;

	return retval;
}

static inline int queue_alignment_offset(const struct request_queue *q)
{
	return q->limits.alignment_offset;
}

static inline unsigned int queue_io_min(const struct request_queue *q)
{
	return q->limits.io_min;
}

static inline unsigned int queue_io_opt(const struct request_queue *q)
{
	return q->limits.io_opt;
}

extern sector_t get_capacity(struct gendisk *disk);

static inline struct request_queue *bdev_get_queue(struct block_device *bdev)
{
	if (bdev && bdev->bd_disk)
		return bdev->bd_disk->queue;

	return NULL;
}

static inline unsigned int queue_max_hw_sectors(const struct request_queue *q)
{
	return q->limits.max_hw_sectors;
}

	/* There are no read only backing devices */
static inline int bdev_read_only(struct block_device *bdev)
{
	return 0;
}

	/* TODO: stub, implement me? */
static inline void blk_queue_write_cache(struct request_queue *q, bool enabled, bool fua)
{
}

extern struct request_queue *bdev_get_queue(struct block_device *bdev);
extern void blk_cleanup_queue(struct request_queue *q);
extern struct request_queue *blk_alloc_queue(int unused);
typedef void (make_request_fn) (struct request_queue *q, struct bio *bio);
extern void blk_queue_make_request(struct request_queue *q, make_request_fn *mfn);
extern void blk_queue_flush(struct request_queue *q, unsigned int flush);

extern int register_blkdev(unsigned int major, const char *name);
extern void unregister_blkdev(unsigned int major, const char *name);

extern int add_disk(struct gendisk *disk);

typedef u8 blk_status_t;
#define BLK_STS_OK 0
#define BLK_STS_NOTSUPP         ((blk_status_t)1)
#define BLK_STS_MEDIUM          ((blk_status_t)7)
#define BLK_STS_RESOURCE        ((blk_status_t)9)
#define BLK_STS_IOERR           ((blk_status_t)10)

static inline int blk_status_to_errno(blk_status_t status)
{
        return  status == BLK_STS_OK ? 0 :
                status == BLK_STS_RESOURCE ? -ENOMEM :
                status == BLK_STS_NOTSUPP ? -EOPNOTSUPP :
                -EIO;
}

static inline blk_status_t errno_to_blk_status(int err)
{
        blk_status_t status =
                err == 0 ? BLK_STS_OK :
                err == -ENOMEM ? BLK_STS_RESOURCE :
                err == -EOPNOTSUPP ? BLK_STS_NOTSUPP :
                BLK_STS_IOERR;

        return status;
}

/* TODO: one day we might implement those: (actually it is already
 * implemented but with a different interface).
 */

#define blk_start_plug(plug)	(void)(plug)
#define blk_finish_plug(plug)   (void)(plug)

/* TODO: 0? really? */
static inline int bdev_discard_alignment(struct block_device *bdev)
{
        return 0;
}

extern const char *bdevname(struct block_device *bdev, char *buffer);

#define blk_queue_split(bio) do { } while (0)

bool set_capacity_and_notify(struct gendisk *disk, sector_t size);

	/* TODO: implement those: */
extern void blk_queue_max_discard_sectors(struct request_queue *q,
		unsigned int max_discard_sectors);
extern void blk_queue_logical_block_size(struct request_queue *, unsigned int);
extern void blk_set_stacking_limits(struct queue_limits *lim);
extern void blk_queue_max_hw_sectors(struct request_queue *, unsigned int);
extern void blk_queue_segment_boundary(struct request_queue *, ULONG_PTR);
extern int blk_stack_limits(struct queue_limits *t, struct queue_limits *b,
			    sector_t offset);
void blk_queue_update_readahead(struct request_queue *q);
void blkdev_put(struct block_device *bdev, fmode_t mode);

	/* This opens a backing device: */
extern struct block_device *blkdev_get_by_path(const char *path, fmode_t mode, void *holder);

#endif

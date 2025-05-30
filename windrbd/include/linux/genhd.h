#ifndef __LINUX_GENDISK_H
#define __LINUX_GENDISK_H

#define DISK_NAME_LEN		16

struct block_device_operations;
struct request_queue;
struct block_device;

struct gendisk {
	char disk_name[DISK_NAME_LEN];  /* name of major driver */
	struct request_queue *queue;
	int major, first_minor;
	int minors;
	const struct block_device_operations *fops;
	void *private_data;
	struct block_device *part0;
	int flags;
};


extern struct gendisk *alloc_disk(int minors);
extern void put_disk(struct gendisk *disk);
extern void del_gendisk(struct gendisk *disk);
extern void set_disk_ro(struct gendisk *disk, int flag);

struct queue_limits;

#ifndef DRBD_9_0
extern struct gendisk *blk_alloc_disk(struct queue_limits *limits_unused, int unused);
#else
extern struct gendisk *blk_alloc_disk(int unused);
#endif
extern void blk_cleanup_disk(struct gendisk *disk);

extern struct block_device *bdget_disk(struct gendisk *disk, int partno);
extern int fsync_bdev(struct block_device *bdev);

/**
 * DOC: genhd capability flags
 *
 * ``GENHD_FL_REMOVABLE``: indicates that the block device gives access to
 * removable media.  When set, the device remains present even when media is not
 * inserted.  Shall not be set for devices which are removed entirely when the
 * media is removed.
 *
 * ``GENHD_FL_HIDDEN``: the block device is hidden; it doesn't produce events,
 * doesn't appear in sysfs, and can't be opened from userspace or using
 * blkdev_get*. Used for the underlying components of multipath devices.
 *
 * ``GENHD_FL_NO_PART``: partition support is disabled.  The kernel will not
 * scan for partitions from add_disk, and users can't add partitions manually.
 *
 */
enum {
	GENHD_FL_REMOVABLE			= 1 << 0,
	GENHD_FL_HIDDEN				= 1 << 1,
	GENHD_FL_NO_PART			= 1 << 2,
};

#endif

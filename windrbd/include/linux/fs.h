#ifndef _FS_H
#define _FS_H

#include <linux/blkdev.h>

	/* TODO: Very basic for now: */

struct file {
	struct kref kref;
	struct block_device *bdev;
};

void fput(struct file *file);

/* file is open for reading */
#define FMODE_READ				    0x1
/* file is open for writing */
#define FMODE_WRITE				    0x2
/* File is opened with O_NDELAY (only set for block devices) */
#define FMODE_NDELAY				    0x40

struct gendisk;

	/* TODO: implement */
static inline int bd_link_disk_holder(struct block_device *bdev,
				      struct gendisk *disk)
{
	return 0;
}
static inline void bd_unlink_disk_holder(struct block_device *bdev,
					 struct gendisk *disk)
{
}

struct inode {
	loff_t i_size;
};

static inline loff_t i_size_read(const struct inode *inode)
{
	return inode->i_size;
}

/* TODO: implement those: */
extern struct block_device *bdgrab(struct block_device *bdev);
extern void bdput(struct block_device *);
extern int fsync_bdev(struct block_device *);

static inline struct block_device *file_bdev(struct file *bdev_file)
{
	if (bdev_file == NULL)
		return NULL;

	return bdev_file->bdev;
}

#endif


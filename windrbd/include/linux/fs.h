#ifndef _FS_H
#define _FS_H

#include <linux/blkdev.h>

/* file is open for reading */
#define FMODE_READ				    0x1
/* file is open for writing */
#define FMODE_WRITE				    0x2
/* File is opened with O_NDELAY (only set for block devices) */
#define FMODE_NDELAY				    0x40

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

#endif


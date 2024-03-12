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
};


extern struct gendisk *alloc_disk(int minors);
extern void put_disk(struct gendisk *disk);
extern void del_gendisk(struct gendisk *disk);
extern void set_disk_ro(struct gendisk *disk, int flag);

extern struct gendisk *blk_alloc_disk(int unused);
extern void blk_cleanup_disk(struct gendisk *disk);

extern struct block_device *bdget_disk(struct gendisk *disk, int partno);
extern int fsync_bdev(struct block_device *bdev);

#endif

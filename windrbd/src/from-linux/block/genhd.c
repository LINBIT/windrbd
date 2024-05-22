#include <linux/blkdev.h>
#include <linux/sprintf.h>

const char *bdevname(struct block_device *bdev, char *buf)
{
	struct gendisk *hd = bdev->bd_disk;
	int partno = bdev->bd_partno;

	if (!partno)
		snprintf(buf, BDEVNAME_SIZE, "%s", hd->disk_name);
	else if (isdigit(hd->disk_name[strlen(hd->disk_name)-1]))
		snprintf(buf, BDEVNAME_SIZE, "%sp%d", hd->disk_name, partno);
	else
		snprintf(buf, BDEVNAME_SIZE, "%s%d", hd->disk_name, partno);

	return buf;
}

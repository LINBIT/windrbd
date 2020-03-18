#ifndef BLKDEV_H
#define BLKDEV_H

#include <linux/bio.h>
#include <linux/timer.h>

/* originally in linux/blk_types.h */
typedef unsigned int blk_qc_t;

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

#endif

#ifndef BLK_TYPES_H
#define BLK_TYPES_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/bvec.h>
#include <linux/mutex.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>

typedef u8 blk_status_t;

	/* When we create more bio's upon request for a single MDL,
	 * this is common data shared between all that bios.
	 */

struct windrbd_bio_collection {
	atomic_t bc_num_completed;
	size_t bc_total_size;
	int bc_num_requests;

	int bc_device_failed;
	spinlock_t bc_device_failed_lock;

};

typedef __u32 blk_opf_t;

#define BI_WINDRBD_FLAG_BOOTSECTOR_PATCHED 0

struct bio {
	struct _IRP **bi_irps;	   /* Used for accessing the backing device */
	struct _IRP *bi_upper_irp; /* Used for the DRBD device */

	struct _KEVENT *bi_io_finished_event;	/* For loopback I/O (WinDRBD calling itself via DRBD engine) */
	struct bio*				bi_next;	/* request queue link */
	struct block_device*	bi_bdev;
	ULONG_PTR			bi_flags;	/* status, command, etc */
	unsigned int			bi_opf;		/* bottom bits req flags, top bits REQ_OP. Use accessors. */
	unsigned short			bi_vcnt;	/* how many bio_vec's */
	atomic_t				bi_cnt;		/* pin count */
	/* bi_end_io is assigned in next comment places.
	Blkdev_issue_zeroout.c (drbd\drbd-kernel-compat):		bio->bi_end_io = bio_batch_end_io;
	Drbd_actlog.c (drbd):	bio->bi_end_io = drbd_md_endio;
	Drbd_bitmap.c (drbd):	bio->bi_end_io = drbd_bm_endio;
	Drbd_receiver.c (drbd):	bio->bi_end_io = one_flush_endio;
	Drbd_receiver.c (drbd):	bio->bi_end_io = drbd_peer_request_endio;
	Drbd_req.h (drbd):	bio->bi_end_io   = drbd_request_endio;
	*/
	void 			(*bi_end_io) (struct bio*);
	void*			bi_private;
	unsigned int		bi_max_vecs;    /* max bvl_vecs we can hold */
	struct bvec_iter	bi_iter;

		/* Windows backing device driver cannot handle more than
		 * 1 (!) vector element. Split the IoCalldriver calls into
		 * subrequests.
		 */

	int bi_num_requests;	/* Includes maybe a flush request */
	int bi_this_request;
	atomic_t bi_requests_completed;
	struct windrbd_bio_collection *bi_common_data;

	int device_failed;
	spinlock_t device_failed_lock;

	void *bi_upper_irp_buffer;

	void *patched_bootsector_buffer;

	/* Squash multiple requests described by the bio vec
	 * into one call to the underlying disk driver.
	 * Unfortunately memory has to be copiied but
	 * I assume it is still faster than calling the
	 * disk driver for every 4K chunk.
	 */

	void *bi_big_buffer;
	unsigned int bi_big_buffer_size;
	bool bi_using_big_buffer;

	/* If set, indicates that the memory is paged, in which case
	 * we must lock it to memory. If not set, must unlock memory
	 * locked by IoBuildAsynchronousFsdRequest().
	 */
	bool bi_paged_memory;

	/* If set do not modify boot sector file system signature
	 * on I/O. Currently only used by check for file system
	 * on backing device on attach.
	 */
	bool dont_patch_boot_sector;

	/* Bit 0: Set by read completion routine to avoid calling
	 * patch_boot_sector multiple times.
	 */
	ULONG_PTR bi_windrbd_flags;

	/* For bio's created by windrbd device ("upper") layer, this
	 * indicates where in the user space MDL the bio starts.
	 * We need it because Linux bios must not be larger than
	 * 1 megabyte, while MDLs may be larger than that. If they
	 * are we split the request in separate calls to
	 * drbd_make_request() (with separate bio's each).
	 */
	size_t bi_mdl_offset;

	/* Used by flush_request (which is currently not enabled).
	 */
	IO_STATUS_BLOCK io_stat;

	blk_status_t bi_status;

	/* We have to free the bio when IRQL is PASSIVE, so we
	 * put them on this list in the IRQ and free it later
	 * from a thread.
	 */
	struct list_head to_be_freed_list;
	struct list_head to_be_freed_list2;

		/* This indicates that the free_mdls_and_irp thread
		 * should complete the upper IRP. It should do so
		 * once the references to the buffers are cleaned
		 * up (no mapping / no locking).
		 */
	bool delayed_io_completion;

#ifdef BIO_ALLOC_DEBUG
	char *file;
	int line;
	char *func;
#endif

	struct bio *is_cloned_from;

	struct list_head corked_bios;  /* used to link the bios */
	struct list_head joined_bios;  /* a list containg bios which we do the big buffer for. Must end_io them once this joined bio is finished */

	/* Set when a bio is created in windrbd_make_drbd_requests.
	   Do not try to join them */
	bool is_user_request;

	/* bios are put on this list once submitted to the underlying
	 * disk driver and removed when bi_endio is called. This allows
	 * us to avoid calling bi_endio twice. It is useful for failing
	 * in-flight bios when a disk timeout happens (the disk still
	 * may call the WinDRBD completion handler after that timeout
	 * which should not call bi_endio again).
	 */
	struct list_head locally_submitted_bios;
	struct list_head locally_submitted_bios2;

	/* Set when there is a disk timeout. We fail the bio in the
	 * disk timeout handler and must not fail it again (bi_endio
	 * should be called only once.
	 */
	spinlock_t already_failed_lock;
	bool already_failed;

	char *where_i_am;	/* checkpoints for debugging backing dev timeout. */

	/* TODO: may be put members here again? Update: Not sure,
	 * we've put a KEVENT here and it didn't work .. might also
	 * have been something else.
	 */

	struct bio_vec bi_io_vec[1];
};

enum req_op {
	/* read sectors from the device */
	REQ_OP_READ		= (__force blk_opf_t)0,
	/* write sectors to the device */
	REQ_OP_WRITE		= (__force blk_opf_t)1,
	/* flush the volatile write cache */
	REQ_OP_FLUSH		= (__force blk_opf_t)2,
	/* discard sectors */
	REQ_OP_DISCARD		= (__force blk_opf_t)3,
	/* securely erase sectors */
	REQ_OP_SECURE_ERASE	= (__force blk_opf_t)5,
	/* write data at the current zone write pointer */
	REQ_OP_ZONE_APPEND	= (__force blk_opf_t)7,
	/* write the zero filled sector many times */
	REQ_OP_WRITE_ZEROES	= (__force blk_opf_t)9,
	/* Open a zone */
	REQ_OP_ZONE_OPEN	= (__force blk_opf_t)10,
	/* Close a zone */
	REQ_OP_ZONE_CLOSE	= (__force blk_opf_t)11,
	/* Transition a zone to full */
	REQ_OP_ZONE_FINISH	= (__force blk_opf_t)12,
	/* reset a zone write pointer */
	REQ_OP_ZONE_RESET	= (__force blk_opf_t)13,
	/* reset all the zone present on the device */
	REQ_OP_ZONE_RESET_ALL	= (__force blk_opf_t)15,

	/* TODO: this exists in DRBD 9.0 but not in DRBD 9.1: */
	REQ_OP_WRITE_SAME	= 7,

	/* Driver private requests */
	REQ_OP_DRV_IN		= (__force blk_opf_t)34,
	REQ_OP_DRV_OUT		= (__force blk_opf_t)35,

	REQ_OP_LAST		= (__force blk_opf_t)36,
};
#endif

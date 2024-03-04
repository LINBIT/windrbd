#ifndef BLK_TYPES_H
#define BLK_TYPES_H

#include <linux/types.h>
#include <linux/bvec.h>

typedef u8 blk_status_t;

#define BI_WINDRBD_FLAG_BOOTSECTOR_PATCHED 0

struct bio {
	struct _IRP **bi_irps;	   /* Used for accessing the backing device */
	struct _IRP *bi_upper_irp; /* Used for the DRBD device */

	struct _KEVENT *bi_io_finished_event;	/* For loopback I/O (WinDRBD calling itself via DRBD engine) */
	struct bio*				bi_next;	/* request queue link */
	struct block_device*	bi_bdev;
	unsigned long			bi_flags;	/* status, command, etc */
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
	struct bio_collection *bi_common_data;

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

	/* TODO: may be put members here again? Update: Not sure,
	 * we've put a KEVENT here and it didn't work .. might also
	 * have been something else.
	 */

	struct bio_vec bi_io_vec[1];
};

#endif

#ifndef __BACKING_DEV_H__
#define __BACKING_DEV_H__

/*
 * Bits in backing_dev_info.state
 */
enum bdi_state {
	BDI_pending,		/* On its way to being activated */
	BDI_wb_alloc,		/* Default embedded wb allocated */
	BDI_async_congested,	/* The async (write) queue is getting full */
	BDI_sync_congested,	/* The sync queue is getting full */
	BDI_registered,		/* bdi_register() was done */
	BDI_unused,		/* Available bits start here */
};



#endif
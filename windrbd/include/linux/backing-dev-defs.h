#ifndef _LINUX_BACKING_DEV_DEFS
#define _LINUX_BACKING_DEV_DEFS

enum wb_congested_state {
	WB_async_congested,	/* The async (write) queue is getting full */
	WB_sync_congested,	/* The sync queue is getting full */
};

#endif

#ifndef MM_TYPES_H
#define MM_TYPES_H

#include <linux/list.h>
#include <linux/kref.h>
#include <linux/types.h>

	/* A 'page' in WinDRBD may actually contain more pages (vmalloc'ed)
	 * We need this to optimize I/O requests larger than 4K which
	 * we used to send by seperate requests to the backing devices
	 * (which is just too slow). A struct page may now contain
	 * memory of any length, therefore we don't need the splitting
	 * mechanism any more for userspace I/O requests (we still need
	 * it, however for the metadata).
	 */

struct page {
	ULONG_PTR private;
	void *addr;
	struct list_head lru;
	struct kref kref;
	size_t size;
	int is_unmapped;
	int is_system_buffer;	/* do not kfree(page->addr) but kfree(page) */
};

#endif

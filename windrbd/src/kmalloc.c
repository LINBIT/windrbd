#include <linux/printk.h>
#include <linux/kref.h>
#include <linux/delay.h>

#include <windrbd_internal.h>

static int kmalloc_errors;

void *kmalloc(size_t size, gfp_t flag)
{
	int retries;
	void *mem;

	retries = 0;
	while (1) {
		mem = ExAllocatePoolWithTag(WinDRBDNonPagedPool, size, DRBD_TAG);

		if (mem != NULL)
			return mem;

		if (!(flag & __GFP_DIRECT_RECLAIM)) {
			kmalloc_errors++;
			return NULL;
		}

                if (KeGetCurrentIrql() == PASSIVE_LEVEL)
                        msleep(100);

                retries++;
	}
	return mem;
}

void *kzalloc(size_t size, gfp_t flag)
{
	void *data;

	data = kmalloc(size, flag);
	if (data != NULL)
		memset(data, 0, size);

	return data;
}

void *kcalloc(size_t size, int count, gfp_t flag)
{
	return kzalloc(size*count, flag);
}

void *__vmalloc(size_t size, gfp_t flag)
{
	return kmalloc(size, flag);
}

void kfree(const void *data)
{
	if (data != NULL)
		ExFreePoolWithTag((void*) data, DRBD_TAG);
}

void kvfree(const void *data)
{
	kfree(data);
}

struct page *alloc_page(gfp_t flag)
{
	struct page *p = kzalloc(sizeof(struct page), flag);
	if (p == NULL)
		return NULL;

		/* Under Windows this is defined to align to a page
		 * of PAGE_SIZE bytes if size is >= PAGE_SIZE.
		 * PAGE_SIZE itself is always 4096 under Windows.
		 */

	p->addr = kmalloc(PAGE_SIZE, flag);
	if (!p->addr){
		kfree(p);
		return NULL;
	}
	kref_init(&p->kref);

	return p;
}

void __free_page(struct page *page)
{
	if (!page->is_system_buffer)
		kfree(page->addr);

	kfree(page);
}

void free_pages(ULONG_PTR addr, int order)
{
	kfree((void*) addr);
}

void free_page(ULONG_PTR addr)
{
	free_pages(addr, 0);
}

void free_page_kref(struct kref *kref)
{
	struct page *page = container_of(kref, struct page, kref);
	__free_page(page);
}

ULONG_PTR __get_free_pages(gfp_t flag, int order)
{
	if (order > 10) {
		printk("Warning: attempt to allocate 4096 * (2 ** %d) bytes\n", order);
		return 0;
	}
	return (ULONG_PTR) kmalloc(PAGE_SIZE * (1 << order), flag);
}

ULONG_PTR __get_free_page(gfp_t flag)
{
	return __get_free_pages(flag, 0);
}

/* These are intended to enable calling functions from within gdb */

void *malloc(size_t size)
{
	return kmalloc(size, GFP_KERNEL);
}

void free(void *p)
{
	return kfree(p);
}


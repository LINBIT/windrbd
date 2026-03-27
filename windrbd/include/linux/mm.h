#ifndef MM_H
#define MM_H

#include <linux/mm_types.h>
#include <linux/page_ref.h>
#include <linux/gfp.h>
#include <linux/printk.h>

struct kref;

#ifdef KMALLOC_DEBUG

	/* In WinDRBD free_page_kref might be a macro that
	 * calls free_page_kref_debug. Therefore a _ here.
	 */

extern void _free_page_kref(struct kref *kref);

static inline void put_page_debug(struct page *page, const char *file, int line)
{
	if (page->first_page)
		kref_put(&page->first_page->kref, _free_page_kref);
	else
		kref_put(&page->kref, _free_page_kref);
}

#define put_page(kref) put_page_debug(kref, __FILE__, __LINE__)

#else

extern void free_page_kref(struct kref *kref);

static inline void put_page(struct page *page)
{
	if (page->first_page)
		kref_put(&page->first_page->kref, free_page_kref);
	else
		kref_put(&page->kref, free_page_kref);
}


#endif

static inline void get_page(struct page *page)
{
	if (page->first_page)
		kref_get(&page->first_page->kref);
	else
		kref_get(&page->kref);
}

extern void *page_address(const struct page *page);

static inline unsigned int compound_order(const struct page *page)
{
	return page->order;
}

#endif

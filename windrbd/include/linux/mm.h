#ifndef MM_H
#define MM_H

#include <linux/mm_types.h>
#include <linux/page_ref.h>

extern void free_page_kref(struct kref *kref);

static inline void put_page(struct page *page)
{
	kref_put(&page->kref, free_page_kref);
}

static inline void get_page(struct page *page)
{
	kref_get(&page->kref);
}

extern void *page_address(const struct page *page);

#endif

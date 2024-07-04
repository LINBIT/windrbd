#ifndef __LINUX_HIGHMEM_H
#define __LINUX_HIGHMEM_H

#define kmap(_page)		(_page->addr)
#define kmap_atomic(_page)	(_page->addr)
#define kunmap(addr)		do { } while (0)
#define kunmap_atomic(addr)	do { } while (0)

struct page;

	/* Probably just does a memcpy() */
extern void copy_highpage(struct page *to, struct page *from);
extern void *kmap_local_page(struct page *page);

#define kunmap_local(__addr) do { } while (0)

#endif

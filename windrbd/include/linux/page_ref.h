#ifndef __LINUX_PAGE_REF_H
#define __LINUX_PAGE_REF_H

struct page;

extern int page_count(struct page *page);

#endif

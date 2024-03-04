#ifndef __GFP_H
#define __GFP_H

#include <linux/types.h>
#include <linux/kref.h>
#include <linux/gfp_types.h>

struct page *alloc_page_of_size_debug(int flag, size_t size, const char *file, int line, const char *func);
struct page *alloc_page_debug(int flag, const char *file, int line, const char *func);
void __free_page_debug(struct page *page, const char *file, int line, const char *func);
void free_page_kref_debug(struct kref *kref, const char *file, int line, const char *func);

#define alloc_page_of_size(flag, size) alloc_page_of_size_debug(flag, size, __FILE__, __LINE__, __func__)
#define alloc_page(flag) alloc_page_debug(flag,  __FILE__, __LINE__, __func__)
#define __free_page(page) __free_page_debug(page, __FILE__, __LINE__, __func__)
#define free_page_kref(kref) free_page_kref_debug(kref, __FILE__, __LINE__, __func__)

#endif

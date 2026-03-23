#ifndef __GFP_H
#define __GFP_H

#include <linux/types.h>
#include <linux/kref.h>
#include <linux/gfp_types.h>

#ifdef KMALLOC_DEBUG

struct page *alloc_page_debug(int flag, const char *file, int line, const char *func);
void __free_page_debug(struct page *page, const char *file, int line, const char *func);
void free_page_kref_debug(struct kref *kref, const char *file, int line, const char *func);
void free_pages_debug(ULONG_PTR addr, int order, const char *file, int line, const char *func);
void free_page_debug(ULONG_PTR addr, const char *file, int line, const char *func);
ULONG_PTR __get_free_pages_debug(gfp_t flag, int order, const char *file, int line, const char *func);
ULONG_PTR __get_free_page_debug(gfp_t flag, const char *file, int line, const char *func);

#define alloc_page(flag) alloc_page_debug(flag,  __FILE__, __LINE__, __func__)
#define __free_page(page) __free_page_debug(page, __FILE__, __LINE__, __func__)
#define free_page(addr) free_page_debug(addr, __FILE__, __LINE__, __func__)
#define free_pages(addr, order) free_pages_debug(addr, order, __FILE__, __LINE__, __func__)
#define __get_free_pages(addr, order) __get_free_pages_debug(addr, order, __FILE__, __LINE__, __func__)
#define __get_free_page(addr) __get_free_page_debug(addr, __FILE__, __LINE__, __func__)

#define free_page_kref(kref) free_page_kref_debug(kref, __FILE__, __LINE__, __func__)

#else

struct page *alloc_page(gfp_t flag);
void __free_page(struct page *page);
void free_pages(ULONG_PTR addr, int order);
void free_page(ULONG_PTR addr);
void free_page_kref(struct kref *kref);
ULONG_PTR __get_free_pages(gfp_t flag, int order);
ULONG_PTR __get_free_page(gfp_t flag);

#endif

/* Taken from linux-7.0-rc5 */
/* Helper macro to avoid gfp flags if they are the default one */
#define __default_gfp(a,b,...) b
#define default_gfp(...) __default_gfp(,##__VA_ARGS__,GFP_KERNEL)
/* End taken from linux-7.0-rc5 */

#endif

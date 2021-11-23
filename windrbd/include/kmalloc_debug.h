/* A simple kmalloc debugger.
 *
 * Features: memory leak detection (between first allocation and call
 * of shutdown_kmalloc_debug(). At shutdown, all memory is freed in order
 * to prevent BSOD's on driver unload.
 *
 * Simple out-of-range write access detection (with poison before and
 * poison after).
 *
 * Attempts to free the NULL pointer (while legal) are logged. Usually
 * this is a bug.
 *
 * Later: kmalloc() failure fault injection by source file/line.
 *
 * To enable this, include this file and compile and link with the 
 * kmalloc_debug.c file. Be sure to include this file in everywhere
 * (or nowhere) in your driver, else behaviour is undefined.
 */

void *kmalloc_debug(size_t size, int flag, const char *file, int line, const char *func);
void *kzalloc_debug(size_t size, int flag, const char *file, int line, const char *func);
void kfree_debug(const void *data, const char *file, int line, const char *func);

int dump_memory_allocations(int free_them);
int check_memory_allocations(const char *msg);
void init_kmalloc_debug(void);
void shutdown_kmalloc_debug(void);

/* TODO: tag will go away */
#define kmalloc(size, flags, tag) kmalloc_debug(size, flags, __FILE__, __LINE__, __func__)
#define kzalloc(size, flags, tag) kzalloc_debug(size, flags, __FILE__, __LINE__, __func__)
#define kcalloc(size, count, flags, tag) kzalloc_debug(size*count, flags, __FILE__, __LINE__, __func__)
#define kfree(data) kfree_debug(data, __FILE__, __LINE__, __func__)
	/* under Windows kfree and kvfree is the same */
#define kvfree(data) kfree_debug(data, __FILE__, __LINE__, __func__)

struct page *alloc_page_of_size_debug(int flag, size_t size, const char *file, int line, const char *func);
struct page *alloc_page_debug(int flag, const char *file, int line, const char *func);
void __free_page_debug(struct page *page, const char *file, int line, const char *func);
void free_page_kref_debug(struct kref *kref, const char *file, int line, const char *func);

#define alloc_page_of_size(flag, size) alloc_page_of_size_debug(flag, size, __FILE__, __LINE__, __func__)
#define alloc_page(flag) alloc_page_debug(flag,  __FILE__, __LINE__, __func__)
#define __free_page(page) __free_page_debug(page, __FILE__, __LINE__, __func__)
#define free_page_kref(kref) free_page_kref_debug(kref, __FILE__, __LINE__, __func__)


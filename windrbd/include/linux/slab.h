#ifndef SLAB_H
#define SLAB_H

#include <linux/types.h>	/* for size_t, ... */
#include <linux/gfp.h>		/* for GFP_xxx macros, ... */

#ifdef KMALLOC_DEBUG
#include "kmalloc_debug.h"

/* Comment that out for production releases */

#ifdef KMEM_CACHE_DEBUG

#define kmem_cache_alloc(cache, flag) \
	kzalloc(cache->element_size, flag, 'X123');

#define kmem_cache_free(cache, obj) \
	kfree(obj);

#endif

#else
/* TODO: flag probably gfp_t */
/* TODO: int? really? should be size_t */
/* TODO: remove Tag. */
extern void * kcalloc(int e_count, int x, int flag);
extern void * kzalloc(int x, int flag);
extern void * kmalloc(int size, int flag);
extern void kfree(const void * x);
extern void kvfree(const void * x);
extern int dump_memory_allocations(int free_them);
#endif

struct kmem_cache {
	NPAGED_LOOKASIDE_LIST l;
	size_t element_size;
};

typedef struct kmem_cache kmem_cache_t;

struct kmem_cache *kmem_cache_create(const char *name, size_t size, size_t align,
				     ULONG_PTR flags,
				     void (*ctor)(void *));
void kmem_cache_destroy(struct kmem_cache *cache);

unsigned int kmem_cache_size(struct kmem_cache *s);


#ifndef KMEM_CACHE_DEBUG
void *kmem_cache_alloc(struct kmem_cache *cache, int flag);
void kmem_cache_free(struct kmem_cache *cache, void *obj);
#endif

#endif

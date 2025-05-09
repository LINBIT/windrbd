#ifndef SLAB_H
#define SLAB_H

#include <linux/types.h>	/* for size_t, ... */

/* TODO: Linux header should not depend on WinDRBD header ... */
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

void *kmalloc(size_t size, gfp_t flag);
void *kzalloc(size_t size, gfp_t flag);
void *kcalloc(size_t size, int count, gfp_t flag);
void *__vmalloc(size_t size, gfp_t flag);

void kfree(const void *data);
void kvfree(const void *data);

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

#include <linux/gfp.h>		/* for GFP_xxx macros, ... */

#endif

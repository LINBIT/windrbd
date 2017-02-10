#ifndef SLAB_H
#define SLAB_H

#include <wdm.h>

struct kmem_cache {
	NPAGED_LOOKASIDE_LIST l;
};

struct kmem_cache *kmem_cache_create(const char *name, size_t size, size_t align,
				     unsigned long flags,
				     void (*ctor)(void *), ULONG tag);
void kmem_cache_destroy(struct kmem_cache *cache);


void *kmem_cache_alloc(void *cache, int flag);
void kmem_cache_free(void *cache, void *obj);

#endif

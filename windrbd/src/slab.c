/* Enable all warnings throws lots of those warnings: */
#pragma warning(disable: 4061 4062 4255 4388 4668 4820 5032 4711 5045)

#include <linux/slab.h>
#include "drbd_windows.h"

struct kmem_cache *kmem_cache_create(const char *name, size_t size, size_t align,
				     unsigned long flags,
				     void (*ctor)(void *), ULONG tag)
{
	struct kmem_cache *cache;

	cache = kmalloc(sizeof(*cache), GFP_KERNEL, tag);
	if (!cache)
		return NULL;
	ExInitializeNPagedLookasideList(&cache->l, NULL, NULL, 0, size, tag, 0);
	cache->element_size = size;

	return cache;
}

void kmem_cache_destroy(struct kmem_cache *cache)
{
	ExDeleteNPagedLookasideList(&cache->l);
	kfree(cache);
}

#ifndef KMEM_CACHE_DEBUG

void *kmem_cache_alloc(struct kmem_cache * cache, int flag)
{
	void *p = ExAllocateFromNPagedLookasideList(&cache->l);
	if (p != NULL)
		RtlZeroMemory(p, cache->element_size);

	return p;
}

void kmem_cache_free(struct kmem_cache * cache, void *obj)
{
	ExFreeToNPagedLookasideList(&cache->l, obj);
}

#endif

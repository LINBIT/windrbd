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

void *kmem_cache_alloc(struct kmem_cache * cache, int flag)
{
	void *p = ExAllocateFromNPagedLookasideList(&cache->l);
mem_printk("RtlZeroMemory %p %d\n", p, cache->element_size);
	RtlZeroMemory(p, cache->element_size);
	return p;
}

void kmem_cache_free(struct kmem_cache * cache, void *obj)
{
	memset(obj, 'y', cache->element_size);
	ExFreeToNPagedLookasideList(&cache->l, obj);
}

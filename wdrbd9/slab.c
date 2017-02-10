#include <linux/slab.h>

struct kmem_cache *kmem_cache_create(const char *name, size_t size, size_t align,
				     unsigned long flags,
				     void (*ctor)(void *), ULONG tag)
{
	struct kmem_cache *cache;

	cache = ExAllocatePoolWithTag(NonPagedPool, sizeof(*cache), tag);
	if (!cache)
		return NULL;
	ExInitializeNPagedLookasideList(&cache->l, NULL, NULL, 0,
					sizeof(struct drbd_request), tag, 0);

	return cache;
}

void kmem_cache_destroy(struct kmem_cache *cache)
{
	ExDeleteNPagedLookasideList(&cache->l);
	ExFreePool(cache);
}

void *kmem_cache_alloc(void * cache, int flag)
{
	return ExAllocateFromNPagedLookasideList(cache);
}

void kmem_cache_free(void * cache, void *obj)
{
	ExFreeToNPagedLookasideList(cache, obj);
}

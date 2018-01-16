#include <linux/slab.h>

struct kmem_cache *kmem_cache_create(const char *name, size_t size, size_t align,
				     unsigned long flags,
				     void (*ctor)(void *), ULONG tag)
{
	struct kmem_cache *cache;

	cache = ExAllocatePoolWithTag(NonPagedPool, sizeof(*cache), tag);
	if (!cache)
		return NULL;
	ExInitializeNPagedLookasideList(&cache->l, NULL, NULL, 0, size, tag, 0);
	cache->element_size = size;

	return cache;
}

void kmem_cache_destroy(struct kmem_cache *cache)
{
	ExDeleteNPagedLookasideList(&cache->l);
	ExFreePool(cache);
}

void *kmem_cache_alloc(struct kmem_cache * cache, int flag)
{
	void *p = ExAllocateFromNPagedLookasideList(&cache->l);
	RtlZeroMemory(p, cache->element_size);
	return p;
}

void kmem_cache_free(struct kmem_cache * cache, void *obj)
{
printk("&cache->l: %p obj: %p\n", &cache->l, obj);
	ExFreeToNPagedLookasideList(&cache->l, obj);
}

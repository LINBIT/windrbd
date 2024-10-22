#include <linux/slab.h>
#include <windrbd_internal.h>

/* TODO: we probably want to remove this. */

struct kmem_cache *kmem_cache_create(const char *name, size_t size, size_t align,
				     ULONG_PTR flags,
				     void (*ctor)(void *))
{
	struct kmem_cache *cache;

	cache = kmalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache)
		return NULL;
//	ExInitializeNPagedLookasideList(&cache->l, NULL, NULL, 0, size, DRBD_TAG, 0);
	cache->element_size = size;

	return cache;
}

void kmem_cache_destroy(struct kmem_cache *cache)
{
//	ExDeleteNPagedLookasideList(&cache->l);
	kfree(cache);
}

unsigned int kmem_cache_size(struct kmem_cache *s)
{
	return s->element_size;
}

#ifndef KMEM_CACHE_DEBUG

void *kmem_cache_alloc(struct kmem_cache * cache, int flag)
{
	void *p = kmalloc(cache->element_size, GFP_KERNEL);
	if (p != NULL)
		RtlZeroMemory(p, cache->element_size); /* TODO: memset? */

	return p;
}

void kmem_cache_free(struct kmem_cache * cache, void *obj)
{
	kfree(obj);
}

#endif

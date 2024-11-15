#include <linux/slab.h>
#include <windrbd_internal.h>

/* This maps the Linux kmem_cache functions used by DRBD
 * to our kmalloc / kfree implementation.
 * There were problems with the ExInitializeNPagedLookasideList()
 * implementation (something with the NX bit in the HLK tests
 * as far as I remember) so we changed it to kmalloc/kfree
 * they will retry the allocation if it fails.
 */

struct kmem_cache *kmem_cache_create(const char *name, size_t size, size_t align,
				     ULONG_PTR flags,
				     void (*ctor)(void *))
{
	struct kmem_cache *cache;

	cache = kmalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache)
		return NULL;
	cache->element_size = size;

	return cache;
}

void kmem_cache_destroy(struct kmem_cache *cache)
{
	kfree(cache);
}

unsigned int kmem_cache_size(struct kmem_cache *s)
{
	return s->element_size;
}

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

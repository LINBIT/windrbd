#ifndef SLAB_H
#define SLAB_H

/* Enable all warnings throws lots of those warnings: */
#pragma warning(disable: 4061 4062 4255 4388 4668 4820 5032  4711 5045)

#include <wdm.h>
#include "drbd_windows.h"

struct kmem_cache {
	NPAGED_LOOKASIDE_LIST l;
	size_t element_size;
};

typedef struct kmem_cache kmem_cache_t;

struct kmem_cache *kmem_cache_create(const char *name, size_t size, size_t align,
				     unsigned long flags,
				     void (*ctor)(void *), ULONG tag);
void kmem_cache_destroy(struct kmem_cache *cache);


#ifndef KMEM_CACHE_DEBUG
void *kmem_cache_alloc(void *cache, int flag);
void kmem_cache_free(void *cache, void *obj);
#endif

#endif

#ifndef MEMPOOL_H
#define MEMPOOL_H

#include <linux/types.h>

struct kmem_cache;

typedef struct mempool_s {
	enum {
		MEMPOOL_PAGE,
		MEMPOOL_SLAB
	} type;
	union {
		struct kmem_cache *cache;
		struct {
			NPAGED_LOOKASIDE_LIST pageLS;
			NPAGED_LOOKASIDE_LIST page_addrLS;
		};
	};
} mempool_t;

extern mempool_t *mempool_create_page_pool(int min_nr, int order, ULONG tag);
extern mempool_t *mempool_create_slab_pool(int min_nr, struct kmem_cache *kc, ULONG tag);
extern void mempool_destroy(mempool_t *pool);
extern void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask);
extern void mempool_free(void *element, mempool_t *pool);

static inline void mempool_exit(mempool_t *pool)
{
	mempool_destroy(pool);
}

int mempool_init_page_pool(mempool_t *pool, int min_nr, int order);
int mempool_init_slab_pool(mempool_t *pool, int min_nr, struct kmem_cache *kc);

#endif

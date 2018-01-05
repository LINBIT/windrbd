#include <linux/mempool.h>
#include <linux/slab.h>

mempool_t *mempool_create_page_pool(int min_nr, int order, ULONG tag)
{
	mempool_t *pool;

	pool = ExAllocatePoolWithTag(NonPagedPool, sizeof(*pool), tag);
	if (!pool)
		return NULL;

	pool->type = MEMPOOL_PAGE;
	ExInitializeNPagedLookasideList(&pool->pageLS, NULL, NULL, 0, sizeof(struct page), tag, 0);
        ExInitializeNPagedLookasideList(&pool->page_addrLS, NULL, NULL, 0, PAGE_SIZE, tag, 0);

	return pool;
}

mempool_t *mempool_create_slab_pool(int min_nr, struct kmem_cache *kc, ULONG tag)
{
	mempool_t *pool;

	pool = ExAllocatePoolWithTag(NonPagedPool, sizeof(*pool), tag);
	if (!pool)
		return NULL;

	pool->type = MEMPOOL_SLAB;
	pool->cache = kc;

	return pool;
}

void mempool_destroy(mempool_t *pool)
{
	if (pool->type == MEMPOOL_PAGE) {
		ExDeleteNPagedLookasideList(&pool->pageLS);
		ExDeleteNPagedLookasideList(&pool->page_addrLS);
	}
	ExFreePool(pool);
}

void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
{
	if (pool->type == MEMPOOL_PAGE) {
		struct page* page;

                page = ExAllocateFromNPagedLookasideList(&pool->pageLS);
                if (page) {
                        page->addr = ExAllocateFromNPagedLookasideList(&pool->page_addrLS);
                        if(page->addr) {
                                return page;
			}

			ExFreeToNPagedLookasideList(&pool->pageLS, page);
		}
		return NULL;
	}

	return kmem_cache_alloc(pool->cache, gfp_mask);
}

void mempool_free(void *element, mempool_t *pool)
{
	if (element == NULL)
		return;

	if (pool->type == MEMPOOL_PAGE) {
		struct page* page = element;

                ExFreeToNPagedLookasideList (&pool->page_addrLS, page->addr);
                ExFreeToNPagedLookasideList (&pool->pageLS, page);
	} else {
		kmem_cache_free(pool->cache, element);
	}
}

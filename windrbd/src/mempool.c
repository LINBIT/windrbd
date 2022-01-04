#include <linux/mempool.h>
#include <linux/slab.h>
#include "drbd_windows.h"

int mempool_init_page_pool(mempool_t *pool, int min_nr, int order)
{
	pool->type = MEMPOOL_PAGE;
	ExInitializeNPagedLookasideList(&pool->pageLS, NULL, NULL, 0, sizeof(struct page), 'DRBD', 0);
        ExInitializeNPagedLookasideList(&pool->page_addrLS, NULL, NULL, 0, PAGE_SIZE, 'DRBD', 0);

	return 0;
}

mempool_t *mempool_create_page_pool(int min_nr, int order, ULONG tag)
{
	mempool_t *pool;

	pool = kmalloc(sizeof(*pool), GFP_KERNEL, tag);
	if (!pool)
		return NULL;
	pool->is_kmalloced = MEMPOOL_KMALLOCED_MAGIC;

	if (mempool_init_page_pool(pool, min_nr, order) != 0) {
		kfree(pool);
		return NULL;
	}
	return pool;
}

int mempool_init_slab_pool(mempool_t *pool, int min_nr, struct kmem_cache *kc)
{
	pool->type = MEMPOOL_SLAB;
	pool->cache = kc;

	return 0;
}

mempool_t *mempool_create_slab_pool(int min_nr, struct kmem_cache *kc, ULONG tag)
{
	mempool_t *pool;

	pool = kmalloc(sizeof(*pool), GFP_KERNEL, tag);
	if (!pool)
		return NULL;
	pool->is_kmalloced = MEMPOOL_KMALLOCED_MAGIC;

	if (mempool_init_slab_pool(pool, min_nr, kc) != 0) {
		kfree(pool);
		return NULL;
	}
	return pool;
}

void mempool_destroy(mempool_t *pool)
{
	if (pool->type == MEMPOOL_PAGE) {
		ExDeleteNPagedLookasideList(&pool->pageLS);
		ExDeleteNPagedLookasideList(&pool->page_addrLS);
	}
	if (pool->is_kmalloced == MEMPOOL_KMALLOCED_MAGIC)
		kfree(pool);
}

void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
{
	if (pool->type == MEMPOOL_PAGE) {
		struct page* page;

                page = ExAllocateFromNPagedLookasideList(&pool->pageLS);
                if (page) {
                        page->addr = ExAllocateFromNPagedLookasideList(&pool->page_addrLS);
                        if(page->addr) {
				page->size = PAGE_SIZE;
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

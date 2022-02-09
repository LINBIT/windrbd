// DRBD_DOC: from http://ftp.openswan.org/openswan/openswan-ocf/klips-fsm/lib/idr.c
/*
* 2002-10-18  written by Jim Houston jim.houston@ccur.com
*	Copyright (C) 2002 by Concurrent Computer Corporation
*	Distributed under the GNU GPL license version 2.
*
* Modified by George Anzinger to reuse immediately and to use
* find bit instructions.  Also removed _irq on spinlocks.
*
* Small id to pointer translation service.
*
* It uses a radix tree like structure as a sparse array indexed
* by the id to obtain the pointer.  The bitmap makes allocating
* a new id quick.
*
* You call it to allocate an id (an int) an associate with that id a
* pointer or what ever, we treat it as a (void *).  You can pass this
* id to a user for him to pass back at a later time.  You then pass
* that id to this code and it returns your pointer.

* You can release ids at any time. When all ids are released, most of
* the memory is returned (we keep IDR_FREE_MAX) in a local pool so we
* don't need to go to the memory "store" during an id allocate, just
* so you don't need to be too concerned about locking and conflicts
* with the slab allocator.
*/

#include "drbd_windows.h"
#include "drbd_wingenl.h"
#include "linux/idr.h"
#include "linux/slab.h"
#include "linux/bitops.h"

/* TODO: no KeAcquireSpinLock -> spin_lock_irqsave() */

static kmem_cache_t *idr_layer_cache = NULL;

static struct idr_layer *alloc_layer(struct idr *idp)
{
	struct idr_layer *p;
	KIRQL oldIrql;

printk("before idp->id_free is %p idp->id_free_cnt is %d\n", idp->id_free, idp->id_free_cnt);
	KeAcquireSpinLock(&idp->lock, &oldIrql);
	if ((p = idp->id_free) != 0) {
		idp->id_free = p->ary[0];
		idp->id_free_cnt--;
		p->ary[0] = NULL;
	}
printk("after idp->id_free is %p idp->id_free_cnt is %d\n", idp->id_free, idp->id_free_cnt);

	KeReleaseSpinLock(&idp->lock, oldIrql);
	return(p);
}

/* only called when idp->lock is held */
static void __free_layer(struct idr *idp, struct idr_layer *p)
{
	p->ary[0] = idp->id_free;
	idp->id_free = p;
	idp->id_free_cnt++;
}

static void free_layer(struct idr *idp, struct idr_layer *p)
{
	KIRQL oldIrql;

	/*
	* Depends on the return element being zeroed.
	*/
	KeAcquireSpinLock(&idp->lock, &oldIrql);
	__free_layer(idp, p);
	KeReleaseSpinLock(&idp->lock, oldIrql);
}

/**
* idr_pre_get - reserver resources for idr allocation
* @idp:	idr handle
* @gfp_mask:	memory allocation flags
*
* This function should be called prior to locking and calling the
* following function.  It preallocates enough memory to satisfy
* the worst possible allocation.
*
* If the system is REALLY out of memory this function returns 0,
* otherwise 1.
*/
int idr_pre_get(struct idr *idp, gfp_t gfp_mask)
{
	while (idp->id_free_cnt < IDR_FREE_MAX) {
		struct idr_layer *new = NULL;

		new = kmem_cache_alloc(idr_layer_cache, gfp_mask);
		if (new == NULL)
			return (0);
printk("IDR new is %p\n", new);
		idp->num_allocated++;
		free_layer(idp, new);
	}
	return (1);
}

static int sub_alloc(struct idr *idp, void *ptr, int *starting_id)
{
	int n, m, sh;
	struct idr_layer *p, *new;
	struct idr_layer *pa[MAX_LEVEL];
	int l, id;
	ULONG_PTR bm;

	id = *starting_id;
	p = idp->top;
	l = idp->layers;
	pa[l--] = NULL;
    
    for (;;) {
		/*
		* We run around this while until we reach the leaf node...
		*/
		n = (id >> (IDR_BITS*l)) & IDR_MASK;
		bm = ~p->bitmap;
		m = find_next_bit(&bm, IDR_SIZE, n);
		if (m == IDR_SIZE) {
			/* no space available go back to previous layer. */
			l++;
			id = (id | ((1 << (IDR_BITS * l)) - 1)) + 1;
			p = pa[l];
			if (!p) {
				*starting_id = id;
				return -2;
			}
			continue;
		}
		if (m != n) {
			sh = IDR_BITS*l;
			id = ((id >> sh) ^ n ^ m) << sh;
		}
		if ((id >= MAX_ID_BIT) || (id < 0))
			return -3;
		if (l == 0)
			break;
		/*
		* Create the layer below if it is missing.
		*/
		if (!p->ary[m]) {
			if (!((new = alloc_layer(idp)) != 0))
				return -1;
			p->ary[m] = new;
			p->count++;
		}
		pa[l--] = p;
		p = p->ary[m];
	}
	/*
	* We have reached the leaf node, plant the
	* users pointer and return the raw id.
	*/
	p->ary[m] = (struct idr_layer *)ptr;
	__set_bit(m, &p->bitmap);
	p->count++;
	/*
	* If this layer is full mark the bit in the layer above
	* to show that this part of the radix tree is full.
	* This may complete the layer above and require walking
	* up the radix tree.
	*/
	n = id;
	while (p->bitmap == IDR_FULL) {
		if (!((p = pa[++l]) != 0))
			break;
		n = n >> IDR_BITS;
		__set_bit((n & IDR_MASK), &p->bitmap);
	}
	return(id);
}

static int idr_get_new_above_int(struct idr *idp, void *ptr, int starting_id)
{
	struct idr_layer *p, *new;
	int layers, v, id;
	KIRQL oldIrql;

	id = starting_id;
build_up:
	p = idp->top;
	layers = idp->layers;
	if (!p) {
printk("1\n");
		p = alloc_layer(idp);
printk("2 p is %p\n", p);
		if (!p)
			return -1;
		layers = 1;
	}
	/*
	* Add a new layer to the top of the tree if the requested
	* id is larger than the currently allocated space.
	*/
printk("3\n");
	while ((layers < (MAX_LEVEL - 1)) && (id >= (1 << (layers*IDR_BITS)))) {
		layers++;
		if (!p->count)
			continue;
printk("4\n");
		if (!((new = alloc_layer(idp)) != 0)) {
			/*
			* The allocation failed.  If we built part of
			* the structure tear it down.
			*/
printk("5\n");
			KeAcquireSpinLock(&idp->lock, &oldIrql);
			for (new = p; p && p != idp->top; new = p) {
				p = p->ary[0];
				new->ary[0] = NULL;
				new->bitmap = new->count = 0;
				__free_layer(idp, new);
			}

			KeReleaseSpinLock(&idp->lock, oldIrql);
			return -1;
		}
printk("6\n");
		new->ary[0] = p;
		new->count = 1;
		if (p->bitmap == IDR_FULL)
			__set_bit(0, &new->bitmap);
		p = new;
	}
printk("7\n");
	idp->top = p;
	idp->layers = layers;
	v = sub_alloc(idp, ptr, &id);
	if (v == -2)
		goto build_up;
printk("8 v is %d\n", v);
	return(v);
}

/**
* idr_get_new_above - allocate new idr entry above or equal to a start id
* @idp: idr handle
* @ptr: pointer you want associated with the ide
* @start_id: id to start search at
* @id: pointer to the allocated handle
*
* This is the allocate id function.  It should be called with any
* required locks.
*
* If memory is required, it will return -EAGAIN, you should unlock
* and go back to the idr_pre_get() call.  If the idr is full, it will
* return -ENOSPC.
*
* @id returns a value in the range 0 ... 0x7fffffff
*/
int idr_get_new_above(struct idr *idp, void *ptr, int starting_id, int *id)
{
	int rv;

	rv = idr_get_new_above_int(idp, ptr, starting_id);
	/*
	* This is a cheap hack until the IDR code can be fixed to
	* return proper error values.
	*/
	if (rv < 0) {
		if (rv == -1)
			return -EAGAIN;
		else /* Will be -3 */
			return -ENOSPC;
	}
	*id = rv;
	return 0;
}

/**
* idr_get_new - allocate new idr entry
* @idp: idr handle
* @ptr: pointer you want associated with the ide
* @id: pointer to the allocated handle
*
* This is the allocate id function.  It should be called with any
* required locks.
*
* If memory is required, it will return -EAGAIN, you should unlock
* and go back to the idr_pre_get() call.  If the idr is full, it will
* return -ENOSPC.
*
* @id returns a value in the range 0 ... 0x7fffffff
*/
int idr_get_new(struct idr *idp, void *ptr, int *id)
{
	int rv;

	rv = idr_get_new_above_int(idp, ptr, 0);
	/*
	* This is a cheap hack until the IDR code can be fixed to
	* return proper error values.
	*/
	if (rv < 0) {
		if (rv == -1)
			return -EAGAIN;
		else /* Will be -3 */
			return -ENOSPC;
	}
	*id = rv;
	return 0;
}

static void idr_remove_warning(int id)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
		"idr_remove called for id=%d which is not allocated.\n", id);
}

static void sub_remove(struct idr *idp, int shift, int id)
{
	struct idr_layer *p = idp->top;
	struct idr_layer **pa[MAX_LEVEL];
	struct idr_layer ***paa = &pa[0];
	int n;

	*paa = NULL;
	*++paa = &idp->top;

	while ((shift > 0) && p) {
		n = (id >> shift) & IDR_MASK;
		__clear_bit(n, &p->bitmap);
		*++paa = &p->ary[n];
		p = p->ary[n];
		shift -= IDR_BITS;
	}
	n = id & IDR_MASK;
	if (likely(p != NULL && test_bit(n, &p->bitmap))){
		__clear_bit(n, &p->bitmap);
		p->ary[n] = NULL;
		while (*paa && !--((**paa)->count)){
			free_layer(idp, **paa);
			**paa-- = NULL;
		}
		if (!*paa)
			idp->layers = 0;
	}
	else
		idr_remove_warning(id);
}

/**
* idr_remove - remove the given id and free it's slot
* idp: idr handle
* id: uniqueue key
*/
void idr_remove(struct idr *idp, int id)
{
	struct idr_layer *p;

printk("about to remove id %d\n", id);
	/* Mask off upper bits we don't use for the search. */
	id &= MAX_ID_MASK;

	sub_remove(idp, (idp->layers - 1) * IDR_BITS, id);
	if (idp->top && idp->top->count == 1 && (idp->layers > 1) &&
		idp->top->ary[0]) {
			// We can drop a layer
			p = idp->top->ary[0];
			idp->top->bitmap = idp->top->count = 0;
			free_layer(idp, idp->top);
			idp->top = p;
			--idp->layers;
	}
	while (idp->id_free_cnt >= IDR_FREE_MAX) {
		p = alloc_layer(idp);
printk("IDR about to free layer %p\n", p);
		idp->num_allocated--;
		kmem_cache_free(idr_layer_cache, p);
		return;
	}
}

/**
* idr_destroy - release all cached layers within an idr tree
* idp: idr handle
*/
void idr_destroy(struct idr *idp)
{
printk("idp->id_free_cnt is %d\n", idp->id_free_cnt);
	while (idp->num_allocated > 0) {
		struct idr_layer *p = alloc_layer(idp);
printk("IDR about to free layer %p idp->id_free_cnt is %d idp->num_allocated is %d\n", p, idp->id_free_cnt, idp->num_allocated);
		idp->num_allocated--;
		kmem_cache_free(idr_layer_cache, p);
	}
printk("IDR finished idp->id_free_cnt is %d idp->num_allocated is %d\n", idp->id_free_cnt, idp->num_allocated);
}

/**
* idr_find - return pointer for given id
* @idp: idr handle
* @id: lookup key
*
* Return the pointer given the id it has been registered with.  A %NULL
* return indicates that @id is not valid or you passed %NULL in
* idr_get_new().
*
* The caller must serialize idr_find() vs idr_get_new() and idr_remove().
*/
void *idr_find(struct idr *idp, int id)
{
	int n;
	struct idr_layer *p;

	n = idp->layers * IDR_BITS;
	p = idp->top;

	/* Mask off upper bits we don't use for the search. */
	id &= MAX_ID_MASK;

	if (id >= (1 << n))
		return NULL;

	while (n > 0 && p) {
		n -= IDR_BITS;
		p = p->ary[(id >> n) & IDR_MASK];
	}
	return((void *) p);
}

/**
 * idr_for_each - iterate through all stored pointers
 * @idp: idr handle
 * @fn: function to be called for each pointer
 * @data: data passed back to callback function
 *
 * Iterate over the pointers registered with the given idr.  The
 * callback function will be called for each pointer currently
 * registered, passing the id, the pointer and the data pointer passed
 * to this function.  It is not safe to modify the idr tree while in
 * the callback, so functions such as idr_get_new and idr_remove are
 * not allowed.
 *
 * We check the return of @fn each time. If it returns anything other
 * than 0, we break out and return that value.
 *
 * The caller must serialize idr_for_each() vs idr_get_new() and idr_remove().
 */
// DRBD_DOC: from http://ftp.openswan.org/openswan/openswan-ocf/klips-fsm/lib/idr.c
int idr_for_each(struct idr *idp,
		 int (*fn)(int id, void *p, void *data), void *data)
{
	int n, id, max, error = 0;
	struct idr_layer *p;
	struct idr_layer *pa[MAX_LEVEL];
	struct idr_layer **paa = &pa[0];

	n = idp->layers * IDR_BITS;
	p = rcu_dereference(idp->top);
	max = 1 << n;

	id = 0;
	while (id < max) {
		while (n > 0 && p) {
			n -= IDR_BITS;
			*paa++ = p;
			p = rcu_dereference(p->ary[(id >> n) & IDR_MASK]);
		}

		if (p) {
			error = fn(id, (void *)p, data);
			if (error)
				break;
		}

		id += 1 << n;
		while (n < fls(id)) {
			n += IDR_BITS;
			p = *--paa;
		}
	}

	return error;
}

/**
* idr_replace - replace pointer for given id
* @idp: idr handle
* @ptr: pointer you want associated with the id
* @id: lookup key
*
* Replace the pointer registered with an id and return the old value.
* A -ENOENT return indicates that @id was not found.
* A -EINVAL return indicates that @id was not within valid constraints.
*
* The caller must serialize vs idr_find(), idr_get_new(), and idr_remove().
*/
void *idr_replace(struct idr *idp, void *ptr, int id)
{
	int n;
	struct idr_layer *p, *old_p;

	n = idp->layers * IDR_BITS;
	p = idp->top;

	id &= MAX_ID_MASK;

	if (id >= (1 << n))
		return ERR_PTR(-EINVAL);

	n -= IDR_BITS;
	while ((n > 0) && p) {
		p = p->ary[(id >> n) & IDR_MASK];
		n -= IDR_BITS;
	}

	n = id & IDR_MASK;
	if (p == NULL || !test_bit(n, &p->bitmap))
		return ERR_PTR(-ENOENT);

	old_p = p->ary[n];
	p->ary[n] = ptr;

	return old_p;
}

static void idr_cache_ctor(void * idr_layer, kmem_cache_t *idr_layer_cache, unsigned long flags)
{
// mem_printk("RtlZeroMemory %p %d\n", idr_layer, sizeof(struct idr_layer));
	RtlZeroMemory(idr_layer, sizeof(struct idr_layer));
}

static  int init_id_cache(void)
{
	if (!idr_layer_cache)
	{
		idr_layer_cache = kmem_cache_create("idr_layer_cache", sizeof(struct idr_layer), 0, 0, NULL, 'E4DW');
	}
	return 0;
}

/**
* idr_init - initialize idr handle
* @idp:	idr handle
*
* This function is use to set up the handle (@idp) that you will pass
* to the rest of the functions.
*/
void idr_init(struct idr *idp)
{
	init_id_cache();
// mem_printk("memset %p 0 %d\n", idp, sizeof(struct idr));
	memset(idp, 0, sizeof(struct idr));
	KeInitializeSpinLock(&idp->lock);
}

void idr_shutdown(void)
{
	if (idr_layer_cache)
		kmem_cache_destroy(idr_layer_cache);
}

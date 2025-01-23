#ifndef RCUPDATE_H
#define RCUPDATE_H

#include <asm-generic/barrier.h>

#define rcu_dereference(_PTR)		(_PTR)
#define __rcu_assign_pointer(_p, _v) \
	do { \
		smp_mb();    \
		WRITE_ONCE((_p), (_v)); \
	} while (0)

#define rcu_dereference_protected(p, c) (p)

#define rcu_assign_pointer(p, v)	__rcu_assign_pointer((p), (v))
#define list_next_rcu(list)		(*((struct list_head **)(&(list)->next)))

	/* TODO: how is this function called in Linux? */
void kfree_when_rcu_in_sync(void *p);

#define kfree_rcu_mightsleep(ptr) kfree_when_rcu_in_sync(ptr)
#define kvfree_rcu_mightsleep(ptr) kfree_when_rcu_in_sync(ptr)

#define rcu_barrier() barrier()

#endif

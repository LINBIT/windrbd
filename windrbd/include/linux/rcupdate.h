
#ifndef RCUPDATE_H
#define RCUPDATE_H

#define rcu_dereference(_PTR)		(_PTR)
#define __rcu_assign_pointer(_p, _v) \
	do { \
		smp_mb();    \
		(_p) = (_v); \
	} while (0)

#define rcu_assign_pointer(p, v)	__rcu_assign_pointer((p), (v))
#define list_next_rcu(list)		(*((struct list_head **)(&(list)->next)))

#endif

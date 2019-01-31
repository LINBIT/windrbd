#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__
#include <wdm.h>

/* TODO: most of this goes away ... soon */
typedef struct _tagSPINLOCK
{
    KSPIN_LOCK 	spinLock;
    KIRQL 		saved_oldIrql;
	PKTHREAD 	OwnerThread; // lock owner
	LONG		Refcnt; // reference count for protecting recursion
} spinlock_t;

extern void spin_lock_init(spinlock_t *lock);
///extern void spin_lock_irqsave(spinlock_t *lock, long flags);
extern void spin_lock_irq(spinlock_t *lock);
extern void spin_lock_bh(spinlock_t *lock);
extern void spin_unlock_bh(spinlock_t *lock);
extern void spin_lock(spinlock_t *lock);
extern void spin_unlock(spinlock_t *lock);
extern void spin_unlock_irq(spinlock_t *lock);
extern void spin_unlock_irqrestore(spinlock_t *lock, long flags);
extern long _spin_lock_irqsave(spinlock_t* lock);

#define spin_lock_irqsave(lock, flags) flags = _spin_lock_irqsave(lock); 

#endif

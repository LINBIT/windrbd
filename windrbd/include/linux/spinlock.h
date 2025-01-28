#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#include <linux/types.h>

typedef struct spinlock
{
	KSPIN_LOCK spinLock;

	bool printk_lock;	/* non zero if used by printk: TODO: ifdef debug */
} spinlock_t;

extern void spin_lock_init(spinlock_t *lock);

#define DECLARE_SPINLOCK(unused) \
Error Cannot implement DECLARE_SPINLOCK since we need to call KeInitializeSpinlock at runtime. Please manually patch your driver.

/* still used by drbd_main lock all resources but with IRQL = DISPATCH level */
extern void spin_lock_nested(spinlock_t *lock, int level);
extern void spin_lock(spinlock_t *lock);
extern void spin_unlock(spinlock_t *lock);
extern void spin_lock_bh(spinlock_t *lock);
extern void spin_unlock_bh(spinlock_t *lock);
extern void spin_lock_irq(spinlock_t *lock);
extern void spin_unlock_irq(spinlock_t *lock);

extern void spin_unlock_irqrestore(spinlock_t *lock, KIRQL flags);
extern KIRQL _spin_lock_irqsave(spinlock_t *lock);

#define spin_lock_irqsave(l,flags) \
	flags = _spin_lock_irqsave(l)

extern int spin_trylock(spinlock_t *lock);
extern void init_locking(void);

extern void local_irq_disable();
extern void local_irq_enable();

/* Nothing for now ... */
#define assert_spin_locked(lock)	do { } while (0);

#endif

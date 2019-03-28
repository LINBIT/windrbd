#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#include <wdm.h>
#include <linux/types.h>

/* Define this to check IRQL at entry of spin_lock_irq() and the like. */
/* It currently probably is buggy. */

#define SPIN_LOCK_DEBUG 1

typedef struct _tagSPINLOCK
{
	KSPIN_LOCK spinLock;
	bool printk_lock;	/* non zero if used by printk: TODO: ifdef debug */
} spinlock_t;

extern void spin_lock_init(spinlock_t *lock);

#ifdef SPIN_LOCK_DEBUG

extern int spinlock_debug_init(void);
extern int spinlock_debug_shutdown(void);

extern void spin_lock_irq_debug(spinlock_t *lock, const char *file, int line, const char *func);
#define spin_lock_irq(lock) spin_lock_irq_debug(lock, __FILE__, __LINE__, __func__)

extern void spin_unlock_irq_debug(spinlock_t *lock, const char *file, int line, const char *func);
#define spin_unlock_irq(lock) spin_unlock_irq_debug(lock, __FILE__, __LINE__, __func__)

extern void spin_lock_debug(spinlock_t *lock, const char *file, int line, const char *func);
#define spin_lock(lock) spin_lock_debug(lock, __FILE__, __LINE__, __func__)

extern void spin_unlock_debug(spinlock_t *lock, const char *file, int line, const char *func);
#define spin_unlock(lock) spin_unlock_debug(lock, __FILE__, __LINE__, __func__)

extern void spin_lock_bh_debug(spinlock_t *lock, const char *file, int line, const char *func);
#define spin_lock_bh(lock) spin_lock_bh_debug(lock, __FILE__, __LINE__, __func__)

extern void spin_unlock_bh_debug(spinlock_t *lock, const char *file, int line, const char *func);
#define spin_unlock_bh(lock) spin_unlock_bh_debug(lock, __FILE__, __LINE__, __func__)

extern void spin_unlock_irqrestore_debug(spinlock_t *lock, long flags, const char *file, int line, const char *func);
#define spin_unlock_irqrestore(lock, flags) spin_unlock_irqrestore_debug(lock, flags, __FILE__, __LINE__, __func__)

extern long _spin_lock_irqsave_debug(spinlock_t* lock, const char *file, int line, const char *func);
#define spin_lock_irqsave(lock, flags) flags = _spin_lock_irqsave_debug(lock, __FILE__, __LINE__, __func__); 

#else

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

#endif

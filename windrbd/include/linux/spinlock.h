#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#include <wdm.h>
#include <linux/types.h>

/* Define this to check IRQL at entry of spin_lock_irq() and the like. */

/* It currently causes some BSOD's to happen more frequently (which
 * is good for testing but bad for releases), so disable it for
 * releases.
 */

/* TODO: SPIN_LOCK_DEBUG code is broken and not needed any more */

/* #define SPIN_LOCK_DEBUG 1 */
/* #define SPIN_LOCK_DEBUG2 1 */
/* #define RCU_DEBUG 1 */

#ifdef RELEASE
#ifdef SPIN_LOCK_DEBUG
#undef SPIN_LOCK_DEBUG
#endif
#ifdef SPIN_LOCK_DEBUG2
#undef SPIN_LOCK_DEBUG2
#endif
#ifdef RCU_DEBUG
#undef RCU_DEBUG
#endif
#endif

typedef struct _tagSPINLOCK
{
	KSPIN_LOCK spinLock;

	bool printk_lock;	/* non zero if used by printk: TODO: ifdef debug */
#if (defined SPIN_LOCK_DEBUG || defined SPIN_LOCK_DEBUG2)
	PKTHREAD locked_by_thread;
/*
	atomic_t recursion_depth;
*/
	char marker[16];
	char locked_by[128];

	LARGE_INTEGER timestamp_taken;
#endif
} spinlock_t;

extern void spin_lock_init(spinlock_t *lock);

#ifdef SPIN_LOCK_DEBUG

extern int spinlock_debug_init(void);
extern int spinlock_debug_shutdown(void);

#if 0

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

#endif

extern void spin_unlock_irqrestore_debug(spinlock_t *lock, long flags, const char *file, int line, const char *func);
#define spin_unlock_irqrestore(lock, flags) spin_unlock_irqrestore_debug(lock, flags, __FILE__, __LINE__, __func__)

extern long _spin_lock_irqsave_debug(spinlock_t* lock, const char *file, int line, const char *func);
#define spin_lock_irqsave(lock, flags) flags = _spin_lock_irqsave_debug(lock, __FILE__, __LINE__, __func__); 

#else

#if 0

extern void spin_lock_irq_debug_new(spinlock_t *lock, const char *file, int line, const char *func);
#define spin_lock_irq(lock) spin_lock_irq_debug_new(lock, __FILE__, __LINE__, __func__)
// extern void spin_lock_irq(spinlock_t *lock);
extern void spin_lock(spinlock_t *lock);
extern void spin_unlock_irq(spinlock_t *lock);
#endif
/* still used by drbd_main lock all resources but with IRQL = DISPATCH level */
extern void spin_lock_nested(spinlock_t *lock, int level);
extern void spin_unlock(spinlock_t *lock);

extern void spin_unlock_irqrestore(spinlock_t *lock, KIRQL flags);

extern KIRQL spin_lock_irqsave_debug_new(spinlock_t *lock, const char *file, int line, const char *func);
// extern KIRQL _spin_lock_irqsave(spinlock_t* lock);

#define spin_lock_irqsave(lock, flags) flags = spin_lock_irqsave_debug_new(lock, __FILE__, __LINE__, __func__)

#endif

int spin_trylock(spinlock_t *lock);
void init_locking(void);

#endif

#ifdef RCU_DEBUG

extern KIRQL rcu_read_lock_debug(const char *file, int line, const char *func);
extern void rcu_read_unlock_debug(KIRQL rcu_flags, const char *file, int line, const char *func);
extern void synchronize_rcu_debug(const char *file, int line, const char *func);
extern void call_rcu_debug(struct rcu_head *head, rcu_callback_t f, const char *file, int line, const char *func);

#define rcu_read_lock() rcu_read_lock_debug(__FILE__, __LINE__, __func__)
#define rcu_read_unlock(rcu_flags) rcu_read_unlock_debug(rcu_flags, __FILE__, __LINE__, __func__)
#define synchronize_rcu() synchronize_rcu_debug(__FILE__, __LINE__, __func__)
#define call_rcu(head, f) call_rcu_debug(head, f, __FILE__, __LINE__, __func__)

#else

extern KIRQL rcu_read_lock(void);
extern void rcu_read_unlock(KIRQL rcu_flags);
extern void synchronize_rcu(void);
extern void call_rcu(struct rcu_head *head, rcu_callback_t func);

#endif
extern void local_irq_disable();
extern void local_irq_enable();


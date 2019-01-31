#ifndef __LINUX_RWLOCK_H
#define __LINUX_RWLOCK_H

#include <linux/rwlock_types.h>

static inline void read_lock(rwlock_t *lock)
{
	spin_lock((spinlock_t*) lock);
}

static inline void read_unlock(rwlock_t *lock)
{
	spin_unlock((spinlock_t*) lock);
}

static inline void write_unlock_bh(rwlock_t *lock)
{
	spin_unlock((spinlock_t*) lock);
}

static inline void write_unlock(rwlock_t *lock)
{
	spin_unlock((spinlock_t*) lock);
}

static inline void write_lock_irq(rwlock_t *lock)
{
	spin_lock((spinlock_t*) lock);
}

static inline void write_lock_bh(rwlock_t *lock)
{
	spin_lock((spinlock_t*) lock);
}

static inline void write_unlock_irq(rwlock_t *lock)
{
	spin_unlock((spinlock_t*) lock);
}

extern void rwlock_init(rwlock_t *lock)
{
	spin_lock_init((spinlock_t*) lock);
}

#endif

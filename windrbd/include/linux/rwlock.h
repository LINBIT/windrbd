#ifndef __LINUX_RWLOCK_H
#define __LINUX_RWLOCK_H

#include <linux/rwlock_types.h>

void read_lock(rwlock_t *lock);
void read_unlock(rwlock_t *lock);
#if 0
void read_lock_bh(rwlock_t *lock);
void read_unlock_bh(rwlock_t *lock);
void read_lock_irq(rwlock_t *lock);
void read_unlock_irq(rwlock_t *lock);
#endif

KIRQL read_lock_irqsave_ret(rwlock_t *lock);

#define read_lock_irqsave(lock, flags) \
	flags = read_lock_irqsave_ret(lock)

void read_unlock_irqrestore(rwlock_t *lock, KIRQL flags);

KIRQL write_lock_irqsave_ret(rwlock_t *lock);

#define write_lock_irqsave(lock, flags) \
	flags = write_lock_irqsave_ret(lock)

void write_unlock_irqrestore(rwlock_t *lock, KIRQL flags);

void write_lock(rwlock_t *lock);
void write_unlock(rwlock_t *lock);
#if 0
void write_lock_bh(rwlock_t *lock);
void write_unlock_bh(rwlock_t *lock);
void write_lock_irq(rwlock_t *lock);
void write_unlock_irq(rwlock_t *lock);
#endif

void rwlock_init(rwlock_t *lock);

#endif

/*
	Copyright(C) 2017-2020, Johannes Thoma <johannes@johannesthoma.com>
	Copyright(C) 2017-2018, LINBIT HA-Solutions GmbH  <office@linbit.com>
	Copyright(C) 2007-2016, ManTechnology Co., LTD.
	Copyright(C) 2007-2016, wdrbd@mantech.co.kr

	Windows DRBD is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2, or (at your option)
	any later version.

	Windows DRBD is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Windows DRBD; see the file COPYING. If not, write to
	the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* This used to be a part of drbd_windows.c . It contains implementation
 * of muteces, spin locks, semaphores, read/write semaphores, RCU
 * handling routines and routines to control IRQL directly.
 */

#include <linux/types.h>
#include "windrbd_config.h"
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/wait.h>

/* Define this if RCU implementation can use read/write locks
 * (ExAcquireSpinLockShared, ...).
 */

/* #define CONFIG_HAVE_RW_LOCKS 1 */

void mutex_init(struct mutex *m)
{
	KeInitializeMutex(&m->mtx, 0);
}

NTSTATUS mutex_lock_timeout(struct mutex *m, ULONG msTimeout)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER nWaitTime = { 0, };

	if (NULL == m)
	{
		return STATUS_INVALID_PARAMETER;
	}

	nWaitTime.QuadPart = (-1 * 10000);
	nWaitTime.QuadPart *= msTimeout;		// multiply timeout value separately to avoid overflow.
	status = KeWaitForMutexObject(&m->mtx, Executive, KernelMode, FALSE, &nWaitTime);

	return status;
}

NTSTATUS mutex_lock(struct mutex *m)
{
    return KeWaitForMutexObject(&m->mtx, Executive, KernelMode, FALSE, NULL);
}

int mutex_lock_interruptible(struct mutex *m)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int err = -EIO;
	struct task_struct *thread = current;
	PVOID waitObjects[2];
	int wObjCount = 1;

	waitObjects[0] = (PVOID)&m->mtx;
	if (thread->has_sig_event)
	{
		waitObjects[1] = (PVOID)&thread->sig_event;
		wObjCount++;
	}
	status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, NULL, NULL);

	switch (status)
	{
	case STATUS_WAIT_0:		// mutex acquired.
		err = 0;
		break;
	case STATUS_WAIT_1:		// thread got signal by the func 'force_sig'
		err = thread->sig != 0 ? -thread->sig : -EIO;
		break;
	default:
		err = -EIO;
		printk("KeWaitForMultipleObjects returned unexpected status(0x%x)", status);
		break;
	}

	return err;
}

// Returns 1 if the mutex is locked, 0 if unlocked.
int mutex_is_locked(struct mutex *m)
{
	return (KeReadStateMutex(&m->mtx) == 1) ? 0 : 1;
}

// Try to acquire the mutex atomically. 
// Returns 1 if the mutex has been acquired successfully, and 0 on contention.
int mutex_trylock(struct mutex *m)
{
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = 0; 

	if (KeWaitForMutexObject(&m->mtx, Executive, KernelMode, FALSE, &Timeout) == STATUS_SUCCESS)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

void mutex_unlock(struct mutex *m)
{
	KeReleaseMutex(&m->mtx, FALSE);
}

void sema_init(struct semaphore *s, int val)
{
	KeInitializeSemaphore(&s->sem, val, LONG_MAX);
}

void down(struct semaphore *s)
{
	KeWaitForSingleObject(&s->sem, Executive, KernelMode, FALSE, NULL);
}

/**
  * down_trylock - try to acquire the semaphore, without waiting
  * @sem: the semaphore to be acquired
  *
  * Try to acquire the semaphore atomically.  Returns 0 if the semaphore has
  * been acquired successfully or 1 if it it cannot be acquired.
  */

int down_trylock(struct semaphore *s)
{
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = 0;
    
	if (KeWaitForSingleObject(&s->sem, Executive, KernelMode, FALSE, &Timeout) == STATUS_SUCCESS)
		return 0;

	return 1;
}

	/* TODO: or so ... */
int down_interruptible(struct semaphore *sem)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int err = -EIO;
	struct task_struct *thread = current;
	PVOID waitObjects[2];
	int wObjCount = 1;

	waitObjects[0] = (PVOID)&sem->sem;
	if (thread->has_sig_event)
	{
		waitObjects[1] = (PVOID)&thread->sig_event;
		wObjCount++;
	}
	status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, NULL, NULL);

	switch (status)
	{
	case STATUS_WAIT_0:		// semaphore acquired.
		err = 0;
		break;
	case STATUS_WAIT_1:		// thread got signal by the func 'force_sig'
		err = thread->sig != 0 ? -thread->sig : -EIO;
		break;
	default:
		err = -EIO;
		printk("KeWaitForMultipleObjects returned unexpected status(0x%x)", status);
		break;
	}

	return err;
}

void up(struct semaphore *s)
{
	if (KeReadStateSemaphore(&s->sem) < s->sem.Limit)
		KeReleaseSemaphore(&s->sem, IO_NO_INCREMENT, 1, FALSE);
	else
		printk("BUG: Semaphore limit reached: %d\n", s->sem.Limit);
}

	/* TODO: Implement rw_semaphores using list of waiters
	 * and a real semaphore.
	 */

void init_rwsem(struct rw_semaphore *sem)
{
	sema_init(&sem->the_semaphore, 1);
}

void down_write(struct rw_semaphore *sem)
{
	down(&sem->the_semaphore);
}

int down_write_trylock(struct rw_semaphore *sem)
{
		/* Note that in Linux the semantics of the return
		 * value is inverse from down_trylock hence the !
		 */
	return !down_trylock(&sem->the_semaphore);
}

void up_write(struct rw_semaphore *sem)
{
	up(&sem->the_semaphore);
}

void down_read(struct rw_semaphore *sem)
{
	down(&sem->the_semaphore);
}

void down_read_non_owner(struct rw_semaphore *sem)
{
	down(&sem->the_semaphore);
}

void up_read(struct rw_semaphore *sem)
{
	up(&sem->the_semaphore);
}

void up_read_non_owner(struct rw_semaphore *sem)
{
	up(&sem->the_semaphore);
}

	/* noop because there is no difference between read and write
	 * locks for now.
	 */

void downgrade_write(struct rw_semaphore *sem)
{
}

void spin_lock_init(spinlock_t *lock)
{
	KeInitializeSpinLock(&lock->spinLock);
	lock->printk_lock = 0;
}

#if 0
// #if (NTDDI_VERSION < NTDDI_VISTASP1)
#ifndef CONFIG_HAVE_RW_LOCKS
static spinlock_t rcu_spin_lock;
#else
static EX_SPIN_LOCK rcu_rw_lock;
#endif

#endif

static KIRQL guess_old_kirql(void)
{
	if (is_windrbd_thread(current))
		return PASSIVE_LEVEL;
	return APC_LEVEL;	/* or so ... */
}

/* See also defintion of spin_lock_irqsave in linux/spinlock.h for handling
 * the flags parameter.
 */

KIRQL _spin_lock_irqsave(spinlock_t *lock)
{
	KIRQL oldIrql;

	KeAcquireSpinLock(&lock->spinLock, &oldIrql);
	return oldIrql;
}

void spin_unlock_irqrestore(spinlock_t *lock, KIRQL flags)
{
	KeReleaseSpinLock(&lock->spinLock, flags);
}

void spin_lock_irq(spinlock_t *lock)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&lock->spinLock, &oldIrql);

		/* if oldIrql != PASSIVE_LEVEL complain */
if (oldIrql != PASSIVE_LEVEL)
printk("Ahiee, we're not passive level at the beginning of spin_lock_irq() irql is %d\n", oldIrql);
}

void spin_unlock_irq(spinlock_t *lock)
{
	KeReleaseSpinLock(&lock->spinLock, guess_old_kirql());
}

/* This does not change the IRQL. In particular if IRQL is
 * at PASSIVE_LEVEL it stays at PASSIVE_LEVEL which means
 * that the critical section may be preempted. Again,
 * use spin_lock_irqsave/spin_unlock_irqrestore whereever
 * possible.
 */

void spin_lock(spinlock_t *lock)
{
	KeAcquireSpinLockAtDpcLevel(&lock->spinLock);
}

void spin_unlock(spinlock_t *lock)
{
	KeReleaseSpinLockFromDpcLevel(&lock->spinLock);
}

void spin_lock_bh(spinlock_t *lock)
{
printk("KIRQL is %d\n", KeGetCurrentIrql());
	KeAcquireSpinLockAtDpcLevel(&lock->spinLock);
}

void spin_unlock_bh(spinlock_t *lock)
{
	KeReleaseSpinLockFromDpcLevel(&lock->spinLock);
}

void spin_lock_nested(spinlock_t *lock, int level)
{
	KeAcquireSpinLockAtDpcLevel(&lock->spinLock);
}

#ifndef CONFIG_HAVE_RW_LOCKS
// #if (NTDDI_VERSION < NTDDI_VISTASP1)

/* And now, the rw_locks. Note that this implementation with spin locks
 * causes DRBD 9.1 to lock up on application I/O, so only DRBD 9.0 support
 * for ReactOS and Windows Server 2003 for now.
 */

void read_lock(rwlock_t *lock)
{
	spin_lock((spinlock_t*) lock);
}

void read_unlock(rwlock_t *lock)
{
	spin_unlock((spinlock_t*) lock);
}

KIRQL read_lock_irqsave_ret(rwlock_t *lock)
{
	KIRQL flags;

	/* expands to flags = ... */
	spin_lock_irqsave(&lock->lock, flags);
	return flags;
}

void read_unlock_irqrestore(rwlock_t *lock, KIRQL flags)
{
	spin_unlock_irqrestore(&lock->lock, flags);
}

KIRQL write_lock_irqsave_ret(rwlock_t *lock)
{
	KIRQL flags;

	spin_lock_irqsave(&lock->lock, flags);
	return flags;
}

void write_unlock_irqrestore(rwlock_t *lock, KIRQL flags)
{
	spin_unlock_irqrestore(&lock->lock, flags);
}

void rwlock_init(rwlock_t *lock)
{
	spin_lock_init(&lock->lock);
}

#else

/* And now, the rw_locks using ExAcquireSpinLockShared and friends.
 * No recursion detection here. Also no DPC checking. It is the
 * same as the Linux implementation (I think :) ).
 */

void read_lock(rwlock_t *lock)
{
	ExAcquireSpinLockSharedAtDpcLevel(&lock->shared_exclusive_lock);
}

void read_unlock(rwlock_t *lock)
{
	ExReleaseSpinLockSharedFromDpcLevel(&lock->shared_exclusive_lock);
}

void read_lock_irq(rwlock_t *lock)
{
	KIRQL oldIrql;

	oldIrql = ExAcquireSpinLockShared(&lock->shared_exclusive_lock);
if (oldIrql != PASSIVE_LEVEL)
printk("Ahiee, we're not passive level at the beginning of read_lock_irq() irql is %d\n", oldIrql);
}

void read_unlock_irq(rwlock_t *lock)
{
	ExReleaseSpinLockShared(&lock->shared_exclusive_lock, guess_old_kirql());
}

KIRQL read_lock_irqsave_ret(rwlock_t *lock)
{
	return ExAcquireSpinLockShared(&lock->shared_exclusive_lock);
}

void read_unlock_irqrestore(rwlock_t *lock, KIRQL flags)
{
	ExReleaseSpinLockShared(&lock->shared_exclusive_lock, flags);
}

void write_lock(rwlock_t *lock)
{
	ExAcquireSpinLockExclusiveAtDpcLevel(&lock->shared_exclusive_lock);
}

void write_unlock(rwlock_t *lock)
{
	ExReleaseSpinLockExclusiveFromDpcLevel(&lock->shared_exclusive_lock);
}

void write_lock_bh(rwlock_t *lock)
{
printk("KIRQL is %d\n", KeGetCurrentIrql());
	ExAcquireSpinLockExclusiveAtDpcLevel(&lock->shared_exclusive_lock);
}

void write_unlock_bh(rwlock_t *lock)
{
	ExReleaseSpinLockExclusiveFromDpcLevel(&lock->shared_exclusive_lock);
}

void write_lock_irq(rwlock_t *lock)
{
	KIRQL oldIrql;

	oldIrql = ExAcquireSpinLockExclusive(&lock->shared_exclusive_lock);
if (oldIrql != PASSIVE_LEVEL)
printk("Ahiee, we're not passive level at the beginning of write_lock_irq() IRQL is %d\n", oldIrql);
}

void write_unlock_irq(rwlock_t *lock)
{
	ExReleaseSpinLockExclusive(&lock->shared_exclusive_lock, guess_old_kirql());
}

KIRQL write_lock_irqsave_ret(rwlock_t *lock)
{
	return ExAcquireSpinLockExclusive(&lock->shared_exclusive_lock);
}

void write_unlock_irqrestore(rwlock_t *lock, KIRQL flags)
{
	ExReleaseSpinLockExclusive(&lock->shared_exclusive_lock, flags);
}

void rwlock_init(rwlock_t *lock)
{
	lock->shared_exclusive_lock = 0;
}

#endif  /* < NTDDI_VISTASP1 */

static atomic_t rcu_counter;
static wait_queue_head_t nobody_in_rcu_read_lock;
static spinlock_t rcu_lock;
static struct rcu_head *rcu_heads;
struct rcu_pointer {
	struct rcu_pointer *next;
	void *free_me_later;
};

static struct rcu_pointer *rcu_pointers_to_free;

static void free_all_rcu_heads(void)
{
	struct rcu_head *h, *h2;

	for (h = rcu_heads; h != NULL; h = h2) {
		h2 = h->next;
		h->func(h);
	}
	rcu_heads = NULL;
}

static void free_all_rcu_pointers(void)
{
	struct rcu_pointer *p, *p2;

	for (p = rcu_pointers_to_free; p != NULL; p = p2) {
		p2 = p->next;
		kfree(p->free_me_later);
		kfree(p);
	}
	rcu_pointers_to_free = NULL;
}

void rcu_read_lock(void)
{
	atomic_inc(&rcu_counter);
}

void rcu_read_unlock(void)
{
	KIRQL flags;

	spin_lock_irqsave(&rcu_lock, flags);
	if (atomic_dec_return(&rcu_counter) == 0) {
		wake_up(&nobody_in_rcu_read_lock);
		free_all_rcu_heads();
		free_all_rcu_pointers();
	}
	spin_unlock_irqrestore(&rcu_lock, flags);
}

void synchronize_rcu(void)
{
	wait_event(nobody_in_rcu_read_lock, atomic_read(&rcu_counter) == 0);
}

void call_rcu(struct rcu_head *head, rcu_callback_t func)
{
	KIRQL flags;
	head->func = func;

	spin_lock_irqsave(&rcu_lock, flags);
	head->next = rcu_heads;
	rcu_heads = head;
	spin_unlock_irqrestore(&rcu_lock, flags);
}

void kfree_when_rcu_in_sync(void *p)
{
	KIRQL flags;
	struct rcu_pointer *new;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (new == NULL) {
		printk("Warning: could not kfree_when_rcu_in_sync(): out of memory.\n");
		return;
	}
	new->free_me_later = p;

	spin_lock_irqsave(&rcu_lock, flags);
	new->next = rcu_pointers_to_free;
	rcu_pointers_to_free = new;
	spin_unlock_irqrestore(&rcu_lock, flags);
}

static spinlock_t irq_lock;

void local_irq_disable()
{
	KIRQL hopefully_passive;

	KeAcquireSpinLock(&irq_lock.spinLock, &hopefully_passive);
	if (hopefully_passive != PASSIVE_LEVEL)
		printk("Bug: IRQL not passive before local_irq_disable().\n");
}

void local_irq_enable()
{
	KeReleaseSpinLock(&irq_lock.spinLock, PASSIVE_LEVEL);
}

/* see DRBD ratelimit implementation */

int spin_trylock(spinlock_t *lock)
{
		/* TODO: broken here. Use an extra spinlock. */
	if (KeTestSpinLock(&lock->spinLock) == FALSE)
		return 0;

	spin_lock(lock);
	return 1;
}

void init_locking(void)
{
#if 0
#ifndef CONFIG_HAVE_RW_LOCKS
	spin_lock_init(&rcu_spin_lock);
#else
        rcu_rw_lock = 0;
#endif
#endif

	atomic_set(&rcu_counter, 0);
	init_waitqueue_head(&nobody_in_rcu_read_lock);
	rcu_heads = NULL;
	spin_lock_init(&rcu_lock);

	spin_lock_init(&irq_lock);
}

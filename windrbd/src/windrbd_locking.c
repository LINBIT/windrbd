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
	return down_trylock(&sem->the_semaphore);
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

// #if (NTDDI_VERSION < NTDDI_VISTASP1)
#ifndef CONFIG_HAVE_RW_LOCKS
static spinlock_t rcu_spin_lock;
#else
static EX_SPIN_LOCK rcu_rw_lock;
#endif

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

/* This does not change the IRQL. In particular if IRQL is
 * at PASSIVE_LEVEL it stays at PASSIVE_LEVEL which means
 * that the critical section may be preempted. Again,
 * use spin_lock_irqsave/spin_unlock_irqrestore whereever
 * possible.
 *
 * TODO: these functions are deprecated and should go away.
 */

void spin_lock(spinlock_t *lock)
{
	KeAcquireSpinLockAtDpcLevel(&lock->spinLock);
}

void spin_unlock(spinlock_t *lock)
{
	KeReleaseSpinLockFromDpcLevel(&lock->spinLock);
}

void spin_lock_nested(spinlock_t *lock, int level)
{
	KeAcquireSpinLockAtDpcLevel(&lock->spinLock);
}

#ifndef CONFIG_HAVE_RW_LOCKS
// #if (NTDDI_VERSION < NTDDI_VISTASP1)

	/* Still need deadlock detection, since rcu_read_lock maybe
	 * held while calling synchronize_rcu. Windows before Vista
	 * Service pack 1 didn't have read/write locks, use plain old
	 * spinlocks instead ... only difference is that rcu_read_locks()
	 * are slower.
	 */

KIRQL rcu_read_lock(void)
{
	KIRQL flags;
	struct task_struct *c;

	c = current;
	if (is_windrbd_thread(c)) {
		if (atomic_inc_return(&c->rcu_recursion_depth) > 1)
			return KeGetCurrentIrql();

		c->in_rcu = 1;
	}

	spin_lock_irqsave(&rcu_spin_lock, flags);
	return flags;
}

void rcu_read_unlock(KIRQL rcu_flags)
{
	struct task_struct *c;

	c = current;
	if (is_windrbd_thread(c)) {
		if (atomic_dec_return(&c->rcu_recursion_depth) > 0)
			return;
	}
	spin_unlock_irqrestore(&rcu_spin_lock, rcu_flags);

	if (is_windrbd_thread(current))
		current->in_rcu = 0;
}

void synchronize_rcu(void)
{
	KIRQL rcu_flags;

	if (is_windrbd_thread(current)) {
		if (current->in_rcu)
			return;	/* avoid deadlock */
	}
	spin_lock_irqsave(&rcu_spin_lock, rcu_flags);
	spin_unlock_irqrestore(&rcu_spin_lock, rcu_flags);
}

void call_rcu(struct rcu_head *head, rcu_callback_t func)
{
	KIRQL rcu_flags = PASSIVE_LEVEL;
	int can_lock = 1;

	if (is_windrbd_thread(current)) {
		if (current->in_rcu)
			can_lock = 0;
	}
	if (can_lock)
		spin_lock_irqsave(&rcu_spin_lock, rcu_flags);

	func(head);

	if (can_lock)
		spin_unlock_irqrestore(&rcu_spin_lock, rcu_flags);
}

#else

	/* Still need deadlock detection, since rcu_read_lock maybe
	 * held while calling synchronize_rcu
	 */

KIRQL rcu_read_lock(void)
{
	KIRQL flags;
	struct task_struct *c;
	
	c = current;
	if (is_windrbd_thread(c)) {
		if (atomic_inc_return(&c->rcu_recursion_depth) > 1)
			return KeGetCurrentIrql();

		c->in_rcu = 1;
	}

	flags = ExAcquireSpinLockShared(&rcu_rw_lock);
	return flags;
}

void rcu_read_unlock(KIRQL rcu_flags)
{
	struct task_struct *c;

	c = current;
	if (is_windrbd_thread(c)) {
		if (atomic_dec_return(&c->rcu_recursion_depth) > 0)
			return;
	}

	ExReleaseSpinLockShared(&rcu_rw_lock, rcu_flags);

	if (is_windrbd_thread(current))
		current->in_rcu = 0;
}

void synchronize_rcu(void)
{
	KIRQL rcu_flags;

	if (is_windrbd_thread(current)) {
		if (current->in_rcu)
			return;	/* avoid deadlock */
	}	
	rcu_flags = ExAcquireSpinLockExclusive(&rcu_rw_lock);
	/* compiler barrier */
	ExReleaseSpinLockExclusive(&rcu_rw_lock, rcu_flags);
}

void call_rcu(struct rcu_head *head, rcu_callback_t func)
{
	KIRQL rcu_flags = PASSIVE_LEVEL;
	int can_lock = 1;

	if (is_windrbd_thread(current)) {
		if (current->in_rcu)
			can_lock = 0;
	}
	if (can_lock)
		rcu_flags = ExAcquireSpinLockExclusive(&rcu_rw_lock);

	func(head);

	if (can_lock)
		ExReleaseSpinLockExclusive(&rcu_rw_lock, rcu_flags);
}

#endif  /* < NTDDI_VISTASP1 */

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
	if (KeTestSpinLock(&lock->spinLock) == FALSE)
		return 0;

	spin_lock(lock);
	return 1;
}

void init_locking(void)
{
#ifndef CONFIG_HAVE_RW_LOCKS
	spin_lock_init(&rcu_spin_lock);
#else
        rcu_rw_lock = 0;
#endif
	spin_lock_init(&irq_lock);
}

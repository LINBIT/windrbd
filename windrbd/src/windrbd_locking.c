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

#include "drbd_windows.h"
#include "windrbd_device.h"
#include "windrbd_threads.h"
#include <wdm.h>

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
enter_interruptible();	
	status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
exit_interruptible();	

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
#ifdef SPIN_LOCK_DEBUG2
	lock->locked_by_thread = NULL;
	strncpy(lock->marker, "SPIN_LOCK123", ARRAY_SIZE(lock->marker)-1);
	strncpy(lock->locked_by, "NONE", ARRAY_SIZE(lock->locked_by)-1);
	lock->timestamp_taken.QuadPart = 0;
#endif
}

static EX_SPIN_LOCK rcu_rw_lock;

	/* TODO: this whole spin_lock_debug thing is broken, remove that
	 * code. We haven't had any system lockup ever since we fixed
	 * it by using only spin_lock_irqsave / spin_unlock_irqrestore.
	 * (other spin lock calls are not supported in Windows). Also
	 * fixing the wake_up call in windrbd_waitqueue.c helped a lot.
	 */

#if 0

#define DESC_SIZE 256
#define FUNC_SIZE 256

struct spin_lock_currently_held {
	struct list_head list;
	spinlock_t *lock;	/* NULL meaning the RCU lock (which is a rw_lock) */
	ULONG_PTR when;
	struct task_struct *thread;
	atomic_t id;
	int seen;

	char marker[16];
	char taken[16];
	char desc[DESC_SIZE];
	char func[FUNC_SIZE];
	char thread_comm[TASK_COMM_LEN+1];
	char irq_level[16];
	char id_ascii[16];
};

static LIST_HEAD(spin_locks_currently_held);
static atomic_t spinlock_cnt;
static KSPIN_LOCK spinlock_lock;
static int run_spinlock_monitor;

static struct spin_lock_currently_held *add_spinlock(spinlock_t *lock, const char *file, int line, const char *func)
{
	KIRQL oldIrql;
	struct spin_lock_currently_held *s;

	if (lock && lock->printk_lock)
		return NULL;

	s = kmalloc(sizeof(*s), GFP_KERNEL, 'DRBD');
	if (s == NULL)
		return NULL;

	s->lock = lock;
	s->when = jiffies;
	s->thread = current;
	s->id = atomic_inc_return(&spinlock_cnt);
	s->seen = 0;

		/* TODO: snprintf implementation currently broken, be
		 * careful with that
		 */

/*
	strncpy(s->desc, file, sizeof(s->desc)-1);
	strncpy(s->func, func, sizeof(s->func)-1);
*/

	snprintf(s->desc, ARRAY_SIZE(s->desc), "%s:%d", file, line);
	snprintf(s->func, ARRAY_SIZE(s->func), "%s", func);
	strcpy(s->marker, "SPINLOCK");
	strncpy(s->thread_comm, current->comm, ARRAY_SIZE(s->thread_comm)-1);
	snprintf(s->id_ascii, ARRAY_SIZE(s->id_ascii), "%d", s->id);
	strcpy(s->taken, "NOTTAKEN");
	snprintf(s->irq_level, ARRAY_SIZE(s->irq_level), "IRQL%d", KeGetCurrentIrql());

	KeAcquireSpinLock(&spinlock_lock, &oldIrql);
	list_add(&s->list, &spin_locks_currently_held);
	KeReleaseSpinLock(&spinlock_lock, oldIrql);

	return s;
}

static void remove_spinlock(spinlock_t *lock)
{
	KIRQL oldIrql;
	struct list_head *sh, *shh;
	struct spin_lock_currently_held *s;
	int n = 0;
	static int spinlock_id;

	if (lock && lock->printk_lock)
		return;

	KeAcquireSpinLock(&spinlock_lock, &oldIrql);
	list_for_each_safe(sh, shh, &spin_locks_currently_held) {
		s = list_entry(sh, struct spin_lock_currently_held, list);
		if (s->lock == lock) {
			snprintf(s->marker, ARRAY_SIZE(s->marker), "NOSPINLO%d", spinlock_id++);
			list_del(&s->list);
			kfree(s);
			n++;
		}
	}
	KeReleaseSpinLock(&spinlock_lock, oldIrql);

/*
	if (n>1)
		printk("spinlock_debug: Warning: spinlock %p was %d times on the list\n", lock, n);
*/
}

	/* TODO: run this at very high priority (interrupt) */

static void see_spinlocks(void)
{
	struct spin_lock_currently_held *s;
	KIRQL oldIrql;

	KeAcquireSpinLock(&spinlock_lock, &oldIrql);
	list_for_each_entry(struct spin_lock_currently_held, s, &spin_locks_currently_held, list) {
		s->seen++;

		if (s->seen > 1) {
			printk("spinlock_debug: Warning: spinlock %p locked since %ld (now is %ld), this is probably too long (seen %d times). Taken at %s (%s())\n", s->lock, s->when, jiffies, s->seen, s->desc, s->func);
//			printk("spinlock_debug: (thread is %s)\n", s->thread->comm);
		}
	}
	KeReleaseSpinLock(&spinlock_lock, oldIrql);
}

static int see_all_spinlocks_thread(void *unused)
{
	while (run_spinlock_monitor) {
		msleep(100);
		see_spinlocks();
	}
	return 0;
}

static int bad_spinlock_test_thread(void *unused)
{
	spinlock_t lock;
	ULONG_PTR now;

	now = jiffies;
	spin_lock_init(&lock);
	spin_lock(&lock);

	while (jiffies < now+HZ*5) ;

	spin_unlock(&lock);

	return 0;
}

int spinlock_debug_init(void)
{
/*
	run_spinlock_monitor = 1;
	if (kthread_run(see_all_spinlocks_thread, NULL, "spinlock_debug") == NULL) {
		printk("Warning: could not start spinlock monitor\n");
		return -1;
	}
	if (kthread_run(bad_spinlock_test_thread, NULL, "spinlock_test") == NULL) {
		printk("Warning: could not start spinlock test\n");
		return -1;
	}
*/
	return 0;
}

int spinlock_debug_shutdown(void)
{
	run_spinlock_monitor = 0;

	return 0;
}

/* See also defintion of spin_lock_irqsave in drbd_windows.h for handling
 * the flags parameter.
 */

KIRQL _spin_lock_irqsave_debug(spinlock_t *lock, const char *file, int line, const char *func)
{
	KIRQL oldIrql;
	struct spin_lock_currently_held *s;

	s = add_spinlock(lock, file, line, func);
	KeAcquireSpinLock(&lock->spinLock, &oldIrql);
	if (s)
		strcpy(s->taken, "TAKEN");

	return oldIrql;
}

void spin_unlock_irqrestore_debug(spinlock_t *lock, long flags, const char *file, int line, const char *func)
{
	KeReleaseSpinLock(&lock->spinLock, (KIRQL) flags);
	if (!lock->printk_lock)
		remove_spinlock(lock);
}

void spin_lock_irq_debug(spinlock_t *lock, const char *file, int line, const char *func)
{
	KIRQL unused;
	struct spin_lock_currently_held *s;
/*
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		printk("spin lock bug: KeGetCurrentIrql() is %d (called from %s:%d in %s()\n", KeGetCurrentIrql(), file, line, func);
*/

	s = add_spinlock(lock, file, line, func);
	KeAcquireSpinLock(&lock->spinLock, &unused);
	if (s)
		strcpy(s->taken, "TAKEN");
}

void spin_unlock_irq_debug(spinlock_t *lock, const char *file, int line, const char *func)
{
	KeReleaseSpinLock(&lock->spinLock, PASSIVE_LEVEL);
	remove_spinlock(lock);
}

void spin_lock_debug(spinlock_t *lock, const char *file, int line, const char *func)
{
	spin_lock_irq_debug(lock, file, line, func);
		/* Using this caused deadlock on Windows Server 2016? */
		/* No, it was something else (bug also in 0.9.1) */
		/* TODO: use this: */
	/* KeAcquireSpinLockAtDpcLevel(&lock->spinLock); */
}

void spin_unlock_debug(spinlock_t *lock, const char *file, int line, const char *func)
{
	spin_unlock_irq_debug(lock, file, line, func);
	/* KeReleaseSpinLockFromDpcLevel(&lock->spinLock); */
}

void spin_lock_bh_debug(spinlock_t *lock, const char *file, int line, const char *func)
{
	spin_lock_irq_debug(lock, file, line, func);
}

void spin_unlock_bh_debug(spinlock_t *lock, const char *file, int line, const char *func)
{
	spin_unlock_irq_debug(lock, file, line, func);
}

KIRQL rcu_read_lock_debug(const char *file, int line, const char *func)
{
	KIRQL flags;
	struct spin_lock_currently_held *s;

	s = add_spinlock(NULL, file, line, func);
	flags = ExAcquireSpinLockShared(&rcu_rw_lock);
	if (s)
		strcpy(s->taken, "TAKEN");
	return flags;
}

void rcu_read_unlock_debug(KIRQL rcu_flags, const char *file, int line, const char *func)
{
	ExReleaseSpinLockShared(&rcu_rw_lock, rcu_flags);
	remove_spinlock(NULL);
}

void synchronize_rcu_debug(const char *file, int line, const char *func)
{
	KIRQL rcu_flags;
	struct spin_lock_currently_held *s;

	s = add_spinlock(NULL, file, line, func);
	rcu_flags = ExAcquireSpinLockExclusive(&rcu_rw_lock);
	if (s)
		strcpy(s->taken, "TAKEN");
	/* compiler barrier */
	ExReleaseSpinLockExclusive(&rcu_rw_lock, rcu_flags);
	remove_spinlock(NULL);
}

void call_rcu_debug(struct rcu_head *head, rcu_callback_t f, const char *file, int line, const char *func)
{
	KIRQL rcu_flags;
	struct spin_lock_currently_held *s;

	s = add_spinlock(NULL, file, line, func);
	rcu_flags = ExAcquireSpinLockExclusive(&rcu_rw_lock);
	if (s)
		strcpy(s->taken, "TAKEN");
	f(head);
	ExReleaseSpinLockExclusive(&rcu_rw_lock, rcu_flags);
	remove_spinlock(NULL);
}

#else

/* See also defintion of spin_lock_irqsave in linux/spinlock.h for handling
 * the flags parameter.
 */

KIRQL spin_lock_irqsave_debug_new(spinlock_t *lock, const char *file, int line, const char *func)
{
	KIRQL oldIrql;

#ifdef SPIN_LOCK_DEBUG2
		/* this introduces about 1000 more races, but is here just
		 * for debugging purposes.
		 */
	if (!lock->printk_lock && lock->locked_by_thread == KeGetCurrentThread()) {
		printk("Warning: Spin lock recursion detected at %s:%d (%s()), first called at %s current IRQL is %d\n", file, line, func, lock->locked_by, KeGetCurrentIrql());

			/* From here on, everything may happen */
		return KeGetCurrentIrql();
	}
	lock->timestamp_taken = KeQueryPerformanceCounter(NULL);
#endif

	KeAcquireSpinLock(&lock->spinLock, &oldIrql);

#ifdef SPIN_LOCK_DEBUG2
	lock->locked_by_thread = KeGetCurrentThread();
	strncpy(lock->marker, "SPIN_LOCK456", ARRAY_SIZE(lock->marker)-1);
	snprintf(lock->locked_by, ARRAY_SIZE(lock->locked_by)-1, "%s:%d (%s())", file, line, func);
	lock->locked_by[ARRAY_SIZE(lock->locked_by)-1] = '\0';
#endif

	return oldIrql;
}

void spin_unlock_irqrestore(spinlock_t *lock, KIRQL flags)
{
#ifdef SPIN_LOCK_DEBUG2
	LARGE_INTEGER now;

	now = KeQueryPerformanceCounter(NULL);
	if (!lock->printk_lock && lock->timestamp_taken.QuadPart != 0 && (now.QuadPart - lock->timestamp_taken.QuadPart) > 10*1000*1000/10000)
		printk("Warning: %s held spinlock longer than 100usecs locked by %s locktime is %lld\n", current->comm, lock->locked_by, (now.QuadPart - lock->timestamp_taken.QuadPart));

	lock->locked_by_thread = NULL;
	strncpy(lock->marker, "SPIN_LOCK123", ARRAY_SIZE(lock->marker)-1);
	strncpy(lock->locked_by, "NONE", ARRAY_SIZE(lock->locked_by)-1);
#endif

	KeReleaseSpinLock(&lock->spinLock, flags);
}

#if 0

// void spin_lock_irq(spinlock_t *lock)
void spin_lock_irq_debug_new(spinlock_t *lock, const char *file, int line, const char *func)
{
	KIRQL unused;

#ifdef SPIN_LOCK_DEBUG2

//  printk("Warning: deprecated function spin_lock_irq_debug_new called by %s:%d %s()\n", file, line, func);

		/* this introduces about 1000 more races, but is here just
		 * for debugging purposes.
		 */
	if (!lock->printk_lock && lock->locked_by_thread == KeGetCurrentThread()) {
		printk("Warning: Spin lock recursion detected at %s:%d (%s()), first called at %s current IRQL is %d\n", file, line, func, lock->locked_by, KeGetCurrentIrql());

			/* From here on, everything may happen */
		return;
	}
#endif
	KeAcquireSpinLock(&lock->spinLock, &unused);

#ifdef SPIN_LOCK_DEBUG2
	lock->locked_by_thread = KeGetCurrentThread();
	strncpy(lock->marker, "SPIN_LOCK456", ARRAY_SIZE(lock->marker)-1);
	snprintf(lock->locked_by, ARRAY_SIZE(lock->locked_by)-1, "%s:%d (%s())", file, line, func);
	lock->locked_by[ARRAY_SIZE(lock->locked_by)-1] = '\0';

		/* TODO: remove this check again later */
	if (unused != PASSIVE_LEVEL)
		printk("Bug: IRQL > PASSIVE_LEVEL (is %d) at %s:%d (%s)\n", unused, file, line, func);
/*	else
		printk("IRQL is PASSIVE_LEVEL (%d), no bug at %s:%d (%s)\n", unused, file, line, func); */
#endif
}

/* This resets the IRQL to PASSIVE_LEVEL. This is normally not
 * what you want. Use spin_lock_irqsave/spin_unlock_irqrestore
 * whereever possible.
 */

void spin_unlock_irq(spinlock_t *lock)
{
#ifdef SPIN_LOCK_DEBUG2
// printk("Warning: deprecated function spin_lock_unirq_debug_new called\n");

	lock->locked_by_thread = NULL;
	strncpy(lock->locked_by, "NONE", ARRAY_SIZE(lock->locked_by)-1);
	strncpy(lock->marker, "SPIN_LOCK123", ARRAY_SIZE(lock->marker)-1);
#endif
	KeReleaseSpinLock(&lock->spinLock, PASSIVE_LEVEL);
}

#endif

/* This does not change the IRQL. In particular if IRQL is
 * at PASSIVE_LEVEL it stays at PASSIVE_LEVEL which means
 * that the critical section may be preempted. Again,
 * use spin_lock_irqsave/spin_unlock_irqrestore whereever
 * possible.
 *
 * TODO: these functions are deprecated and should go away.
 */

static void spin_lock(spinlock_t *lock)
{
#ifdef SPIN_LOCK_DEBUG2
// if (!lock->printk_lock)
// printk("Warning: deprecated function spin_lock called\n");
#endif

	KeAcquireSpinLockAtDpcLevel(&lock->spinLock);
}

void spin_unlock(spinlock_t *lock)
{
#ifdef SPIN_LOCK_DEBUG2
// if (!lock->printk_lock)
// printk("Warning: deprecated function spin_unlock called\n");
#endif

	KeReleaseSpinLockFromDpcLevel(&lock->spinLock);
}

void spin_lock_nested(spinlock_t *lock, int level)
{
#ifdef SPIN_LOCK_DEBUG2
// if (!lock->printk_lock)
// printk("Warning: deprecated function spin_lock_nested called\n");
#endif

	KeAcquireSpinLockAtDpcLevel(&lock->spinLock);
}

#ifdef RCU_DEBUG

KIRQL rcu_read_lock_debug(const char *file, int line, const char *func)
{
	KIRQL flags;
	struct task_struct *c;
	
	c = current;
	if (is_windrbd_thread(c)) {
		if (atomic_inc_return(&c->rcu_recursion_depth) > 1) {
			printk("RCU read lock recursion detected (from %s:%d %s()), doing nothing.\n", file, line, func);
			return KeGetCurrentIrql();
		}
		c->in_rcu = 1;
		c->rcu_file = file;
		c->rcu_line = line;
		c->rcu_func = func;
	} else {
		printk("RCU read lock called from non-WinDRBD thread (from %s:%d %s())\n", file, line, func);
	}

	printk("called from %s:%d (%s())\n", file, line, func);
	flags = ExAcquireSpinLockShared(&rcu_rw_lock);
	return flags;
}

void rcu_read_unlock_debug(KIRQL rcu_flags, const char *file, int line, const char *func)
{
	struct task_struct *c;

	c = current;
	if (is_windrbd_thread(c)) {
		if (atomic_dec_return(&c->rcu_recursion_depth) > 0) {
			printk("RCU read lock recursion detected (from %s:%d %s()), doing nothing.\n", file, line, func);
			return;
		}
	} else {
		printk("RCU read lock called from non-WinDRBD thread (from %s:%d %s())\n", file, line, func);
	}
	ExReleaseSpinLockShared(&rcu_rw_lock, rcu_flags);

	printk("called from %s:%d (%s())\n", file, line, func);
	if (is_windrbd_thread(current))
		current->in_rcu = 0;
}

extern void print_threads_in_rcu(void);

void synchronize_rcu_debug(const char *file, int line, const char *func)
{
	KIRQL rcu_flags;
	struct task_struct *c;

	print_threads_in_rcu();

	c = current;
	if (is_windrbd_thread(c)) {
		if (c->in_rcu) {
			printk("Warning: RCU syncronize called (from %s:%d %s()) while thread is holding rcu_readlock (called from %s:%d %s())\n", file, line, func, c->rcu_file, c->rcu_line, c->rcu_func);
			return;	/* avoid deadlock */
		}
	}	
	printk("called from %s:%d (%s())\n", file, line, func);
	rcu_flags = ExAcquireSpinLockExclusive(&rcu_rw_lock);
	/* compiler barrier */
	ExReleaseSpinLockExclusive(&rcu_rw_lock, rcu_flags);
	printk("after locks from %s:%d (%s())\n", file, line, func);
}

void call_rcu_debug(struct rcu_head *head, rcu_callback_t callback_func, const char *file, int line, const char *func)
{
	KIRQL rcu_flags = PASSIVE_LEVEL;
	int can_lock = 1;
	struct task_struct *c = current;

	if (is_windrbd_thread(c)) {
		if (c->in_rcu) {
			printk("Warning: RCU call_rcu called (from %s:%d %s()) while thread is holding rcu_readlock (called from %s:%d %s())\n", file, line, func, c->rcu_file, c->rcu_line, c->rcu_func);
			can_lock = 0;
		}
	}
	printk("called from %s:%d (%s())\n", file, line, func);
	if (can_lock)
		rcu_flags = ExAcquireSpinLockExclusive(&rcu_rw_lock);

	callback_func(head);

	if (can_lock)
		ExReleaseSpinLockExclusive(&rcu_rw_lock, rcu_flags);

	printk("after locks from %s:%d (%s())\n", file, line, func);
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

#endif	/* RCU_DEBUG */

#endif

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
        rcu_rw_lock = 0;
	spin_lock_init(&irq_lock);
}

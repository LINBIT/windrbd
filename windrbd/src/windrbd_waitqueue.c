#ifdef RELEASE
#ifdef DEBUG
#undef DEBUG
#endif
#endif

#include "drbd_windows.h"
#include "windrbd_threads.h"

/* TODO: for debugging purposes, record which processes currently
 * are waiting and have ioctl for printing those .. much like
 * spinlock_debug()
 */

	/* Timeout is in jiffies (usually 1ms on WinDRBD)
         * Returns -EINTR, -ETIMEOUT or 0
	 */

int raised_irql_waits;

static int ll_wait(struct wait_queue_entry *e, LONG_PTR timeout, int interruptible, const char *file, int line, const char *func)
{
	LARGE_INTEGER wait_time;
	LARGE_INTEGER *wait_time_p;
	NTSTATUS status;
	int num_wait_objects = 0;
	PVOID wait_objects[2] = {0};
	struct task_struct *thread = current;

#if 0
	/* Busy looping .. to see where it hangs */
if (timeout > 30000) timeout = 30000;
#endif

	if(timeout != MAX_SCHEDULE_TIMEOUT) {
		wait_time.QuadPart = timeout * (-1 * 1000 * 1000 * 10 / HZ);
		wait_time_p = &wait_time;
	}
	else
		wait_time_p = NULL;

	if (e) {
		wait_objects[num_wait_objects] = (void *) &e->windows_event;
		num_wait_objects++;
	}
	if (thread->has_sig_event && interruptible == TASK_INTERRUPTIBLE) {
		wait_objects[num_wait_objects] = (PVOID) &thread->sig_event;
		num_wait_objects++;
	}

	if (num_wait_objects == 0 && wait_time_p == NULL) {
		printk("Warning: Refusing to wait forever on no objects\n");
		return -EINVAL;
	}
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
		printk("Warning: Attempt to schedule at IRQL %d will not sleep (called from %s:%d (%s())\n", KeGetCurrentIrql(), file, line, func);
		raised_irql_waits++;
		return -EINVAL;
	}

		/* KeWaitForMultipleObjects BSODs when num_wait_objects is
		 * 0 (on schedule_timeout_uninterruptible() for example).
		 * So do a simple msleep() like wait.
		 */

enter_interruptible_debug(file, line, func);
	if (num_wait_objects == 0)
		status = KeDelayExecutionThread(KernelMode, FALSE, wait_time_p);
	else
		status = KeWaitForMultipleObjects(num_wait_objects, &wait_objects[0], WaitAny, Executive, KernelMode, FALSE, wait_time_p, NULL);
exit_interruptible_debug(file, line, func);

	if (!NT_SUCCESS(status)) {
		printk("Warning: KeWaitForMultipleObjects returned with status %x\n", status);
		return -EINVAL;
	}

	switch (status) {
	case STATUS_WAIT_0:
		if (e) return 0;	/* fallthrough */
	case STATUS_WAIT_1:
		return -EINTR;		/* TODO: -ERESTARTSYS */
	case STATUS_TIMEOUT:
// printk("TIMED OUT after %d milliseconds (%s:%d %s()) wait queue entry is %p\n", timeout, file, line, func, e);
		return -ETIMEDOUT;
	}
	return 0;	/* TODO: -EINVAL or some other error */
}

void schedule_debug(const char *file, int line, const char *func)
{
	if (!is_windrbd_thread(current))
		printk("Warning: schedule called from a non WinDRBD thread\n");

	ll_wait(current->wait_queue_entry, MAX_SCHEDULE_TIMEOUT, TASK_INTERRUPTIBLE, file, line, func);
}

static LONG_PTR ll_schedule_debug(LONG_PTR timeout, int return_error, int interruptible, const char *file, int line, const char *func)
{
	LONG_PTR then = jiffies;
	LONG_PTR elapsed;
	int err;

	if (!is_windrbd_thread(current)) {
		printk("Warning: schedule called from a non WinDRBD thread, not waiting\n");
		return -EINVAL;
	}

	err = ll_wait(current->wait_queue_entry, timeout, interruptible, file, line, func);

	if (err < 0 && return_error)
		return err;

	if (timeout == MAX_SCHEDULE_TIMEOUT)
		return MAX_SCHEDULE_TIMEOUT;

	elapsed = jiffies - then;
	if ((timeout - elapsed) > 0)
		return timeout - elapsed;
	return 0;
}

LONG_PTR schedule_timeout_debug(LONG_PTR timeout, const char *file, int line, const char *func)
{
	return ll_schedule_debug(timeout, 0, TASK_INTERRUPTIBLE, file, line, func);
}

LONG_PTR schedule_timeout_maybe_interrupted_debug(LONG_PTR timeout, const char *file, int line, const char *func)
{
	return ll_schedule_debug(timeout, 1, TASK_INTERRUPTIBLE, file, line, func);
}

LONG_PTR schedule_timeout_uninterruptible_debug(LONG_PTR timeout, const char *file, int line, const char *func)
{
	return ll_schedule_debug(timeout, 0, TASK_UNINTERRUPTIBLE, file, line, func);
}

	/* TODO: no locks? Assumes that current is always (1) valid and
	 * (2) unique.
	 */

void prepare_to_wait(struct wait_queue_head *w, struct wait_queue_entry *e, int interruptible)
{
	KIRQL flags;
	struct task_struct *thread = current;

	spin_lock_irqsave(&w->lock, flags);
	thread->interruptible = interruptible;
	thread->wait_queue = w;
	thread->wait_queue_entry = e;

printk("1 w is %p entry is %p\n", w, e);
	if (list_empty(&e->entry)) {
printk("2\n");
		list_add(&e->entry, &w->head);
	}
printk("3\n");
	spin_unlock_irqrestore(&w->lock, flags);
}

void finish_wait(struct wait_queue_head *w, struct wait_queue_entry *e)
{
	KIRQL flags;
	struct task_struct *thread = current;

	spin_lock_irqsave(&w->lock, flags);

	thread->wait_queue = NULL;
	thread->wait_queue_entry = NULL;

printk("1 w is %p entry is %p\n", w, e);
	if (!list_empty(&e->entry)) {
printk("2\n");
		list_del(&e->entry);
		INIT_LIST_HEAD(&e->entry);
	}
printk("3\n");
	spin_unlock_irqrestore(&w->lock, flags);
}

static spinlock_t big_wakeup_lock;

void wake_up_all_debug(wait_queue_head_t *q, const char *file, int line, const char *func)
{
	KIRQL flags, flags2;
	struct wait_queue_entry *e, *e2;

printk("wake_up_all %p %s:%d (%s())\n", q, file, line, func);
	spin_lock_irqsave(&q->lock, flags);
	spin_lock_irqsave(&big_wakeup_lock, flags2);
	if (list_empty(&q->head)) {
printk("Warning: attempt to wake up all with no one waiting (%s:%d %s()) queue is %p.\n", file, line, func, q);
		goto unlock_and_out;
	}
		/* Use safe version: entries might get deleted soon by
		 * woken up waiters.
		 */

printk("1\n");
	list_for_each_entry_safe(struct wait_queue_entry, e, e2, &q->head, entry) {
printk("2 entry is at %p\n", e);
		KeSetEvent(&e->windows_event, 0, FALSE);
printk("2a\n");
	}
printk("3\n");

unlock_and_out:
printk("4\n");
	spin_unlock_irqrestore(&big_wakeup_lock, flags2);
printk("5\n");
	spin_unlock_irqrestore(&q->lock, flags);
printk("6\n");
}

	/* This wakes up all non-exclusive tasks. Since we only have
	 * non-exclusive tasks, this does the same as wake_up_all().
	 */

void wake_up_debug(wait_queue_head_t *q, const char *file, int line, const char *func)
{
	wake_up_all_debug(q, file, line, func);
}

void init_waitqueue(void)
{
	spin_lock_init(&big_wakeup_lock);
}

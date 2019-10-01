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


static int ll_wait(struct wait_queue_entry *e, ULONG_PTR timeout, int interruptible, const char *file, int line, const char *func)
{
	LARGE_INTEGER wait_time;
	LARGE_INTEGER *wait_time_p;
	NTSTATUS status;
	int num_wait_objects = 0;
	PVOID wait_objects[2] = {0};
	struct task_struct *thread = current;

	/* Busy looping .. to see where it hangs */
if (timeout > 5000) timeout = 5000;

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
		printk("Warning: Attempt to schedule at IRQL %d will not sleep\n", KeGetCurrentIrql());
		return -EINVAL;
	}

#if 0
if (line != 48)	/* silence drbd_md_get_buffer */
printk("into KeWaitForMultipleObjects from %s:%d (%s()) timeout is %d\n", file, line, func, timeout);
#endif

		/* KeWaitForMultipleObjects BSODs when num_wait_objects is
		 * 0 (on schedule_timeout_uninterruptible() for example).
		 * So do a simple msleep() like wait.
		 */

	if (num_wait_objects == 0)
		status = KeDelayExecutionThread(KernelMode, FALSE, wait_time_p);
	else
		status = KeWaitForMultipleObjects(num_wait_objects, &wait_objects[0], WaitAny, Executive, KernelMode, FALSE, wait_time_p, NULL);

#if 0
if (line != 48)	/* silence drbd_md_get_buffer */
printk("out of KeWaitForMultipleObjects from %s:%d (%s()) stastus is %x\n", file, line, func, status);
#endif

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

static LONG_PTR ll_schedule_debug(ULONG_PTR timeout, int return_error, int interruptible, const char *file, int line, const char *func)
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

ULONG_PTR schedule_timeout_debug(ULONG_PTR timeout, const char *file, int line, const char *func)
{
	return ll_schedule_debug(timeout, 0, TASK_INTERRUPTIBLE, file, line, func);
}

LONG_PTR schedule_timeout_maybe_interrupted_debug(ULONG_PTR timeout, const char *file, int line, const char *func)
{
	return ll_schedule_debug(timeout, 1, TASK_INTERRUPTIBLE, file, line, func);
}

LONG_PTR schedule_timeout_uninterruptible_debug(ULONG_PTR timeout, const char *file, int line, const char *func)
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

	if (list_empty(&e->entry))
		list_add(&e->entry, &w->head);
	spin_unlock_irqrestore(&w->lock, flags);
}

void finish_wait(struct wait_queue_head *w, struct wait_queue_entry *e)
{
	KIRQL flags;
	struct task_struct *thread = current;

	spin_lock_irqsave(&w->lock, flags);

	thread->wait_queue = NULL;
	thread->wait_queue_entry = NULL;

	if (!list_empty(&e->entry)) {
		list_del(&e->entry);
		INIT_LIST_HEAD(&e->entry);
	}
	spin_unlock_irqrestore(&w->lock, flags);
}

void wake_up_debug(wait_queue_head_t *q, const char *file, int line, const char *func)
{		
	KIRQL flags;
	dbg("wake_up %p %s:%d (%s())\n", q, file, line, func);
	struct wait_queue_entry *e;

	spin_lock_irqsave(&q->lock, flags);
	if (list_empty(&q->head)) {
		dbg("Warning: attempt to wake up with no one waiting.\n");
		spin_unlock_irqrestore(&q->lock, flags);

		return;
	}
	e = list_first_entry(&q->head, struct wait_queue_entry, entry);
	KeSetEvent(&e->windows_event, 0, FALSE);

	spin_unlock_irqrestore(&q->lock, flags);
}

void wake_up_all_debug(wait_queue_head_t *q, const char *file, int line, const char *func)
{
	KIRQL flags;
	dbg("wake_up_all %p %s:%d (%s())\n", q, file, line, func);
	struct wait_queue_entry *e, *e2;

	spin_lock_irqsave(&q->lock, flags);
	if (list_empty(&q->head)) {
		dbg("Warning: attempt to wake up all with no one waiting.\n");
		spin_unlock_irqrestore(&q->lock, flags);

		return;
	}
		/* Use safe version: entries might get deleted soon by
		 * woken up waiters.
		 */

	list_for_each_entry_safe(struct wait_queue_entry, e, e2, &q->head, entry) {
		KeSetEvent(&e->windows_event, 0, FALSE);
	}

	spin_unlock_irqrestore(&q->lock, flags);
}


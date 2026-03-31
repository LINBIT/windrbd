#ifdef RELEASE
#ifdef DEBUG
#undef DEBUG
#endif
#endif

#include <linux/list.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/jiffies.h>
#include <linux/printk.h>
#include <linux/completion.h>

	/* Timeout is in jiffies (usually 1ms on WinDRBD)
         * Returns -EINTR, -ETIMEOUT or 0
	 */

int raised_irql_waits;

static int ll_wait(void *wait_object, LONG_PTR timeout, int interruptible, const char *file, int line, const char *func)
{
	LARGE_INTEGER wait_time;
	LARGE_INTEGER *wait_time_p;
	NTSTATUS status;
	int num_wait_objects = 0;
	PVOID wait_objects[2] = {0};
	struct task_struct *thread = current;

	if(timeout != MAX_SCHEDULE_TIMEOUT) {
		wait_time.QuadPart = timeout * (-1 * 1000 * 1000 * 10 / HZ);
		wait_time_p = &wait_time;
	}
	else
		wait_time_p = NULL;

	if (wait_object) {
		wait_objects[num_wait_objects] = wait_object;
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

	if (num_wait_objects == 0)
		status = KeDelayExecutionThread(KernelMode, FALSE, wait_time_p);
	else
		status = KeWaitForMultipleObjects(num_wait_objects, &wait_objects[0], WaitAny, Executive, KernelMode, FALSE, wait_time_p, NULL);

	if (!NT_SUCCESS(status)) {
		printk("Warning: KeWaitForMultipleObjects returned with status %x\n", status);
		return -EINVAL;
	}

	switch (status) {
	case STATUS_WAIT_0:
		if (wait_object) return 0;	/* fallthrough */
	case STATUS_WAIT_1:
		return -ERESTARTSYS;
	case STATUS_TIMEOUT:
		return -ETIMEDOUT;
	}
	return 0;	/* TODO: -EINVAL or some other error */
}

void schedule_debug(const char *file, int line, const char *func)
{
	void *wait_object;

	if (!is_windrbd_thread(current))
		printk("Warning: schedule called from a non WinDRBD thread (called from %s:%d %s())\n", file, line, func);

	wait_object = NULL;
	if (current->wait_queue_entry)
		wait_object = &current->wait_queue_entry->windows_event;

	ll_wait(wait_object, MAX_SCHEDULE_TIMEOUT, TASK_INTERRUPTIBLE, file, line, func);
}

LONG_PTR ll_schedule_debug(LONG_PTR timeout, int return_error, int interruptible, const char *file, int line, const char *func)
{
	LONG_PTR then = jiffies;
	LONG_PTR elapsed;
	int err;
	void *wait_object;

	if (!is_windrbd_thread(current)) {
		printk("Warning: schedule called from a non WinDRBD thread, not waiting (called from %s:%d %s())\n", file, line, func);
		return -EINVAL;
	}

	wait_object = NULL;
	if (current->wait_queue_entry)
		wait_object = &current->wait_queue_entry->windows_event;

	err = ll_wait(wait_object, timeout, interruptible, file, line, func);

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

void prepare_to_wait_debug(struct wait_queue_head *w, struct wait_queue_entry *e, int interruptible, const char *file, int line, const char *func)
{
	KIRQL flags;
	struct task_struct *thread = current;

	spin_lock_irqsave(&w->lock, flags);
	thread->interruptible = interruptible;
	thread->wait_queue = w;
	thread->wait_queue_entry = e;

	if (list_empty(&e->entry)) {
		list_add(&e->entry, &w->head);
	}
	spin_unlock_irqrestore(&w->lock, flags);
}

void finish_wait_debug(struct wait_queue_head *w, struct wait_queue_entry *e, const char *file, int line, const char *func)
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

void wake_up_all_debug(wait_queue_head_t *q, const char *file, int line, const char *func)
{
	KIRQL flags;
	struct wait_queue_entry *e, *e2;

	spin_lock_irqsave(&q->lock, flags);
	if (list_empty(&q->head)) {
		goto unlock_and_out;
	}
		/* Use safe version: entries might get deleted soon by
		 * woken up waiters.
		 */

	list_for_each_entry_safe(e, e2, &q->head, entry) {
		KeSetEvent(&e->windows_event, 0, FALSE);
	}

unlock_and_out:
	spin_unlock_irqrestore(&q->lock, flags);
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
}

void init_completion(struct completion *completion)
{
		/* Notification event (stays set - no autoclear) in
		 * case we have more waiters.
		 */

	KeInitializeEvent(&completion->windows_event, NotificationEvent, FALSE);
}

void reinit_completion(struct completion *completion)
{
	init_completion(completion);
}

LONG_PTR wait_for_completion_interruptible_timeout(struct completion *completion, ULONG_PTR timeout)
{
	return ll_wait(&completion->windows_event, timeout, TASK_INTERRUPTIBLE, __FILE__, __LINE__, __func__);
}

ULONG_PTR wait_for_completion_timeout(struct completion *completion, ULONG_PTR timeout)
{
	return ll_wait(&completion->windows_event, timeout, TASK_UNINTERRUPTIBLE, __FILE__, __LINE__, __func__);
}

void wait_for_completion(struct completion *completion)
{
	ll_wait(&completion->windows_event, MAX_SCHEDULE_TIMEOUT, TASK_UNINTERRUPTIBLE, __FILE__, __LINE__, __func__);
}

int wait_for_completion_interruptible(struct completion *completion)
{
	return ll_wait(&completion->windows_event, MAX_SCHEDULE_TIMEOUT, TASK_INTERRUPTIBLE, __FILE__, __LINE__, __func__);
}

void complete(struct completion *c)
{
	KeSetEvent(&c->windows_event, 0, FALSE);
}

void complete_all(struct completion *c)
{
	KeSetEvent(&c->windows_event, 0, FALSE);
}

#include "drbd_windows.h"
#include "windrbd_threads.h"

/* TODO: for debugging purposes, record which processes currently
 * are waiting and have ioctl for printing those .. much like
 * spinlock_debug()
 */

	/* Timeout is in jiffies (usually 1ms on WinDRBD)
         * Returns -EINTR, -ETIMEOUT or 0
	 */


static int ll_wait(wait_queue_head_t *q, ULONG_PTR timeout, int interruptible, const char *file, int line, const char *func)
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

	if (q) {
		wait_objects[num_wait_objects] = (void *) &q->wqh_event;
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

if (line != 48)	/* silence drbd_md_get_buffer */
printk("into KeWaitForMultipleObjects from %s:%d (%s())\n", file, line, func);

	status = KeWaitForMultipleObjects(num_wait_objects, &wait_objects[0], WaitAny, Executive, KernelMode, FALSE, wait_time_p, NULL);

if (line != 48)	/* silence drbd_md_get_buffer */
printk("out of KeWaitForMultipleObjects from %s:%d (%s())\n", file, line, func);

	if (!NT_SUCCESS(status)) {
		printk("Warning: KeWaitForMultipleObjects returned with status %x\n", status);
		return -EINVAL;
	}

	switch (status) {
	case STATUS_WAIT_0:
		if (q) return 0;	/* fallthrough */
	case STATUS_WAIT_1:
		return -EINTR;		/* TODO: -ERESTARTSYS */
	case STATUS_TIMEOUT:
		return -ETIMEDOUT;
	}
	return 0;
}

/* TODO: rename to schedule_debug and have schedule macro */
void new_schedule(const char *file, int line, const char *func)
{
	if (!is_windrbd_thread(current))
		printk("Warning: schedule called from a non WinDRBD thread\n");

	ll_wait(current->wait_queue, MAX_SCHEDULE_TIMEOUT, TASK_INTERRUPTIBLE, file, line, func);
}

LONG_PTR new_schedule_timeout_maybe_with_error_code(ULONG_PTR timeout, int return_error, const char *file, int line, const char *func)
{
	LONG_PTR then = jiffies;
	LONG_PTR elapsed;
	int err;

	if (!is_windrbd_thread(current)) {
		printk("Warning: schedule called from a non WinDRBD thread, not waiting\n");
		return -EINVAL;
	}

	err = ll_wait(current->wait_queue, timeout, TASK_INTERRUPTIBLE, file, line, func);

	if (err < 0 && return_error)
		return err;

	elapsed = jiffies - then;
	if ((timeout - elapsed) > 0)
		return timeout - elapsed;
	return 0;
}

ULONG_PTR new_schedule_timeout(ULONG_PTR timeout, const char *file, int line, const char *func)
{
	return new_schedule_timeout_maybe_with_error_code(timeout, 0, file, line, func);
}

LONG_PTR new_schedule_timeout_maybe_interrupted(ULONG_PTR timeout, const char *file, int line, const char *func)
{
	return new_schedule_timeout_maybe_with_error_code(timeout, 1, file, line, func);
}

	/* TODO: no locks? Assumes that current is always (1) valid and
	 * (2) unique.
	 */

void prepare_to_wait(struct wait_queue_head *w, void *unused, int interruptible)
{
	struct task_struct *thread = current;

	thread->interruptible = interruptible;
	thread->wait_queue = w;
}

void finish_wait(struct wait_queue_head *w, void *unused)
{
	struct task_struct *thread = current;

	thread->wait_queue = NULL;
}

void wake_up_debug(wait_queue_head_t *q, const char *file, int line, const char *func)
{		
printk("wake_up %p %s:%d (%s())\n", q, file, line, func);
	KeSetEvent(&q->wqh_event, 0, FALSE);
}

void wake_up_all(wait_queue_head_t *q)
{
	printk("Warning: wake_up_all called but not implemented yet\n");
	/* Should cause all threads to wake up and check the condition again */
	/* TODO: phil check whether the single-wake-up is wrong? */
	KeSetEvent(&q->wqh_event, 0, FALSE);
}


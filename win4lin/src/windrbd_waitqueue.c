#include "drbd_windows.h"
#include "windrbd_threads.h"

	/* Timeout is in jiffies (usually 1ms on WinDRBD) */

static void ll_wait(wait_queue_head_t *q, ULONG_PTR timeout, int interruptible) 
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
		return;
	}
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
		printk("Warning: Attempt to schedule at IRQL %d will not sleep\n", KeGetCurrentIrql());
		return;
	}
	status = KeWaitForMultipleObjects(num_wait_objects, &wait_objects[0], WaitAny, Executive, KernelMode, FALSE, wait_time_p, NULL);

	if (!NT_SUCCESS(status))
		printk("Warning: KeWaitForMultipleObjects returned with status %x\n", status);
}

void new_schedule(void)
{
	if (!is_windrbd_thread(current))
		printk("Warning: schedule called from a non WinDRBD thread\n");

	ll_wait(current->wait_queue, MAX_SCHEDULE_TIMEOUT, TASK_INTERRUPTIBLE);
}

ULONG_PTR new_schedule_timeout(ULONG_PTR timeout)
{
	LONG_PTR then = jiffies;
	LONG_PTR elapsed;

	if (!is_windrbd_thread(current))
		printk("Warning: schedule called from a non WinDRBD thread\n");

	ll_wait(current->wait_queue, timeout, TASK_INTERRUPTIBLE);

	elapsed = jiffies - then;
	if ((timeout - elapsed) > 0)
		return timeout - elapsed;
	return 0;
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

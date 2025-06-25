#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/spinlock.h>

struct workqueue_struct *system_wq;

static struct work_struct *get_a_work(struct workqueue_struct *wq)
{
	KIRQL flags;

	struct work_struct *w;
	spin_lock_irqsave(&wq->work_list_lock, flags);

	if (list_empty(&wq->work_list)) {
		spin_unlock_irqrestore(&wq->work_list_lock, flags);
		return NULL;
	}
	w = list_first_entry(&wq->work_list, struct work_struct, work_list);
	list_del_init(&w->work_list);
	w->queue = NULL;
	spin_unlock_irqrestore(&wq->work_list_lock, flags);

	return w;
}

static bool remove_work_from_worklist(struct work_struct *work)
{
	KIRQL flags;

	struct workqueue_struct *wq;
	wq = work->queue;

	if (wq == NULL)
		return false;

	spin_lock_irqsave(&wq->work_list_lock, flags);
	if (list_empty(&work->work_list)) {
		spin_unlock_irqrestore(&wq->work_list_lock, flags);
		return false;
	}
	list_del_init(&work->work_list);
	work->queue = NULL;
	spin_unlock_irqrestore(&wq->work_list_lock, flags);

	return true;
}

void really_destroy_workqueue(struct kref *kref)
{
	struct workqueue_struct *wq = container_of(kref, struct workqueue_struct, kref);

	kfree(wq);
}

void destroy_workqueue(struct workqueue_struct *wq)
{
	int i;

	for (i=0;i<wq->num_threads;i++)
		force_sig(wq->threads[i], SIGINT);

	kref_put(&wq, really_destroy_workqueue);
}

static int run_singlethread_workqueue(void *param)
{
	struct workqueue_struct *wq = param;
	struct work_struct *w;

	while (1) {
		ret = wait_event_interruptible(wq->there_is_work, !list_empty(&wq->work_list));
		if (ret == -ERESTARTSYS) {
			if (current->sig == SIGHUP) {
				flush_signals(current);
				continue;
			}
			break;
		}

		w = get_a_work(wq);
		if (w == NULL)
			continue;

		w->func(w);
	}
	kref_put(&wq, really_destroy_workqueue);

	return 0;
}

bool queue_work(struct workqueue_struct *queue, struct work_struct *work)
{
	KIRQL flags;

	if (queue->about_to_destroy) {
		printk("Warning: Attempt to queue_work while destroying workqueue\n");
		return false;
	}
	spin_lock_irqsave(&queue->work_list_lock, flags);

	if (!list_empty(&work->work_list)) {	/* it is already on the list */
		spin_unlock_irqrestore(&queue->work_list_lock, flags);
		return false;
	}
	list_add_tail(&work->work_list, &queue->work_list);
	work->queue = queue;
	spin_unlock_irqrestore(&queue->work_list_lock, flags2);

	wake_up(&queue->there_is_work);

	return true;	/* work was queued */
}

struct workqueue_struct *alloc_workqueue(const char * fmt, unsigned int flags, int max_active, ...)
{
	struct workqueue_struct *wq;
	va_list args;
	int i, j;

	if (max_active > MAX_WORKQUEUE_THREADS) {
		printk("max_active is %d and we support only %d threads.\n", max_active, MAX_WORKQUEUE_THREADS);
		return NULL;
	}
	wq = kzalloc(sizeof(*wq), GFP_KERNEL);
	if (wq == NULL) {
		printk("Warning: not enough memory for workqueue\n");
		return NULL;
	}
	INIT_LIST_HEAD(&wq->work_list);
	spin_lock_init(&wq->work_list_lock);
	init_waitqueue_head(&wq->there_is_work);
	kref_init(&wq->kref);

	va_start(args, max_active);

		/* ignore error if string is too long */
	_vsnprintf(wq->name, sizeof(wq->name)-1, fmt, args);
	wq->name[sizeof(wq->name)-1] = '\0';

	va_end(args);

	for (i=0;i<max_active;i++) {
		kref_get(&wq->kref);
		wq->threads[i] = kthread_create(run_singlethread_workqueue, wq, "wq_%s_%d", wq->name, i);

		if (IS_ERR(wq->threads[i])) {
			kref_put(&wq->kref, really_destroy_workqueue);

			printk("kthread_run failed on creating workqueue thread, err is %d\n", PTR_ERR(wq->thread));
			for (j=0;j<i;j++)
				force_sig(wq->threads[j], SIGINT);

			kfree(wq);
			return NULL;
		}
		wake_up_process(wq->threads[i]);
	}

	return wq;
}

/* This should ensure that all work on the workqueue is done (has finished).
 * It is typically invoked when a driver shuts down a resource (for example
 * on drbdadm down).
 */
void flush_workqueue(struct workqueue_struct *wq)
{
	PVOID waitObjects[2] = { &wq->workFinishedEvent, &wq->killEvent };
	NTSTATUS status;

	KeResetEvent(&wq->workFinishedEvent);
	KeSetEvent(&wq->wakeupEvent, 0, FALSE);
	status = KeWaitForMultipleObjects(2, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		printk("Warning: KeWaitForMultipleObjects in flush_workqueue() returned status %08x\n", status);
	}
	if (!list_empty(&wq->work_list)) {
		printk("Warning: wq->work_list not empty at exiting flush_workqueue\n");
	}
}

int cancel_work_sync(struct work_struct *work)
{
	bool ret = work->pending;

	if (remove_work_from_worklist(work)) {
			/* To terminate revc()  .... */
		/* TODO: needed? hopefully not ... */
//		force_sig(SIGHUP, work->queue->thread);
		flush_workqueue(work->orig_queue);
	}           /* else it was never queued */

	return ret;
}


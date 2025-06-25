#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <asm/signal.h>
#include <linux/sched/signal.h>
#include <linux/completion.h>

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
	list_del(&w->work_list);
	list_add(&w->work_list, &wq->in_progress_list);
	spin_unlock_irqrestore(&wq->work_list_lock, flags);

	return w;
}

void really_destroy_workqueue(struct kref *kref)
{
	struct workqueue_struct *wq = container_of(kref, struct workqueue_struct, kref);

printk("really destroying workqueue at %p\n", wq);
	kfree(wq->tasks);
	kfree(wq);
}

void destroy_workqueue(struct workqueue_struct *wq)
{
	int i;

printk("about to destroy workqueue at %p\n", wq);
	for (i=0;i<wq->num_tasks;i++)
		force_sig(SIGINT, wq->tasks[i].task);

printk("sent signals to threads of workqueue %p\n", wq);
printk("now waiting for all completions ...\n");

	for (i=0;i<wq->num_tasks;i++)
		wait_for_completion(&wq->tasks[i].completion);

printk("All tasks completed, now dropping (last) reference.\n");
	kref_put(&wq->kref, really_destroy_workqueue);
printk("ok, kref put was run\n");
}

static int run_singlethread_workqueue(void *param)
{
	struct workqueue_task *t = param;
	struct workqueue_struct *wq = t->workqueue;
	struct work_struct *w;
	int ret;
	KIRQL flags;

printk("workqueue started.\n");
	while (1) {
		ret = wait_event_interruptible(wq->there_is_work, !list_empty(&wq->work_list));
		if (ret == -ERESTARTSYS) {
			if (current->sig == SIGHUP) {
				flush_signals(current);
				continue;
			}
printk("got a signal, terminating...\n");
			break;
		}

printk("getting work ...\n");
		w = get_a_work(wq);
		if (w == NULL)
			continue;

printk("running work ...\n");
printk("w is %p w->func is %p queue is %p\n", w, w->func, wq);
		w->func(w);
printk("ok finished work ...\n");

			/* either on in_progress_list or on a
			 * active_list of a flush_workqueue.
			 */

		spin_lock_irqsave(&wq->work_list_lock, flags);
		list_del_init(&w->work_list);
		w->queue = NULL;	/* done with it */
		spin_unlock_irqrestore(&wq->work_list_lock, flags);

printk("waking flush/cancel work functions...\n");
		wake_up(&wq->a_work_has_finished);
	}
printk("terminating into kref_put\n");
	kref_put(&wq->kref, really_destroy_workqueue);
printk("terminating out of kref_put\n");
	complete(&t->completion);
printk("completion completed\n");

	return 0;
}

bool queue_work(struct workqueue_struct *queue, struct work_struct *work)
{
	KIRQL flags;

	spin_lock_irqsave(&queue->work_list_lock, flags);
	if (work->queue != NULL) {	/* it is already on the list or
					 * currently executing
					 */
		spin_unlock_irqrestore(&queue->work_list_lock, flags);
		return false;
	}
	list_add_tail(&work->work_list, &queue->work_list);
	work->queue = queue;
	spin_unlock_irqrestore(&queue->work_list_lock, flags);

printk("work is %p work->queue is %p work->func is %p\n", work, queue, work->func);

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
	wq->tasks = kzalloc(max_active*sizeof(*wq->tasks), GFP_KERNEL);
	if (wq->tasks == NULL) {
		printk("Warning: not enough memory for workqueue threads\n");
		kfree(wq);
		return NULL;
	}

	INIT_LIST_HEAD(&wq->work_list);
	INIT_LIST_HEAD(&wq->in_progress_list);
	spin_lock_init(&wq->work_list_lock);
	init_waitqueue_head(&wq->there_is_work);
	init_waitqueue_head(&wq->a_work_has_finished);
	kref_init(&wq->kref);

	va_start(args, max_active);

		/* ignore error if string is too long */
	_vsnprintf(wq->name, sizeof(wq->name)-1, fmt, args);
	wq->name[sizeof(wq->name)-1] = '\0';

	va_end(args);

	for (i=0;i<max_active;i++) {
		kref_get(&wq->kref);

		init_completion(&wq->tasks[i].completion);
		wq->tasks[i].i = i;
		wq->tasks[i].workqueue = wq;
		wq->tasks[i].task = kthread_create(run_singlethread_workqueue, wq, "wq_%s_%d", wq->name, i);

		if (IS_ERR(wq->tasks[i].task)) {
			kref_put(&wq->kref, really_destroy_workqueue);

			printk("kthread_run failed on creating workqueue thread, err is %d\n", PTR_ERR(wq->tasks[i].task));
			for (j=0;j<i;j++)
				force_sig(SIGINT, wq->tasks[j].task);

			kfree(wq);
			return NULL;
		}
		wake_up_process(wq->tasks[i].task);
	}
	wq->num_tasks = i;

	return wq;
}

/* This should ensure that all work on the workqueue is done (has finished).
 * It is typically invoked when a driver shuts down a resource (for example
 * on drbdadm down).
 */
void flush_workqueue(struct workqueue_struct *wq)
{
	KIRQL flags;
	struct work_struct *work, *w2;
	struct list_head active_work_items;

	INIT_LIST_HEAD(&active_work_items);

	spin_lock_irqsave(&wq->work_list_lock, flags);
	list_for_each_entry_safe(work, w2, &wq->in_progress_list, work_list) {
		list_del(&work->work_list);
		list_add(&work->work_list, &active_work_items);
	}
	spin_unlock_irqrestore(&wq->work_list_lock, flags);

	wait_event(wq->a_work_has_finished, list_empty(&active_work_items));
}

int cancel_work_sync(struct work_struct *work)
{
	struct list_head active_work_items;
	KIRQL flags;

	INIT_LIST_HEAD(&active_work_items);

	struct workqueue_struct *wq;

	wq = work->queue;
	if (wq == NULL)
		return false;

	spin_lock_irqsave(&wq->work_list_lock, flags);
	list_del(&work->work_list);
	list_add(&work->work_list, &active_work_items);
	spin_unlock_irqrestore(&wq->work_list_lock, flags);

	wait_event(wq->a_work_has_finished, list_empty(&active_work_items));
	return true;
}


		/* TODO: needed? hopefully not ... */
//		force_sig(SIGHUP, work->queue->thread);


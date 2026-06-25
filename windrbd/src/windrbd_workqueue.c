// SPDX-License-Identifier: GPL-2.0-or-later

/* A multi-threaded workqueue implementation for WinDRBD.
 *
 * It uses only Linux kernel APIs (no direct calls to
 * Windows kernel API functions). The interface is compatible
 * to a recent (say, 6.14) Linux kernel.
 *
 * Copyright (C) 2025, Johannes Khoshnazar-Thoma <johannes@johannesthoma.com>
 *
 */

#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <asm/signal.h>
#include <linux/sched/signal.h>
#include <linux/completion.h>
#include <linux/mutex.h>

struct workqueue_struct *system_wq;

void destroy_work_struct_internal(struct kref *kref)
{
	struct work_struct_internal *wi = container_of(kref, struct work_struct_internal, kref);

	kfree(wi);
}

static struct work_struct *get_a_work(struct workqueue_struct *wq)
{
	unsigned long flags;
	struct work_struct_internal *wi;

	spin_lock_irqsave(&wq->work_list_lock, flags);

	if (list_empty(&wq->work_list)) {
		spin_unlock_irqrestore(&wq->work_list_lock, flags);
		return NULL;
	}
	wi = list_first_entry(&wq->work_list, struct work_struct_internal, work_list);
	list_del_init(&wi->work_list);
	spin_unlock_irqrestore(&wq->work_list_lock, flags);

	return wi->work;
}

void really_destroy_workqueue(struct kref *kref)
{
	struct workqueue_struct *wq = container_of(kref, struct workqueue_struct, kref);

	kfree(wq->tasks);
	kfree(wq);
}

void destroy_workqueue(struct workqueue_struct *wq)
{
	int i;

	for (i = 0; i < wq->num_tasks; i++)
		force_sig(SIGINT, wq->tasks[i].task);

	for (i = 0; i < wq->num_tasks; i++)
		wait_for_completion(&wq->tasks[i].completion);

	kref_put(&wq->kref, really_destroy_workqueue);
}

static int run_singlethread_workqueue(void *param)
{
	struct workqueue_task *t = param;
	struct workqueue_struct *wq = t->workqueue;
	struct work_struct *w;
	struct work_struct_internal *wi;
	int ret;
	unsigned long flags;

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

		wi = w->internal_work_struct;
		kref_get(&wi->kref);

		mutex_lock(&wi->the_mutex);

		if (!wi->cancelled) {
			if (w->func == NULL)
				printk("ARGHHH func is NULL in work %p!!\n", w);
			w->func(w);
		}
		mutex_unlock(&wi->the_mutex);

		/* either on in_progress_list or on a
		 * active_list of a flush_workqueue.
		 */

		spin_lock_irqsave(&wq->work_list_lock, flags);
		list_del_init(&wi->in_progress_list);
		wi->queue = NULL;	/* done with it */
		spin_unlock_irqrestore(&wq->work_list_lock, flags);

		/* This is 'the trick': the work_struct_internal lives
		 * a little bit longer than the work_struct, so we can
		 * remove from it the list here and release the mutex.
		 * The work_struct ('w') maybe already freed once
		 * the worker function returns.
		 */

		kref_put(&wi->kref, destroy_work_struct_internal);

		wake_up(&wq->a_work_has_finished);
	}
	kref_put(&wq->kref, really_destroy_workqueue);
	complete(&t->completion);

	return 0;
}

bool queue_work(struct workqueue_struct *queue, struct work_struct *work)
{
	struct work_struct_internal *wi = work->internal_work_struct;
	unsigned long flags;

	kref_get(&wi->kref);

	spin_lock_irqsave(&queue->work_list_lock, flags);
	if (!list_empty(&wi->work_list) || wi->cancelled) {	/* it is already queued or cancelled */
		spin_unlock_irqrestore(&queue->work_list_lock, flags);
		kref_put(&wi->kref, destroy_work_struct_internal);

		return false;
	}
	if (wi->queue != NULL && queue != wi->queue) {	/* it is executing */
		pr_warn("Warning: attempt to move work to another queue while it is executing.\n");
	}
	list_add_tail(&wi->work_list, &queue->work_list);
	if (list_empty(&wi->in_progress_list))
		list_add(&wi->in_progress_list, &queue->in_progress_list);
			/* else it is already on the list executing right now */

	wi->queue = queue;
	spin_unlock_irqrestore(&queue->work_list_lock, flags);

	kref_put(&wi->kref, destroy_work_struct_internal);
	wake_up(&queue->there_is_work);

	return true;	/* work was queued */
}

struct workqueue_struct *alloc_workqueue(const char *fmt, unsigned int flags, int max_active, ...)
{
	struct workqueue_struct *wq;
	va_list args;
	int i, j;

	if ((flags & WQ_UNBOUND) && (max_active == 0))
		max_active = 2;		/* or so ... */

	if (max_active <= 0) {
		pr_warn("max_active is %d, invalid!\n", max_active);
		return NULL;
	}

	if (max_active > MAX_WORKQUEUE_THREADS) {
		pr_warn("max_active is %d and we support only %d threads.\n", max_active, MAX_WORKQUEUE_THREADS);
		return NULL;
	}
	wq = kzalloc(sizeof(*wq), GFP_KERNEL);
	if (wq == NULL)
		return NULL;

	wq->tasks = kcalloc(max_active, sizeof(*wq->tasks), GFP_KERNEL);
	if (wq->tasks == NULL) {
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

	for (i = 0; i < max_active; i++) {
		kref_get(&wq->kref);

		init_completion(&wq->tasks[i].completion);
		wq->tasks[i].i = i;
		wq->tasks[i].workqueue = wq;
		wq->tasks[i].task = kthread_create(run_singlethread_workqueue, &wq->tasks[i], "wq_%s_%d", wq->name, i);

		if (IS_ERR(wq->tasks[i].task)) {
			kref_put(&wq->kref, really_destroy_workqueue);

			pr_warn("kthread_run failed on creating workqueue thread, err is %d\n", PTR_ERR(wq->tasks[i].task));

			for (j = 0; j < i; j++)
				force_sig(SIGINT, wq->tasks[j].task);
			for (j = 0; j < i; j++)
				wait_for_completion(&wq->tasks[j].completion);

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
	unsigned long flags;
	struct work_struct_internal *wi, *wi2;
	struct list_head active_work_items;

	INIT_LIST_HEAD(&active_work_items);

	spin_lock_irqsave(&wq->work_list_lock, flags);
	list_for_each_entry_safe(wi, wi2, &wq->in_progress_list, in_progress_list) {
		list_del_init(&wi->in_progress_list);
		list_add(&wi->in_progress_list, &active_work_items);
	}
	spin_unlock_irqrestore(&wq->work_list_lock, flags);

	wait_event(wq->a_work_has_finished, list_empty(&active_work_items));
}

int cancel_work_sync(struct work_struct *work)
{
	struct work_struct_internal *wi = work->internal_work_struct;
	struct list_head active_work_items;
	unsigned long flags;
	struct workqueue_struct *wq;

	kref_get(&wi->kref);

// printk("ZAKZAK cancel_work_sync work %p\n", work);

	INIT_LIST_HEAD(&active_work_items);
	wi->cancelled = true;

	wq = wi->queue;
	if (wq == NULL) {
		kref_put(&wi->kref, destroy_work_struct_internal);
		return false;
	}

	spin_lock_irqsave(&wq->work_list_lock, flags);
	list_del_init(&wi->in_progress_list);
	list_add(&wi->in_progress_list, &active_work_items);
	spin_unlock_irqrestore(&wq->work_list_lock, flags);

	wait_event(wq->a_work_has_finished, list_empty(&active_work_items));

	kref_put(&wi->kref, destroy_work_struct_internal);
	return true;
}


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

static struct work_struct *get_a_work(struct workqueue_struct *wq)
{
	unsigned long flags;
	struct work_struct *w;

	spin_lock_irqsave(&wq->work_list_lock, flags);

	if (list_empty(&wq->work_list)) {
		spin_unlock_irqrestore(&wq->work_list_lock, flags);
		return NULL;
	}
	w = list_first_entry(&wq->work_list, struct work_struct, work_list);
	list_del_init(&w->work_list);
	spin_unlock_irqrestore(&wq->work_list_lock, flags);

	return w;
}

void really_destroy_workqueue(struct kref *kref)
{
	struct workqueue_struct *wq = container_of(kref, struct workqueue_struct, kref);

// printk("ZAKZAK really_destroy_workqueue 4 %p\n", wq);
	kfree(wq->tasks);
	kfree(wq);
// printk("ZAKZAK really_destroy_workqueue 5 %p\n", wq);
}

void destroy_workqueue(struct workqueue_struct *wq)
{
	int i;

// printk("ZAKZAK destroy_workqueue 1 %p\n", wq);
	for (i = 0; i < wq->num_tasks; i++)
		force_sig(SIGINT, wq->tasks[i].task);

// printk("ZAKZAK destroy_workqueue 2 %p\n", wq);
	for (i = 0; i < wq->num_tasks; i++)
		wait_for_completion(&wq->tasks[i].completion);
// printk("ZAKZAK destroy_workqueue 3 %p\n", wq);
// if (!list_empty(&wq->in_progress_list))
// printk("ZAKZAK wq %p in progresslist not empty!!!\n");

	kref_put(&wq->kref, really_destroy_workqueue);
}

static int run_singlethread_workqueue(void *param)
{
	struct workqueue_task *t = param;
	struct workqueue_struct *wq = t->workqueue;
	struct work_struct *w;
	int ret;
	unsigned long flags;
	bool wdw;

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

		wdw = w->will_delete_work;
		if (!wdw) {
			mutex_lock(&w->the_mutex);
		} else {/* must not touch w after calling func, so
			 * we cleanup here. cancel_work is not defined
			 * to work when the handler deletes the work
			 * anyway.
			 */
			spin_lock_irqsave(&wq->work_list_lock, flags);
			list_del_init(&w->in_progress_list);
			w->queue = NULL;	/* done with it */
			spin_unlock_irqrestore(&wq->work_list_lock, flags);
		}
		if (!w->cancelled) {
			if (w->func == NULL)
				printk("ARGHHH func is NULL in work %p!!\n", w);
			w->func(w);
		}
		if (!wdw) {
			mutex_unlock(&w->the_mutex);

			/* either on in_progress_list or on a
			 * active_list of a flush_workqueue.
			 */

			spin_lock_irqsave(&wq->work_list_lock, flags);
			list_del_init(&w->in_progress_list);
			w->queue = NULL;	/* done with it */
			spin_unlock_irqrestore(&wq->work_list_lock, flags);
		}
		wake_up(&wq->a_work_has_finished);
	}
	kref_put(&wq->kref, really_destroy_workqueue);
	complete(&t->completion);

	return 0;
}

bool queue_work(struct workqueue_struct *queue, struct work_struct *work)
{
	unsigned long flags;

	spin_lock_irqsave(&queue->work_list_lock, flags);
	if (!list_empty(&work->work_list) || work->cancelled) {	/* it is already queued or cancelled */
		spin_unlock_irqrestore(&queue->work_list_lock, flags);
		return false;
	}
	if (work->queue != NULL && queue != work->queue) {	/* it is executing */
		pr_warn("Warning: attempt to move work to another queue while it is executing.\n");
	}
	list_add_tail(&work->work_list, &queue->work_list);
	if (list_empty(&work->in_progress_list))
		list_add(&work->in_progress_list, &queue->in_progress_list);
// else 
// printk("ZAKZAK work %p already on some list\n", work);
			/* else it is already on the list executing right now */

	work->queue = queue;
	spin_unlock_irqrestore(&queue->work_list_lock, flags);

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
	struct work_struct *work, *w2;
	struct list_head active_work_items;

// printk("ZAKZAK flush_workqueue wq %p\n", wq);

	INIT_LIST_HEAD(&active_work_items);

	spin_lock_irqsave(&wq->work_list_lock, flags);
	list_for_each_entry_safe(work, w2, &wq->in_progress_list, in_progress_list) {
		list_del_init(&work->in_progress_list);
		list_add(&work->in_progress_list, &active_work_items);
	}
	spin_unlock_irqrestore(&wq->work_list_lock, flags);

	wait_event(wq->a_work_has_finished, list_empty(&active_work_items));
}

int cancel_work_sync(struct work_struct *work)
{
	struct list_head active_work_items;
	unsigned long flags;
	struct workqueue_struct *wq;

// printk("ZAKZAK cancel_work_sync work %p\n", work);

	INIT_LIST_HEAD(&active_work_items);
	work->cancelled = true;

	wq = work->queue;
	if (wq == NULL)
// { printk("ZAKZAK wq is NULL\n");
		return false;
// }

	spin_lock_irqsave(&wq->work_list_lock, flags);
	list_del_init(&work->in_progress_list);
	list_add(&work->in_progress_list, &active_work_items);
	spin_unlock_irqrestore(&wq->work_list_lock, flags);

	wait_event(wq->a_work_has_finished, list_empty(&active_work_items));
// printk("ZAKZAK ok work %p should be cancelled\n", work);
	return true;
}

/* DRBD should call this before freeing the structs containing
 * the work.
 */

void windrbd_assert_work_list_empty(struct work_struct *work, const char *msg)
{
	if (!list_empty(&work->in_progress_list))
		printk("ZAKZAK work list %p not empty!!! at: %s work->queue: %p work->func: %p\n", work, msg, work->queue, work->func);
}

		/* TODO: needed? hopefully not ... */
//		force_sig(SIGHUP, work->queue->thread);


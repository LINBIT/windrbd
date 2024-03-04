#ifndef _WORKQUEUE_H
#define _WORKQUEUE_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#define WQ_MEM_RECLAIM 0
#define WQNAME_LEN	32

struct workqueue_struct {
	struct list_head work_list;
	spinlock_t work_list_lock;

	int run;
	int about_to_destroy;
	KEVENT	wakeupEvent;
	KEVENT	killEvent;
	KEVENT	workFinishedEvent;
	KEVENT	readyToFreeEvent;

	void (*func)();
	char name[WQNAME_LEN];
	struct task_struct *thread;
};

struct work_struct {
	int pending;
	spinlock_t pending_lock;
	struct list_head work_list;

	void (*func)(struct work_struct *work);

		/* For checking if they change */
	struct workqueue_struct *orig_queue;
	void (*orig_func)(struct work_struct *work);
};

extern struct workqueue_struct *system_wq;

struct workqueue_struct *alloc_ordered_workqueue(const char * fmt, int flags, ...);
extern void queue_work(struct workqueue_struct* queue, struct work_struct* work);
extern void flush_workqueue(struct workqueue_struct *wq);
extern void destroy_workqueue(struct workqueue_struct *wq);

static inline void schedule_work(struct work_struct *work)
{
	queue_work(system_wq, work);
}

#endif

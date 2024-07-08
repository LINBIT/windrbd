#ifndef _WORKQUEUE_H
#define _WORKQUEUE_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#define WQ_MEM_RECLAIM  (1 << 3)
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

#define PREPARE_WORK(_work, _func)                                      \
	do {                                                            \
		(_work)->func = (_func);                                \
	} while (0)

#define __INIT_WORK(_work, _func, _onstack)                             \
	 do {                                                           \
	       /* __init_work((_work), _onstack);        */  \
	       /*  (_work)->data = (atomic_long_t) WORK_DATA_INIT(); */ \
		INIT_LIST_HEAD(&(_work)->work_list);			\
		spin_lock_init(&(_work)->pending_lock);			\
		PREPARE_WORK((_work), (_func));                         \
		(_work)->pending = 0;					\
	} while (0)

#define INIT_WORK(_work, _func)                                         \
	 __INIT_WORK((_work), (_func), 0);


#define create_singlethread_workqueue(name)				\
	alloc_ordered_workqueue("%s", WQ_MEM_RECLAIM, name)

extern bool cancel_work_sync(struct work_struct *work);

#endif

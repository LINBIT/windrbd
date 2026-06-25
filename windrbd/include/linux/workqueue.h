#ifndef _WORKQUEUE_H
#define _WORKQUEUE_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/kref.h>
#include <linux/completion.h>
#include <linux/mutex.h>

/*
 * Workqueue flags and constants.  For details, please refer to
 * Documentation/core-api/workqueue.rst.
 */
enum wq_flags {
	WQ_BH			= 1 << 0, /* execute in bottom half (softirq) context */
	WQ_UNBOUND		= 1 << 1, /* not bound to any cpu */
	WQ_FREEZABLE		= 1 << 2, /* freeze during suspend */
	WQ_MEM_RECLAIM		= 1 << 3, /* may be used for memory reclaim */
	WQ_HIGHPRI		= 1 << 4, /* high priority */
	WQ_CPU_INTENSIVE	= 1 << 5, /* cpu intensive workqueue */
	WQ_SYSFS		= 1 << 6, /* visible in sysfs, see workqueue_sysfs_register() */

	/*
	 * Per-cpu workqueues are generally preferred because they tend to
	 * show better performance thanks to cache locality.  Per-cpu
	 * workqueues exclude the scheduler from choosing the CPU to
	 * execute the worker threads, which has an unfortunate side effect
	 * of increasing power consumption.
	 *
	 * The scheduler considers a CPU idle if it doesn't have any task
	 * to execute and tries to keep idle cores idle to conserve power;
	 * however, for example, a per-cpu work item scheduled from an
	 * interrupt handler on an idle CPU will force the scheduler to
	 * execute the work item on that CPU breaking the idleness, which in
	 * turn may lead to more scheduling choices which are sub-optimal
	 * in terms of power consumption.
	 *
	 * Workqueues marked with WQ_POWER_EFFICIENT are per-cpu by default
	 * but become unbound if workqueue.power_efficient kernel param is
	 * specified.  Per-cpu workqueues which are identified to
	 * contribute significantly to power-consumption are identified and
	 * marked with this flag and enabling the power_efficient mode
	 * leads to noticeable power saving at the cost of small
	 * performance disadvantage.
	 *
	 * http://thread.gmane.org/gmane.linux.kernel/1480396
	 */
	WQ_POWER_EFFICIENT	= 1 << 7,

	__WQ_DESTROYING		= 1 << 15, /* internal: workqueue is destroying */
	__WQ_DRAINING		= 1 << 16, /* internal: workqueue is draining */
	__WQ_ORDERED		= 1 << 17, /* internal: workqueue is ordered */
	__WQ_LEGACY		= 1 << 18, /* internal: create*_workqueue() */

	/* BH wq only allows the following flags */
	__WQ_BH_ALLOWS		= WQ_BH | WQ_HIGHPRI,
};

#define WQNAME_LEN	32
#define MAX_WORKQUEUE_THREADS 1024

struct workqueue_struct;

struct workqueue_task {
	struct workqueue_struct *workqueue;
	struct task_struct *task;
	int i;
	struct completion completion;
};

struct workqueue_struct {
	struct list_head work_list;
	struct list_head in_progress_list;
	spinlock_t work_list_lock;

	wait_queue_head_t there_is_work;
	wait_queue_head_t a_work_has_finished;
	struct kref kref;

	char name[WQNAME_LEN];
	int num_tasks;
	struct workqueue_task *tasks;
};

extern void destroy_work_struct_internal(struct kref *kref);

struct work_struct;

struct work_struct_internal {
	struct list_head work_list;
	struct list_head in_progress_list;
	struct workqueue_struct *queue;
	struct mutex the_mutex;
	bool cancelled;
	struct work_struct *work;
	struct kref kref;
};

/* We need a 'destructor' for this: */
struct work_struct {
	struct work_struct_internal *internal_work_struct;
	void (*func)(struct work_struct *work);
};

extern struct workqueue_struct *system_wq;

#define alloc_ordered_workqueue(fmt, flags, args...)			\
	alloc_workqueue(fmt, WQ_UNBOUND | __WQ_ORDERED | (flags), 1, ##args)

/**
 * alloc_workqueue - allocate a workqueue
 * @fmt: printf format for the name of the workqueue
 * @flags: WQ_* flags
 * @max_active: max in-flight work items, 0 for default
 * @...: args for @fmt
 *
 * For a per-cpu workqueue, @max_active limits the number of in-flight work
 * items for each CPU. e.g. @max_active of 1 indicates that each CPU can be
 * executing at most one work item for the workqueue.
 *
 * For unbound workqueues, @max_active limits the number of in-flight work items
 * for the whole system. e.g. @max_active of 16 indicates that that there can be
 * at most 16 work items executing for the workqueue in the whole system.
 *
 * As sharing the same active counter for an unbound workqueue across multiple
 * NUMA nodes can be expensive, @max_active is distributed to each NUMA node
 * according to the proportion of the number of online CPUs and enforced
 * independently.
 *
 * Depending on online CPU distribution, a node may end up with per-node
 * max_active which is significantly lower than @max_active, which can lead to
 * deadlocks if the per-node concurrency limit is lower than the maximum number
 * of interdependent work items for the workqueue.
 *
 * To guarantee forward progress regardless of online CPU distribution, the
 * concurrency limit on every node is guaranteed to be equal to or greater than
 * min_active which is set to min(@max_active, %WQ_DFL_MIN_ACTIVE). This means
 * that the sum of per-node max_active's may be larger than @max_active.
 *
 * For detailed information on %WQ_* flags, please refer to
 * Documentation/core-api/workqueue.rst.
 *
 * RETURNS:
 * Pointer to the allocated workqueue on success, %NULL on failure.
 */
__printf(1, 4) struct workqueue_struct *
alloc_workqueue(const char *fmt, unsigned int flags, int max_active, ...);

extern bool queue_work(struct workqueue_struct *queue, struct work_struct *work);
extern void flush_workqueue(struct workqueue_struct *wq);
extern void destroy_workqueue(struct workqueue_struct *wq);

static inline bool schedule_work(struct work_struct *work)
{
	return queue_work(system_wq, work);
}

#define PREPARE_WORK(_work, _func)                                      \
	do {                                                            \
		(_work)->func = (_func);                                \
	} while (0)

#define __INIT_WORK(_work, _func, _onstack)                             \
	 do {                                                           \
		struct work_struct_internal *wi;			\
		wi = kmalloc(sizeof(*wi), GFP_KERNEL);			\
		if (wi == NULL)						\
		 	pr_warn("No memory for work_struct_internal, this is very bad.\n");	\
		else {							\
			(_work)->internal_work_struct = wi;		\
			INIT_LIST_HEAD(&wi->work_list);			\
			INIT_LIST_HEAD(&wi->in_progress_list);		\
			mutex_init(&wi->the_mutex);			\
			PREPARE_WORK((_work), (_func));                 \
			wi->queue = NULL;				\
			wi->cancelled = false;				\
			wi->work = (_work);				\
			kref_init(&wi->kref);				\
		};							\
	} while (0)

#define INIT_WORK(_work, _func)                                         \
	 __INIT_WORK((_work), (_func), 0);

/* This is non-standard Linux: DRBD needs to call this whereever a
 * work is (implicitly) freed. Sorry about that, in WinDRBD 2.0 this
 * will go away.
 */

#define FINALIZE_WORK(w)						\
	kref_put(&(w)->internal_work_struct.kref, destroy_work_struct_internal); \

#define create_singlethread_workqueue(name)				\
	alloc_ordered_workqueue("%s", WQ_MEM_RECLAIM, name)

extern int cancel_work_sync(struct work_struct *work);

#endif

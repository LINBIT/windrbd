#ifndef __SCHED_H__
#define __SCHED_H__

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <asm/current.h>
// #include <windrbd.h>

#define TASK_COMM_LEN 32

struct task_struct {
	struct list_head list;

	pid_t pid;
	PKTHREAD windows_thread;

	int (*threadfn)(void*);
	void *data;

		/* Signal handling. TODO: the has_sig_event should
		 * go away one day.
		 */
	KEVENT sig_event;
	BOOLEAN has_sig_event;
	int sig; 
	KEVENT start_event;

		/* Set by prepare_to_wait: a followup call to
		 * schedule() will wait on that wait queue entry.
		 */
	struct wait_queue_head *wait_queue;
	struct wait_queue_entry *wait_queue_entry;

		/* Set to TASK_INTERRUPTIBLE if schedule should also
		 * wait for signals.
		 */
	int interruptible;

	int thread_started:1;
	int is_zombie:1;
	int is_root:1;
	int in_rcu:1;

	const char *rcu_file;
	int rcu_line;
	const char *rcu_func;

	atomic_t rcu_recursion_depth;

	spinlock_t thread_started_lock;

		/* TODO: needed? */
	struct blk_plug *plug;

	char comm[TASK_COMM_LEN];
};

static inline pid_t task_pid_nr(struct task_struct *tsk)
{
	return tsk->pid;
}

static inline char *get_task_comm(char *buf, struct task_struct *task)
{
	/* Linux has here a build bug on sizeof(buf) != TASK_COMM_LEN .. */
	strncpy(buf, task->comm, TASK_COMM_LEN);
	return buf;
}

static inline bool need_resched(void)
{
    return false;
}

struct sched_param {
	int sched_priority;
};

#define SCHED_RR 42

static inline int sched_setscheduler(struct task_struct *p, int policy,
	                       const struct sched_param *param)
{
	/* TODO: at least test for SCHED_RR here ... */
    (void)policy;
    (void)param;

    KeSetPriorityThread(p->windows_thread, LOW_REALTIME_PRIORITY);
    return 0;
}

static inline int sched_set_fifo_low(struct task_struct *p)
{
    KeSetPriorityThread(p->windows_thread, LOW_REALTIME_PRIORITY);

    return 0;
}

#define MAX_SCHEDULE_TIMEOUT ((long)(~0UL>>1))

#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2

#endif

#ifndef _WINDRBD_THREAD_H
#define _WINDRBD_THREAD_H

#include <wdm.h>

typedef int pid_t;

/* Helper functions that might be useful for others. */

NTSTATUS windrbd_create_windows_thread(void (*threadfn)(void*), void *data, void **thread_object_p);
NTSTATUS windrbd_cleanup_windows_thread(void *thread_object);

void init_windrbd_threads(void);

	/* Currently called by reply_reaper, see netlink code */
void windrbd_reap_threads(void);

	/* This waits forever, only use this on driver unload */
void windrbd_reap_all_threads(void);

struct task_struct* windrbd_find_thread(PKTHREAD id);
#define current	windrbd_find_thread(KeGetCurrentThread())

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
		 * schedule() will wait on that wait queue.
		 * Note that currently a wait queue has only
		 * a single event (no internal list).
		 */
	struct wait_queue_head *wait_queue;

	int thread_started:1;
	int is_zombie:1;
	spinlock_t thread_started_lock;

		/* TODO: needed? */
	struct blk_plug *plug;
	
	char comm[TASK_COMM_LEN];
};

/* From include/linux/sched.h */

static inline pid_t task_pid_nr(struct task_struct *tsk)
{
	return tsk->pid;
}


	/* These should be more or less compatible to their Linux
	 * counterparts. For documentation see there.
	 */

struct task_struct *kthread_create(int (*threadfn)(void *), void *data, const char *name, ...);
int wake_up_process(struct task_struct *t);

	/* TODO: no varargs here, since we call kthread_create internally
	 * (and don't have GNU-style varargs macros that create a block).
	 */

struct task_struct *kthread_run(int (*threadfn)(void *), void *data, const char *name);

static inline char *get_task_comm(char *buf, struct task_struct *task)
{
	/* Linux has here a build bug on sizeof(buf) != TASK_COMM_LEN .. */
	strncpy(buf, task->comm, TASK_COMM_LEN);
	return buf;
}

#endif

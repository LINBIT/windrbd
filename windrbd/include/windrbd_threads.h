#ifndef _WINDRBD_THREAD_H
#define _WINDRBD_THREAD_H

/* Enable all warnings throws lots of those warnings: */
#pragma warning(disable: 4061 4062 4255 4388 4668 4820 5032  4711 5045)

#include <wdm.h>

#ifndef ATOMIC_T_DEFINED
typedef int atomic_t;
#define ATOMIC_T_DEFINED
#endif

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

        /* Use this to create a task_struct for a Windows thread
         * This is needed so we can call wait_event_XXX functions
         * within those threads.
         */

struct task_struct *make_me_a_windrbd_thread(const char *name, ...);

        /* Call this when a thread returns to the calling Windows
         * kernel function.
         */

void return_to_windows(struct task_struct *t);

/* Non-zero if thread is created via the Linux emulation layer (this
 * file).
 */

bool is_windrbd_thread(struct task_struct *t);

/* Set realtime priority. Used for asender */

void windrbd_set_realtime_priority(struct task_struct *t);

/* Become super user */
void sudo(void);

#endif

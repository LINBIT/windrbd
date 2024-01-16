#ifndef KTHREAD_H
#define KTHREAD_H

#include <linux/sched.h>

	/* These should be more or less compatible to their Linux
	 * counterparts. For documentation see there.
	 */

struct task_struct *kthread_create(int (*threadfn)(void *), void *data, const char *name, ...);
int wake_up_process(struct task_struct *t);

	/* TODO: no varargs here, since we call kthread_create internally
	 * (and don't have GNU-style varargs macros that create a block).
	 */

struct task_struct *kthread_run(int (*threadfn)(void *), void *data, const char *name);

#endif

#ifndef __WAIT_H__
#define __WAIT_H__
#include <wdm.h>
#include "linux/list.h"
#include "linux/spinlock.h"

typedef struct wait_queue_entry
{
	unsigned int flags;
	struct list_head task_list;
} wait_queue_t;

typedef struct wait_queue_head
{
	spinlock_t lock;
	struct list_head task_list;
	KEVENT	wqh_event;
#define Q_NAME_SZ	16 
	char eventName[Q_NAME_SZ];
} wait_queue_head_t;

#define DEFINE_WAIT(w) void *(w)

void prepare_to_wait(struct wait_queue_head *w, void *unused, int interruptible);
void finish_wait(struct wait_queue_head *w, void *unused);

void schedule_debug(const char *file, int line, const char *func);
/* Returns -EINTR on signal else remaining time. */
ULONG_PTR schedule_timeout_debug(ULONG_PTR timeout, const char *file, int line, const char *func);
/* Returns -EINTR on signal else remaining time. Use only internally. */
/* TODO: better name for function */
LONG_PTR schedule_timeout_maybe_interrupted_debug(ULONG_PTR timeout, const char *file, int line, const char *func);
LONG_PTR schedule_timeout_uninterruptible_debug(ULONG_PTR timeout, const char *file, int line, const char *func);

#define schedule() schedule_debug(__FILE__, __LINE__, __func__)
#define schedule_timeout_interruptible(timeout) schedule_timeout_debug((timeout), __FILE__, __LINE__, __func__)
/* TODO: honor the current->state field */
#define schedule_timeout(timeout) schedule_timeout_debug((timeout), __FILE__, __LINE__, __func__)
#define schedule_timeout_uninterruptible(timeout) schedule_timeout_uninterruptible_debug((timeout), __FILE__, __LINE__, __func__)

/* One macro for all cases of wait_event: if there is a bug it is
 * most likely in here ...
 */

#define ll_wait_event_macro(ret, wait_queue, condition, timeout, interruptible) \
do {									\
	LONG_PTR __timeout = timeout;					\
	while (1) {							\
		prepare_to_wait(&wait_queue, NULL, interruptible);	\
		if (condition) {					\
			if (__timeout == 0)				\
				__timeout = 1;				\
			break;						\
		}							\
									\
		__timeout = schedule_timeout_maybe_interrupted_debug(	\
			__timeout, __FILE__, __LINE__, __func__);	\
									\
		if (__timeout <= 0) 					\
			break;						\
									\
	}								\
	finish_wait(&wait_queue, NULL);					\
	ret = __timeout;						\
} while (0);

/* TODO: those two should honor current->state */
#define wait_event(wait_queue, condition)				\
do {									\
	int unused;							\
	ll_wait_event_macro(unused, wait_queue, condition,		\
		MAX_SCHEDULE_TIMEOUT, TASK_INTERRUPTIBLE);		\
} while (0);

	/* TODO: this might 'return' -EINTR */
#define wait_event_timeout(ret, wait_queue, condition, timeout)		\
do {									\
	ll_wait_event_macro(ret, wait_queue, condition,			\
		timeout, TASK_INTERRUPTIBLE);				\
} while (0);

#define wait_event_interruptible(ret, wait_queue, condition)		\
do {									\
	ll_wait_event_macro(ret, wait_queue, condition,			\
		MAX_SCHEDULE_TIMEOUT, TASK_INTERRUPTIBLE);		\
	if (ret > 0)							\
		ret = 0;						\
} while (0);

#define wait_event_interruptible_timeout(ret, wait_queue, condition, timeout) \
do {									\
	ll_wait_event_macro(ret, wait_queue, condition,			\
		timeout, TASK_INTERRUPTIBLE);		\
} while (0);

#define wake_up(q) wake_up_debug(q, __FILE__, __LINE__, __func__)

void wake_up_debug(wait_queue_head_t *q, const char *file, int line, const char *func);
extern void wake_up_all(wait_queue_head_t *q);

#endif

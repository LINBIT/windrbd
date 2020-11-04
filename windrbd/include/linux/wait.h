#ifndef __WAIT_H__
#define __WAIT_H__
#include <wdm.h>
#include "linux/list.h"
#include "linux/spinlock.h"

struct wait_queue_entry
{
	struct list_head entry;
	KEVENT windows_event;
};

struct wait_queue_head
{
	spinlock_t lock;
	struct list_head head;
};

typedef struct wait_queue_head wait_queue_head_t;

static __inline void init_waitqueue_head(wait_queue_head_t *q)
{
	spin_lock_init(&q->lock);
	INIT_LIST_HEAD(&q->head);
};

#define DEFINE_WAIT(name) struct wait_queue_entry (name) = {	\
		.entry = LIST_HEAD_INIT((name).entry),		\
	};							\
	KeInitializeEvent(&(name).windows_event, SynchronizationEvent, FALSE);

void prepare_to_wait(struct wait_queue_head *w, struct wait_queue_entry *e, int interruptible);
void finish_wait(struct wait_queue_head *w, struct wait_queue_entry *e);

void schedule_debug(const char *file, int line, const char *func);
/* Returns -EINTR on signal else remaining time. */
LONG_PTR schedule_timeout_debug(LONG_PTR timeout, const char *file, int line, const char *func);
/* Returns -EINTR on signal else remaining time. Use only internally. */
/* TODO: better name for function */
LONG_PTR schedule_timeout_maybe_interrupted_debug(LONG_PTR timeout, const char *file, int line, const char *func);
LONG_PTR schedule_timeout_uninterruptible_debug(LONG_PTR timeout, const char *file, int line, const char *func);

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
	DEFINE_WAIT(__wait);						\
	while (1) {							\
		prepare_to_wait(&wait_queue, &__wait, interruptible);	\
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
	finish_wait(&wait_queue, &__wait);				\
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
	if (ret == -ETIMEDOUT) 						\
		ret = 0;						\
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
		timeout, TASK_INTERRUPTIBLE);				\
	if (ret == -ETIMEDOUT) 						\
		ret = 0;						\
} while (0);

void wake_up_debug(wait_queue_head_t *q, const char *file, int line, const char *func);
void wake_up_all_debug(wait_queue_head_t *q, const char *file, int line, const char *func);

#define wake_up(q) wake_up_debug(q, __FILE__, __LINE__, __func__)
#define wake_up_all(q) wake_up_all_debug(q, __FILE__, __LINE__, __func__)

#endif

#ifndef __WAIT_H__
#define __WAIT_H__
#include <wdm.h>
#include "linux/list.h"
#include "linux/spinlock.h"

/* TODO: location of this should probably be linux/wait.h */

	/* TODO: this is unused: */
typedef struct _wait_queue
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

#endif

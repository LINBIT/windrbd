#ifndef __WAIT_H__
#define __WAIT_H__
#include <wdm.h>
#include "linux/list.h"
#include "linux/spinlock.h"

typedef struct _wait_queue
{
    unsigned int flags;
    struct list_head task_list;
} wait_queue_t;

typedef struct __wait_queue_head
{
    spinlock_t lock;
    struct list_head task_list;
    KEVENT	wqh_event;
#define Q_NAME_SZ	16 
    char eventName[Q_NAME_SZ];
} wait_queue_head_t;

#define prepare_to_wait(a, b, c)

#define finish_wait(a, b)
#endif

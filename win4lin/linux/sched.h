#ifndef __SCHED_H__
#define __SCHED_H__

#include <linux/types.h>
#include "drbd_windows.h"

static __inline bool need_resched(void)
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
    (void)policy;
    (void)param;

    KeSetPriorityThread(p->pid, LOW_REALTIME_PRIORITY);
    return 0;
}


#endif

#ifndef __SCHED_H__
#define __SCHED_H__

#ifdef _WIN32
static __inline bool need_resched(void)
{
    return false;
}
#else
static __always_inline bool need_resched(void)
{
    return unlikely(tif_need_resched());
}
#endif


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

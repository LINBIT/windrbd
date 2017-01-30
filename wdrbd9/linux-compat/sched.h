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

#endif
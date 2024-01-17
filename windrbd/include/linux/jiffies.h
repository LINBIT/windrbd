#ifndef __JIFFIES_H__
#define __JIFFIES_H__

#include <stdint.h>
#include <linux/time64.h>
#include <linux/math64.h>
#include <linux/types.h>

#define HZ 1000

/* TODO: compute with HZ */
static inline unsigned long long JIFFIES()
{
	LARGE_INTEGER Tick;
	LARGE_INTEGER Elapse;
	KeQueryTickCount(&Tick);
	Elapse.QuadPart = Tick.QuadPart * KeQueryTimeIncrement();
	Elapse.QuadPart /= (10000);
// printk("KeQueryTimeIncrement is %lld tick count is %lld jiffies is %lld\n", KeQueryTimeIncrement(), Tick.QuadPart, Elapse.QuadPart);
	return Elapse.QuadPart;
}

#define jiffies	JIFFIES()

static inline unsigned int jiffies_to_msecs(const UINT64 j)
{
	return (unsigned int)j;
}

static inline u64 nsecs_to_jiffies(u64 n)
{
	return n / (NSEC_PER_SEC / HZ);
}

#endif

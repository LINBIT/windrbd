#ifndef __JIFFIES_H__
#define __JIFFIES_H__

#include <stdint.h>
#include <linux/time64.h>
#include <linux/types.h>

#define HZ 1000

__inline unsigned int jiffies_to_msecs(const UINT64 j)
{
	return (unsigned int)j;
}

__inline u64 nsecs_to_jiffies(u64 n)
{
	return n / (NSEC_PER_SEC / HZ);
}

#endif

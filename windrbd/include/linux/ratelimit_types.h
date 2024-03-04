#ifndef __LINUX_RATELIMIT_TYPES
#define __LINUX_RATELIMIT_TYPES

#include <linux/spinlock.h>

struct ratelimit_state {
	spinlock_t	lock;		/* protect the state */

	int		interval;
	int		burst;
	int		printed;
	int		missed;
	unsigned long	begin;
	unsigned long	flags;
};

#endif

#ifndef _LINUX_RATELIMIT_H
#define _LINUX_RATELIMIT_H

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


#define DEFAULT_RATELIMIT_INTERVAL	(5 * HZ)
#define DEFAULT_RATELIMIT_BURST		10

#define RATELIMIT_STATE_INIT(name, interval_init, burst_init) {		\
		.lock		= { 0 },				\
		.interval	= interval_init,			\
		.burst		= burst_init,				\
	}

#define DEFINE_RATELIMIT_STATE(name, interval_init, burst_init)		\
									\
	struct ratelimit_state name =					\
		RATELIMIT_STATE_INIT(name, interval_init, burst_init)	\

extern int ___ratelimit(struct ratelimit_state *rs, const char *func);

#endif /* _LINUX_RATELIMIT_H */

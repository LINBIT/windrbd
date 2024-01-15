#ifndef TIMER_H
#define TIMER_H

#include <linux/ktime.h>

#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)

#endif

#ifndef TIMER_H
#define TIMER_H

#define from_timer(var, callback_timer, timer_fieldname, type) \
	container_of(callback_timer, type, timer_fieldname)

#endif

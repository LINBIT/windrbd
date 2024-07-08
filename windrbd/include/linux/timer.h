#ifndef TIMER_H
#define TIMER_H

#include <linux/ktime.h>
#include <linux/types.h>

struct timer_list {
    KTIMER ktimer;
    KDPC dpc;
    void (*function)(struct timer_list *data);
    ULONG_PTR expires; 
};

extern void add_timer(struct timer_list *t);
extern int del_timer_sync(struct timer_list *t);
extern void del_timer(struct timer_list *t);
extern int mod_timer(struct timer_list *t, ULONG_PTR expires);
extern int timer_pending(const struct timer_list * timer);

extern int mod_timer_pending(struct timer_list *timer, ULONG_PTR expires);
void timer_setup(struct timer_list *timer, void(*callback)(struct timer_list *timer), ULONG_PTR flags_unused);

extern int timer_shutdown_sync(struct timer_list *timer);

#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)

#endif

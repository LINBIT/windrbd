#ifndef _SEMAPHORE_H
#define _SEMAPHORE_H

#include <linux/types.h>

struct semaphore {
    KSEMAPHORE sem;
};

extern void sema_init(struct semaphore *s, int limit);
extern void down(struct semaphore *s);
extern int down_trylock(struct semaphore *s);
/* TODO: implement: */
extern int down_interruptible(struct semaphore *sem);
extern void up(struct semaphore *s);

#endif

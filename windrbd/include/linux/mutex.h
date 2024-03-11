#ifndef __LINUX_MUTEX_H
#define __LINUX_MUTEX_H

#include <linux/types.h>

struct mutex {
	KMUTEX mtx;
};

extern void mutex_init(struct mutex *m);

/* TODO: those should return int. These are Linux functions */
extern NTSTATUS mutex_lock(struct mutex *m);
extern int mutex_lock_interruptible(struct mutex *m);
extern NTSTATUS mutex_lock_timeout(struct mutex *m, ULONG msTimeout);
extern int mutex_is_locked(struct mutex *m);
extern void mutex_unlock(struct mutex *m);
extern int mutex_trylock(struct mutex *m);

#define DEFINE_MUTEX(unused) \
Error Cannot implement DEFINE_MUTEX since we need to call KeInitializeMutex at runtime. Please manually patch your driver.

#endif

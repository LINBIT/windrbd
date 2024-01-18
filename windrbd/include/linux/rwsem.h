#ifndef _RWSEM_H
#define _RWSEM_H

#include <linux/semaphore.h>
#include <linux/kernel.h>

struct rw_semaphore {
	struct semaphore the_semaphore;
};

extern void init_rwsem(struct rw_semaphore *sem);
extern void down_write(struct rw_semaphore *sem);
extern void down_read(struct rw_semaphore *sem);
extern void down_read_non_owner(struct rw_semaphore *sem);
extern void up_write(struct rw_semaphore *sem);
extern void up_read(struct rw_semaphore *sem);
extern void up_read_non_owner(struct rw_semaphore *sem);
extern void downgrade_write(struct rw_semaphore *sem);

#define DECLARE_RWSEM(unused) \
Error Cannot implement DECLARE_RWSEM since we need to call KeInitializeSemaphore at runtime. Please manually patch your driver.

#endif

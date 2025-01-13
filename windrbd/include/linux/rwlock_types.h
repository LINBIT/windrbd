#ifndef __LINUX_RWLOCK_TYPES_H
#define __LINUX_RWLOCK_TYPES_H

#include <windrbd_config.h>

#ifndef CONFIG_HAVE_RW_LOCKS

	/* ReactOS, Windows 2003: don't have a working
	 * Shared/Exclusive spinlock implementation (yet).
	 * Note that DRBD 9.1 and DRBD 9.2 will lock up
	 * when there is I/O and we are connected (the
	 * normal case) so at the moment only DRBD 9.0
	 * works.
	 */

#include <linux/spinlock.h>

typedef struct rwlock {
	spinlock_t lock;
} rwlock_t;

#else

	/* 'normal' modern Windows (NT6 or later, I think
	 * NT6 was Vista).
	 */

#include <linux/types.h>

typedef struct rwlock {
	EX_SPIN_LOCK shared_exclusive_lock;
} rwlock_t;

#endif

#endif

#ifndef __LINUX_RWLOCK_TYPES_H
#define __LINUX_RWLOCK_TYPES_H

#include <linux/spinlock.h>

	/* TODO: we have shared/exclusive locks in Windows (but
	 * not (yet) in ReactOS).
	 */
typedef spinlock_t rwlock_t;

#endif

#ifndef __REFCOUNT_H
#define __REFCOUNT_H

#include <linux/types.h>

typedef struct refcount_struct {
	atomic_t refs;
} refcount_t;

#endif

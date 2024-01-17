#ifndef KREF_H
#define KREF_H

#include <linux/refcount.h>

struct kref {
	refcount_t refcount;
};

#endif

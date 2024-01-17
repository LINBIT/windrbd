#ifndef KREF_H
#define KREF_H

#include <linux/refcount.h>

/* TODO: somewhere else */
#include <linux/mm.h>

struct kref {
	refcount_t refcount;
};

#endif

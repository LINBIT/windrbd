#ifndef KREF_H
#define KREF_H

#include <linux/refcount.h>

/* TODO: somewhere else */
#include <linux/mm.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>
#include <linux/typecheck.h>
#include <linux/minmax.h>
#include <linux/overflow.h>

struct kref {
	refcount_t refcount;
};

#endif

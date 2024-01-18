#ifndef KREF_H
#define KREF_H

#include <linux/refcount.h>

struct kref {
	refcount_t refcount;
};

/* TODO: to somewhere else */
#include <linux/mm.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>
#include <linux/typecheck.h>
#include <linux/minmax.h>
#include <linux/overflow.h>
#include <linux/errno.h>
#include <linux/instruction_pointer.h>

#endif

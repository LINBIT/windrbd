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
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/numa.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/tm.h>
#include <linux/time.h>
#include <linux/umh.h>
#include <linux/backing-dev-defs.h>
#include <linux/kdev_t.h>
#include <asm/current.h>

#endif

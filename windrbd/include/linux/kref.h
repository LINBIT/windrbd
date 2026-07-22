#ifndef KREF_H
#define KREF_H

#include <linux/refcount.h>
#include <linux/spinlock.h>

struct kref {
	refcount_t refcount;
	spinlock_t spinlock;
};

extern int kref_put(struct kref *kref, void (*release)(struct kref *kref));
extern void kref_get(struct kref *kref);
extern void kref_init(struct kref *kref);

static inline bool kref_get_unless_zero(struct kref *kref)
{
	KIRQL flags;

	spin_lock_irqsave(&kref->spinlock, flags);
	if (atomic_read(&kref->refcount.refs) == 0) {
		spin_unlock_irqrestore(&kref->spinlock, flags);
		return 0;
	}
	kref_get(kref);

	spin_unlock_irqrestore(&kref->spinlock, flags);
	return 1;
}

#ifndef KREF_INIT
#define KREF_INIT(N) { .refcount = { .refs = ATOMIC_INIT(N) }, \
		       .spinlock = { 0 }, \
		     }
#endif

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
#include <linux/err.h>
#include <linux/atomic.h>
#include <asm-generic/bug.h>
#include <asm-generic/barrier.h>
#include <linux/prefetch.h>
#include <linux/stringify.h>
#include <linux/align.h>
#include <linux/random.h>
#include <linux/highmem.h>
#include <linux/kstrtox.h>
#include <linux/string.h>
#include <linux/sprintf.h>
#include <linux/panic.h>
#include <linux/math.h>
#include <linux/build_bug.h>
#include <linux/div64.h>
#include <linux/capability.h>
#include <linux/cpumask.h>
#include <linux/bitmap-str.h>
#include <asm-generic/getorder.h>
#include <linux/kmod.h>
#include <linux/array_size.h>
#include <linux/kconfig.h>
#include <linux/rwlock_types.h>
#include <linux/rwlock.h>
#include <linux/limits.h>
#include <linux/lockdep.h>
#include <linux/crypto.h>
#include <linux/pfn.h>
#include <asm/page.h>

/* TODO somewhere else: */
#define noinline_for_stack
#define __ro_after_init
#define __aligned(x)

#endif

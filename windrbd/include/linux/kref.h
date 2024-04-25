#ifndef KREF_H
#define KREF_H

#include <linux/refcount.h>

struct kref {
	refcount_t refcount;
};

#ifdef KREF_DEBUG

int kref_put_debug(struct kref *kref, void (*release)(struct kref *kref), const char *release_name, const char *file, int line, const char *func, int may_printk);
void kref_get_debug(struct kref *kref, const char *file, int line, const char *func, int may_printk);
void kref_init_debug(struct kref *kref, const char *file, int line, const char *func);

#define kref_put(kref, release) \
	kref_put_debug(kref, release, #release, __FILE__, __LINE__, __func__, 1)

#define kref_get(kref) \
	kref_get_debug(kref, __FILE__, __LINE__, __func__, 1)

#define kref_put_no_printk(kref, release) \
	kref_put_debug(kref, release, #release, __FILE__, __LINE__, __func__, 0)

#define kref_get_no_printk(kref) \
	kref_get_debug(kref, __FILE__, __LINE__, __func__, 0)

#define kref_init(kref) \
	kref_init_debug(kref, __FILE__, __LINE__, __func__)

#else

extern int kref_put(struct kref *kref, void (*release)(struct kref *kref));
extern void kref_get(struct kref *kref);
extern void kref_init(struct kref *kref);

/* See windrbd_winsocket.c */
#define kref_put_no_printk kref_put
#define kref_get_no_printk kref_get

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
#include <linux/bio.h>
#include <linux/kmod.h>

/* TODO somewhere else: */
#define noinline_for_stack
#define __ro_after_init
#define __aligned(x)

#endif

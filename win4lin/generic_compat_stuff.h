/* This file has to be in windows compatible format, no transformations */

#ifndef WDRBD9_GENERIC_COMPAT_STUFF
#define WDRBD9_GENERIC_COMPAT_STUFF

#define MODULE_AUTHOR(egal, ...)
#define MODULE_DESCRIPTION(egal, ...)
#define MODULE_VERSION(egal)
#define MODULE_LICENSE(egal)
#define MODULE_PARM_DESC(egal, ...)
#define MODULE_ALIAS_BLOCKDEV_MAJOR(egal)
#define MODULE_PARM_DESC(egal, ...)
#define EXPORT_SYMBOL(...)

#define module_init(...)
#define module_exit(...)
#define module_param(...)
#define module_param_string(...)
#define put_page(egal)
#define free_cpumask_var(...)
#define remove_proc_entry(...)
#define drbd_unregister_blkdev(...)
#define zalloc_cpumask_var(...) (true)
#define blk_queue_bounce_limit(...)
#define blk_queue_write_cache(...)
#define add_disk(...)

#define uninitialized_var(x) x = x
#define WARN(condition, ...) do {if(!!(condition)) printk(__VA_ARGS__);} while(0)
/* As good as it gets for now, don't know how to implement a true windows *ONCE* */
#define WARN_ONCE(condition, ...) WARN(condition, __VA_ARGS__)

/* not capable of anything... */
#define capable(x) (1)

#if 0
struct kmem_cache {
	NPAGED_LOOKASIDE_LIST cache;
};
#endif

#define swahw32(x) ( (__u32)((((__u32)(x) & (__u32)0x0000ffffUL)<<16) | (((__u32)(x) & (__u32)0xffff0000UL)>>16)) )

#define __always_inline inline
#define __inline inline

typedef char bool;
typedef int cpumask_var_t;

/* Yes, that'll be active for all structures...
 * But unless defined otherwise the compiler is free to choose alignment anyway. */
#define __packed

/* For shared/inaddr.h, struct in_addr */
#define FAR

#define BUILD_BUG_ON(expr)

/* Undefined if input is zero.
 * http://lxr.free-electrons.com/source/include/linux/bitops.h#L215 */
static inline int __ffs64(u64 i)
{
	int index, found;

	found = _BitScanForward64(&index, i);
	return found ? index : 0;
}

struct module {
	char version[1];
};

static inline void module_put(void *module)
{
    (void)module;
}

static inline void request_module(const char *fmt, ...)
{
    (void)fmt;
}

static inline int try_module_get(void *m)
{
    (void)m;
    return 1;
}

#define bdput(this_bdev) do { \
	kfree2(this_bdev->bd_contains); \
	kfree2(this_bdev); \
} while(0)

static inline void* __vmalloc(u64 bytes, int flags, int flags2)
{
    (void)bytes;
    (void)flags;
    (void)flags2;
    /* NULL not defined yet */
    return (void*)0;
}

/* Taken from include/asm-generic/div64.h */
static inline u32 _do_div_fn(u64 *n, u32 base)
{
        u32 rem;
        rem = (*n) % base;
	*n  = (*n) / base;
        return rem;
}

#define do_div(n, base) _do_div_fn(&(n), (base))
#define sector_div(n, base) _do_div_fn(&(n), (base))

static inline void might_sleep() { }

#define blk_start_plug(egal)
#define blk_finish_plug(egal)

#define xchg_ptr(__target, __value) (  (void*)xchg(  (LONG_PTR*)(__target), (LONG_PTR)(__value)  )  )

/* Doesn't seem to be available.
 * http://stackoverflow.com/questions/29010214/winsock-msg-dontwait-equivalent */
#define MSG_DONTWAIT 0

#define __printf(a, b) /* nothing */

#define CRYPTO_MAX_ALG_NAME (64)

#define spin_lock_nested(__lock, __subclass) spin_lock(__lock)

#endif

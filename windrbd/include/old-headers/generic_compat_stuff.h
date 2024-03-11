/* This file has to be in windows compatible format, no transformations */

#ifndef WDRBD9_GENERIC_COMPAT_STUFF
#define WDRBD9_GENERIC_COMPAT_STUFF

#include <stdarg.h>

#define EXPORT_SYMBOL(...)

#define module_init(...)
#define module_exit(...)
#define module_param(...)
#define module_param_string(...)
#define free_cpumask_var(...)
#define remove_proc_entry(...)
#define drbd_unregister_blkdev(...)
#define zalloc_cpumask_var(...) (true)
#define blk_queue_bounce_limit(...)
#define blk_queue_write_cache(...)

#define uninitialized_var(x) x = x
#define WARN(condition, args...) do {if(!!(condition)) printk(args);} while(0)
/* As good as it gets for now, don't know how to implement a true windows *ONCE* */
#define WARN_ONCE(condition, args...) WARN(condition, args)

/* not capable of anything... */
#define capable(x) (1)

#if 0
struct kmem_cache {
	NPAGED_LOOKASIDE_LIST cache;
};
#endif

#define swahw32(x) ( (__u32)((((__u32)(x) & (__u32)0x0000ffffUL)<<16) | (((__u32)(x) & (__u32)0xffff0000UL)>>16)) )

#define __always_inline inline
// #define __inline inline

typedef int cpumask_var_t;

/* Yes, that'll be active for all structures...
 * But unless defined otherwise the compiler is free to choose alignment anyway. */

#ifndef __packed
#define __packed
#endif

/* For shared/inaddr.h, struct in_addr */
#define FAR

#define BUILD_BUG_ON(expr)


/* Undefined if input is zero.
 * http://lxr.free-electrons.com/source/include/linux/bitops.h#L215 */
static inline int __ffs(u64 i)
{
	ULONG index, found;

#if BITS_PER_LONG == 32
	found = _BitScanForward(&index, i);
#else
	found = _BitScanForward64(&index, i);
#endif
	return found ? index : 0;
}

/**
 * __ffs64 - find first set bit in a 64 bit word
 * @word: The 64 bit word
 *
 * On 64 bit arches this is a synonym for __ffs
 * The result is not defined if no bits are set, so check that @word
 * is non-zero before calling this.
 */
static inline ULONG_PTR __ffs64(u64 word)
{
#if BITS_PER_LONG == 32
	if (((u32)word) == 0UL)
		return __ffs((u32)(word >> 32)) + 32;
#elif BITS_PER_LONG != 64
#error BITS_PER_LONG not 32 or 64
#endif
	return __ffs((ULONG_PTR)word);
}

/* TODO: what does this? */
static inline void request_module(const char *fmt, ...)
{
    (void)fmt;
}

/* This is just a fallback version for kmalloc in case
 * kmalloc fails.
 */

static inline void* __vmalloc(u64 bytes, int flags)
{
    (void)bytes;
    (void)flags;
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

#define __printf(a, b) /* nothing */

#define CRYPTO_MAX_ALG_NAME (64)

char *kvasprintf(int flags, const char *fmt, va_list args);


#endif

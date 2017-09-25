/*
 *  include/linux/ktime.h
 *
 *  ktime_t - nanosecond-resolution time format.
 *
 *   Copyright(C) 2005, Thomas Gleixner <tglx@linutronix.de>
 *   Copyright(C) 2005, Red Hat, Inc., Ingo Molnar
 *
 *  data type definitions, declarations, prototypes and macros.
 *
 *  Started by: Thomas Gleixner and Ingo Molnar
 *
 *  Credits:
 *
 *  	Roman Zippel provided the ideas and primary code snippets of
 *  	the ktime_t union and further simplifications of the original
 *  	code.
 *
 *  For licencing details see kernel-base/COPYING
 */
#ifndef _LINUX_KTIME_H
#define _LINUX_KTIME_H

/* #include <linux/time.h> */
#include <linux/jiffies.h>

/* From: time64.h */
/* Parameters used to convert the timespec values: */
#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define NSEC_PER_USEC   1000L
#define NSEC_PER_MSEC   1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL

/* Located here for timespec[64]_valid_strict */
#define TIME64_MAX                      ((s64)~((u64)1 << 63))
#define KTIME_MAX                       ((s64)~((u64)1 << 63))
#define KTIME_SEC_MAX                   (KTIME_MAX / NSEC_PER_SEC)

/*
 * ktime_t:
 *
 * A single 64-bit variable is used to store the hrtimers
 * internal representation of time values in scalar nanoseconds. The
 * design plays out best on 64-bit CPUs, where most conversions are
 * NOPs and most arithmetic ktime_t operations are plain arithmetic
 * operations.
 *
 */
union ktime {
	s64	tv64;
};

typedef union ktime ktime_t;		/* Kill this */

/**
 * ktime_set - Set a ktime_t variable from a seconds/nanoseconds value
 * @secs:	seconds to set
 * @nsecs:	nanoseconds to set
 *
 * Return: The ktime_t representation of the value.
 */
static inline ktime_t ktime_set(const s64 secs, const unsigned long nsecs)
{
	if (unlikely(secs >= KTIME_SEC_MAX))
		return (ktime_t){ .tv64 = KTIME_MAX };

	return (ktime_t) { .tv64 = secs * NSEC_PER_SEC + (s64)nsecs };
}

/* Subtract two ktime_t variables. rem = lhs -rhs: */
static inline ktime_t ktime_sub(const ktime_t lhs, const ktime_t rhs)
{
	return (ktime_t) { .tv64 = (lhs).tv64 - (rhs).tv64 };
}

/* Add two ktime_t variables. res = lhs + rhs: */
static inline ktime_t ktime_add(const ktime_t lhs, const ktime_t rhs)
{
	return (ktime_t) { .tv64 = (lhs).tv64 + (rhs).tv64 };
}

/*
 * Same as ktime_add(), but avoids undefined behaviour on overflow; however,
 * this means that you must check the result for overflow yourself.
 */
static inline ktime_t ktime_add_unsafe(const ktime_t lhs, const ktime_t rhs)
{
	return (ktime_t){ .tv64 = (u64) (lhs).tv64 + (rhs).tv64 };
}

/*
 * Add a ktime_t variable and a scalar nanosecond value.
 * res = kt + nsval:
 */
static inline ktime_t ktime_add_ns(const ktime_t kt, const u64 nsval)
{
	return (ktime_t){ .tv64 = (kt).tv64 + (nsval) };
}

/*
 * Subtract a scalar nanosecod from a ktime_t variable
 * res = kt - nsval:
 */
static inline ktime_t ktime_sub_ns(const ktime_t kt, const u64 nsval)
{
	return (ktime_t){ .tv64 = (kt).tv64 - (nsval) };
}

/**
 * ktime_equal - Compares two ktime_t variables to see if they are equal
 * @cmp1:	comparable1
 * @cmp2:	comparable2
 *
 * Compare two ktime_t variables.
 *
 * Return: 1 if equal.
 */
static inline int ktime_equal(const ktime_t cmp1, const ktime_t cmp2)
{
	return cmp1.tv64 == cmp2.tv64;
}

/**
 * ktime_compare - Compares two ktime_t variables for less, greater or equal
 * @cmp1:	comparable1
 * @cmp2:	comparable2
 *
 * Return: ...
 *   cmp1  < cmp2: return <0
 *   cmp1 == cmp2: return 0
 *   cmp1  > cmp2: return >0
 */
static inline int ktime_compare(const ktime_t cmp1, const ktime_t cmp2)
{
	if (cmp1.tv64 < cmp2.tv64)
		return -1;
	if (cmp1.tv64 > cmp2.tv64)
		return 1;
	return 0;
}

/**
 * ktime_after - Compare if a ktime_t value is bigger than another one.
 * @cmp1:	comparable1
 * @cmp2:	comparable2
 *
 * Return: true if cmp1 happened after cmp2.
 */
static inline bool ktime_after(const ktime_t cmp1, const ktime_t cmp2)
{
	return ktime_compare(cmp1, cmp2) > 0;
}

/**
 * ktime_before - Compare if a ktime_t value is smaller than another one.
 * @cmp1:	comparable1
 * @cmp2:	comparable2
 *
 * Return: true if cmp1 happened before cmp2.
 */
static inline bool ktime_before(const ktime_t cmp1, const ktime_t cmp2)
{
	return ktime_compare(cmp1, cmp2) < 0;
}

#if BITS_PER_LONG < 64
extern s64 __ktime_divns(const ktime_t kt, s64 div);
static inline s64 ktime_divns(const ktime_t kt, s64 div)
{
	/*
	 * Negative divisors could cause an inf loop,
	 * so bug out here.
	 */
	BUG_ON(div < 0);
	if (__builtin_constant_p(div) && !(div >> 32)) {
		s64 ns = kt.tv64;
		u64 tmp = ns < 0 ? -ns : ns;

		do_div(tmp, div);
		return ns < 0 ? -tmp : tmp;
	} else {
		return __ktime_divns(kt, div);
	}
}
#else /* BITS_PER_LONG < 64 */
static inline s64 ktime_divns(const ktime_t kt, s64 div)
{
	/*
	 * 32-bit implementation cannot handle negative divisors,
	 * so catch them on 64bit as well.
	 */
	WARN_ON(div < 0);
	return kt.tv64 / div;
}
#endif

static inline s64 ktime_to_us(const ktime_t kt)
{
	return ktime_divns(kt, NSEC_PER_USEC);
}

static inline s64 ktime_to_ms(const ktime_t kt)
{
	return ktime_divns(kt, NSEC_PER_MSEC);
}

static inline s64 ktime_us_delta(const ktime_t later, const ktime_t earlier)
{
       return ktime_to_us(ktime_sub(later, earlier));
}

static inline s64 ktime_ms_delta(const ktime_t later, const ktime_t earlier)
{
	return ktime_to_ms(ktime_sub(later, earlier));
}

static inline ktime_t ktime_add_us(const ktime_t kt, const u64 usec)
{
	return ktime_add_ns(kt, usec * NSEC_PER_USEC);
}

static inline ktime_t ktime_add_ms(const ktime_t kt, const u64 msec)
{
	return ktime_add_ns(kt, msec * NSEC_PER_MSEC);
}

static inline ktime_t ktime_sub_us(const ktime_t kt, const u64 usec)
{
	return ktime_sub_ns(kt, usec * NSEC_PER_USEC);
}

static inline ktime_t ktime_sub_ms(const ktime_t kt, const u64 msec)
{
	return ktime_sub_ns(kt, msec * NSEC_PER_MSEC);
}

extern ktime_t ktime_add_safe(const ktime_t lhs, const ktime_t rhs);

/*
 * The resolution of the clocks. The resolution value is returned in
 * the clock_getres() system call to give application programmers an
 * idea of the (in)accuracy of timers. Timer values are rounded up to
 * this resolution values.
 */
#define LOW_RES_NSEC		TICK_NSEC
#define KTIME_LOW_RES		(ktime_t){ .tv64 = LOW_RES_NSEC }

static inline ktime_t ns_to_ktime(u64 ns)
{
	static const ktime_t ktime_zero = { .tv64 = 0 };

	return ktime_add_ns(ktime_zero, ns);
}

static inline ktime_t ms_to_ktime(u64 ms)
{
	static const ktime_t ktime_zero = { .tv64 = 0 };

	return ktime_add_ms(ktime_zero, ms);
}

/* # include <linux/timekeeping.h> */

extern ktime_t ktime_get(void);

#endif

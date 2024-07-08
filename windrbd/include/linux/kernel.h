#ifndef __KERNEL_H__
#define __KERNEL_H__

#include <linux/types.h>	/* for uint64_t */
#include <linux/printk.h>
#include <linux/container_of.h>
#include <linux/export.h>
#include <linux/err.h>

/* defined in stdlib.h which is included by some reactos header.
 * which is TODO: probably not a good idea.
 */
// #define ULLONG_MAX	(~0ULL)

/* We have neither typeof() nor blocks in macros. So we define
 * this as a function. If you need signed values, you need to
 * touch this (DRBD currently does not).
 */

uint64_t roundup(uint64_t x, uint64_t y);

#define READ					0
#define WRITE					1

static inline void might_sleep() { }


/**
 * upper_32_bits - return bits 32-63 of a number
 * @n: the number we're accessing
 *
 * A basic shift-right of a 64- or 32-bit quantity.  Use this to suppress
 * the "right shift count >= width of type" warning when that quantity is
 * 32-bits.
 */
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

/**
 * lower_32_bits - return bits 0-31 of a number
 * @n: the number we're accessing
 */
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))

/**
 * upper_16_bits - return bits 16-31 of a number
 * @n: the number we're accessing
 */
#define upper_16_bits(n) ((u16)((n) >> 16))

/**
 * lower_16_bits - return bits 0-15 of a number
 * @n: the number we're accessing
 */
#define lower_16_bits(n) ((u16)((n) & 0xffff))

#endif

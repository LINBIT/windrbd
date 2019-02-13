#ifndef __KERNEL_H__
#define __KERNEL_H__

#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#endif

#define ULLONG_MAX	(~0ULL)

/* We have neither typeof() nor blocks in macros. So we define
 * this as a function. If you need signed values, you need to
 * touch this (DRBD currently does not).
 */

uint64_t roundup(uint64_t x, uint64_t y);

#endif

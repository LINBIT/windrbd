#ifndef __KERNEL_H__
#define __KERNEL_H__

#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#endif

#define ULLONG_MAX	(~0ULL)

#endif

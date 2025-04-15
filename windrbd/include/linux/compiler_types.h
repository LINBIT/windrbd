#ifndef __COMPILER_TYPES_H
#define __COMPILER_TYPES_H

#include <linux/compiler_attributes.h>

#define __releases(unused)
#define __acquire(x) (void)0
#define __release(x) (void)0
	/* Nothing: */
#define __rcu
#define __must_hold(x)

#define __force
#define __user

/* Are two types/vars the same type (ignoring qualifiers)? */
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

	/* TODO: Somehow this does not work with our gcc ... ignoring for now */
	/* Has something to do with DRBD: in DRBD 9.1 this works: */

#ifndef WINNT_52

# define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		/*							\
		 * __noreturn is needed to give the compiler enough	\
		 * information to avoid certain possibly-uninitialized	\
		 * warnings (regardless of the build failing).		\
		 */							\
		__noreturn extern void prefix ## suffix(void)		\
			__compiletime_error(msg);			\
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)
#else

/* REACTOS */
	/* Nothing. at least with MinGW i686 and drbd-9.1 the
	 * above definitions do not work.
	 */

#define __compiletime_assert(condition, msg, prefix, suffix)

#endif

#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)

/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)

/*
 * Optional: only supported since gcc >= 15
 * Optional: only supported since clang >= 18
 *
 *   gcc: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108896
 * clang: https://github.com/llvm/llvm-project/pull/76348
 *
 * __bdos on clang < 19.1.2 can erroneously return 0:
 * https://github.com/llvm/llvm-project/pull/110497
 *
 * __bdos on clang < 19.1.3 can be off by 4:
 * https://github.com/llvm/llvm-project/pull/112636
 */
#ifdef CONFIG_CC_HAS_COUNTED_BY
# define __counted_by(member)		__attribute__((__counted_by__(member)))
#else
# define __counted_by(member)
#endif

#endif

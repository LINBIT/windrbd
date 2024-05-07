#ifndef __COMPILER_H
#define __COMPILER_H

#include <linux/compiler_types.h>
#include <linux/compiler_attributes.h>
#include <linux/build_bug.h>

#define WRITE_ONCE(var, val) \
	(*((volatile typeof(val) *)(&(var))) = (val))

#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))

/* &a[0] degrades to a pointer: a different type from an array */
#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

#define __maybe_unused

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#define likely_notrace(x)	likely(x)
#define unlikely_notrace(x)	unlikely(x)

/* &a[0] degrades to a pointer: a different type from an array */
#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

#endif


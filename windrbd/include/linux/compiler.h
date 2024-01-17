#ifndef __COMPILER_H
#define __COMPILER_H

#include <linux/compiler_types.h>
#include <linux/compiler_attributes.h>

/* &a[0] degrades to a pointer: a different type from an array */
#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

#define __maybe_unused

#endif


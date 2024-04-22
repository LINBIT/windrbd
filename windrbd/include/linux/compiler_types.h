#ifndef __COMPILER_TYPES_H
#define __COMPILER_TYPES_H

#define __releases(unused)
#define __acquire(x) (void)0
#define __release(x) (void)0

#define __force
#define __user

/* Are two types/vars the same type (ignoring qualifiers)? */
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

#define compiletime_assert(condition, msg) do { } while (0)

#endif

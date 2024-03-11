#ifndef __LINUX_PREFETCH_H
#define __LINUX_PREFETCH_H

#define prefetch(x) __builtin_prefetch(x)

#endif

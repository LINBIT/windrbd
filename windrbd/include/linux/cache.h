#ifndef __LINUX_CACHE_H
#define __LINUX_CACHE_H

#define __read_mostly

/* or so ... */
#define SMP_CACHE_BYTES 16

#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

#endif

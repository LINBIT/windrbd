#ifndef __ASM_GENERIC_BARRIER_H
#define __ASM_GENERIC_BARRIER_H

extern void flush_all_cpu_caches(void);

#define smp_mb() flush_all_cpu_caches()
#define smp_rmb() flush_all_cpu_caches()
#define smp_wmb() flush_all_cpu_caches()

#endif

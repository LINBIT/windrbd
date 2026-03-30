#ifndef CPUMASK_H
#define CPUMASK_H

#include <linux/slab.h>

typedef struct cpumask { ULONG_PTR mask; } cpumask_t;
typedef cpumask_t *cpumask_var_t;

/* TODO: this should disable cpu_mask which we do not have on
 * Windows ...
 */
#define nr_cpu_ids 1

#define cpumask_bits(maskp) (ULONG_PTR*)((maskp)->mask)

static inline void cpumask_setall(struct cpumask *m)
{
	m->mask = ~0;
}

static inline bool cpumask_and(struct cpumask *dstp,
			       const struct cpumask *src1p,
			       const struct cpumask *src2p)
{
	dstp->mask = src1p->mask & src2p->mask;
	return dstp->mask != 0;
}

static inline bool cpumask_empty(const struct cpumask *srcp)
{
	return srcp->mask == 0;
}

static inline bool cpumask_equal(const struct cpumask *src1p,
				const struct cpumask *src2p)
{
	return src1p->mask == src2p->mask;
}

static inline void cpumask_copy(struct cpumask *dstp,
				const struct cpumask *srcp)
{
	dstp->mask = srcp->mask;
}

static inline void free_cpumask_var(cpumask_var_t mask)
{
	kfree(mask);
}

static inline bool zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	cpumask_var_t new_mask = kzalloc(sizeof(*new_mask), flags);
	if (new_mask != NULL) {
		*mask = new_mask;
		return true;
	}
	return false;
}

#endif

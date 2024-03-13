#ifndef CPUMASK_H
#define CPUMASK_H

typedef struct cpumask { int mask; } cpumask_t;
typedef cpumask_t *cpumask_var_t;


/* TODO: this should disable cpu_mask which we do not have on
 * Windows ...
 */
#define nr_cpu_ids 1

#define cpumask_bits(maskp) (maskp)->mask
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
}

static inline bool zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	return true;
}

#endif

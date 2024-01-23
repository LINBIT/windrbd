#ifndef CPUMASK_H
#define CPUMASK_H

typedef int cpumask_var_t;

/* TODO: this should disable cpu_mask which we do not have on
 * Windows ...
 */
#define nr_cpu_ids 1

#endif

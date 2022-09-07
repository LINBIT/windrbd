#ifndef PART_STAT_H
#define PART_STAT_H

enum stat_group {
	STAT_READ,
	STAT_WRITE,
	STAT_DISCARD,
	STAT_FLUSH,

	NR_STAT_GROUPS
};


struct disk_stats {
//	u64 nsecs[NR_STAT_GROUPS];
	ULONG_PTR sectors[NR_STAT_GROUPS];
/*
	unsigned long ios[NR_STAT_GROUPS];
	unsigned long merges[NR_STAT_GROUPS];
	unsigned long io_ticks;
	local_t in_flight[2];
*/
};

#define part_stat_read(part, field) \
	((part)->bd_stats.field)

#define part_stat_read_accum(part, field)				\
	(part_stat_read(part, field[STAT_READ]) +			\
	 part_stat_read(part, field[STAT_WRITE]) +			\
	 part_stat_read(part, field[STAT_DISCARD]))


#define part_stat_add(part, field, addnd)	do {			\
	(part)->bd_stats.field += addnd;				\
} while (0)

#define part_stat_dec(part, field)					\
	part_stat_add(part, field, -1)
#define part_stat_inc(part, field)					\
	part_stat_add(part, field, 1)
#define part_stat_sub(part, field, subnd)				\
	part_stat_add(part, field, -subnd)

#endif

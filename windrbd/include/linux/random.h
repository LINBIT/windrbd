#ifndef __LINUX_RANDOM_H
#define __LINUX_RANDOM_H

#include <linux/types.h>

extern void get_random_bytes(void *buf, int nbytes);

static inline u32 prandom_u32(void)
{
	u32 buf;

	get_random_bytes((char*) &buf, sizeof(buf));
	return buf;
}

#endif

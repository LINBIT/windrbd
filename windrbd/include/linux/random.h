#ifndef __LINUX_RANDOM_H
#define __LINUX_RANDOM_H

#include <linux/types.h>
#include <linux/log2.h>

extern void get_random_bytes(void *buf, int nbytes);

static inline u8 get_random_u8(void)
{
	u8 buf;

	get_random_bytes((char*) &buf, sizeof(buf));
	return buf;
}

static inline u16 get_random_u16(void)
{
	u16 buf;

	get_random_bytes((char*) &buf, sizeof(buf));
	return buf;
}

static inline u32 prandom_u32(void)
{
	u32 buf;

	get_random_bytes((char*) &buf, sizeof(buf));
	return buf;
}

static inline u32 get_random_u32(void)
{
	return prandom_u32();
}

/*
 * Returns a random integer in the interval [0, ceil), with uniform
 * distribution, suitable for all uses. Fastest when ceil is a constant, but
 * still fast for variable ceil as well.
 */
static inline u32 get_random_u32_below(u32 ceil)
{
	if (ceil <= 1)
		return 0;
	for (;;) {
		if (ceil <= 1U << 8) {
			u32 mult = ceil * get_random_u8();
			if (likely(is_power_of_2(ceil) || (u8)mult >= (1U << 8) % ceil))
				return mult >> 8;
		} else if (ceil <= 1U << 16) {
			u32 mult = ceil * get_random_u16();
			if (likely(is_power_of_2(ceil) || (u16)mult >= (1U << 16) % ceil))
				return mult >> 16;
		} else {
			u64 mult = (u64)ceil * get_random_u32();
			if (likely(is_power_of_2(ceil) || (u32)mult >= -ceil % ceil))
				return mult >> 32;
		}
	}
}
#endif

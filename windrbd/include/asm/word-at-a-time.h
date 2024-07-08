/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_WORD_AT_A_TIME_H
#define _ASM_WORD_AT_A_TIME_H

#include <linux/kernel.h>
#include <asm/byteorder.h>

/**
 * REPEAT_BYTE - repeat the value @x multiple times as an unsigned long value
 * @x: value to repeat
 *
 * NOTE: @x is not checked for > 0xff; larger values produce odd results.
 */
#define REPEAT_BYTE(x)	((~0ul / 0xff) * (x))

#ifdef __BIG_ENDIAN

struct word_at_a_time {
	const ULONG_PTR high_bits, low_bits;
};

#define WORD_AT_A_TIME_CONSTANTS { REPEAT_BYTE(0xfe) + 1, REPEAT_BYTE(0x7f) }

/* Bit set in the bytes that have a zero */
static inline LONG_PTR prep_zero_mask(ULONG_PTR val, ULONG_PTR rhs, const struct word_at_a_time *c)
{
	ULONG_PTR mask = (val & c->low_bits) + c->low_bits;
	return ~(mask | rhs);
}

#define create_zero_mask(mask) (mask)

static inline LONG_PTR find_zero(ULONG_PTR mask)
{
	LONG_PTR byte = 0;
#ifdef CONFIG_64BIT
	if (mask >> 32)
		mask >>= 32;
	else
		byte = 4;
#endif
	if (mask >> 16)
		mask >>= 16;
	else
		byte += 2;
	return (mask >> 8) ? byte : byte + 1;
}

static inline ULONG_PTR has_zero(ULONG_PTR val, ULONG_PTR *data, const struct word_at_a_time *c)
{
	ULONG_PTR rhs = val | c->low_bits;
	*data = rhs;
	return (val + c->high_bits) & ~rhs;
}

#ifndef zero_bytemask
#define zero_bytemask(mask) (~1ul << __fls(mask))
#endif

#else

/*
 * The optimal byte mask counting is probably going to be something
 * that is architecture-specific. If you have a reliably fast
 * bit count instruction, that might be better than the multiply
 * and shift, for example.
 */
struct word_at_a_time {
	const ULONG_PTR one_bits, high_bits;
};

#define WORD_AT_A_TIME_CONSTANTS { REPEAT_BYTE(0x01), REPEAT_BYTE(0x80) }

#ifdef CONFIG_64BIT

/*
 * Jan Achrenius on G+: microoptimized version of
 * the simpler "(mask & ONEBYTES) * ONEBYTES >> 56"
 * that works for the bytemasks without having to
 * mask them first.
 */
static inline LONG_PTR count_masked_bytes(ULONG_PTR mask)
{
	return mask*0x0001020304050608ul >> 56;
}

#else	/* 32-bit case */

/* Carl Chatfield / Jan Achrenius G+ version for 32-bit */
static inline LONG_PTR count_masked_bytes(LONG_PTR mask)
{
	/* (000000 0000ff 00ffff ffffff) -> ( 1 1 2 3 ) */
	LONG_PTR a = (0x0ff0001+mask) >> 23;
	/* Fix the 1 for 00 case */
	return a & mask;
}

#endif

/* Return nonzero if it has a zero */
static inline ULONG_PTR has_zero(ULONG_PTR a, ULONG_PTR *bits, const struct word_at_a_time *c)
{
	ULONG_PTR mask = ((a - c->one_bits) & ~a) & c->high_bits;
	*bits = mask;
	return mask;
}

static inline ULONG_PTR prep_zero_mask(ULONG_PTR a, ULONG_PTR bits, const struct word_at_a_time *c)
{
	return bits;
}

static inline ULONG_PTR create_zero_mask(ULONG_PTR bits)
{
	bits = (bits - 1) & ~bits;
	return bits >> 7;
}

/* The mask we created is directly usable as a bytemask */
#define zero_bytemask(mask) (mask)

static inline ULONG_PTR find_zero(ULONG_PTR mask)
{
	return count_masked_bytes(mask);
}

#endif /* __BIG_ENDIAN */


ULONG_PTR read_word_at_a_time(const void *addr)
{
	return *(ULONG_PTR *)addr;
}


#endif /* _ASM_WORD_AT_A_TIME_H */

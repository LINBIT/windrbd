#ifndef __BITOPS_H__
#define __BITOPS_H__

#include "linux/hweight.h"
#include <linux/bitsperlong.h>
#include <linux/types.h>
#include <linux/find.h>

#include <asm-generic/bitops/builtin-__fls.h>
#include <asm-generic/bitops/fls.h>
#include <asm-generic/bitops/fls64.h>

static inline void barrier(void)
{
	KeMemoryBarrier();
}

#define BIT_MASK(_nr)				(1ULL << ((_nr) % BITS_PER_LONG))
#define BIT_WORD(_nr)				((_nr) / BITS_PER_LONG)

	/* In 2024 we can safely assume this: */
#define BITS_PER_BYTE 8

#define BITS_PER_TYPE(type)	(sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)	__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(long))
#define BITS_TO_U64(nr)		__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(u64))
#define BITS_TO_U32(nr)		__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(u32))
#define BITS_TO_BYTES(nr)	__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(char))

extern int test_and_change_bit(int nr, volatile ULONG_PTR *vaddr);

static inline int test_and_set_bit(int bit, volatile ULONG_PTR * base)
{
#ifdef _WIN64
    return (InterlockedBitTestAndSet64((volatile __int64 *)base, bit));
#else
    return (InterlockedBitTestAndSet((volatile LONG_PTR *)base, bit));
#endif
}

static inline int test_and_clear_bit(int bit, volatile ULONG_PTR * base)
{
#ifdef _WIN64
    return (InterlockedBitTestAndReset64((volatile __int64 *)base, bit));
#else
    return (InterlockedBitTestAndReset((volatile LONG_PTR *)base, bit));
#endif
}

static inline void set_bit(int bit, volatile ULONG_PTR * base)
{
    test_and_set_bit(bit, base);
}

static inline void clear_bit(int bit, volatile ULONG_PTR * base)
{
    test_and_clear_bit(bit, base);
}

static inline void clear_bit_unlock(int bit, volatile ULONG_PTR * base)
{
    barrier();
    test_and_clear_bit(bit, base);
}

#define __clear_bit(__n, __p) clear_bit(__n, __p)

static inline void __set_bit(int nr, volatile ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);

	*p |= mask;
}

static inline int __test_and_set_bit(int nr, volatile ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);
	ULONG_PTR old = *p;

	*p = old | mask;
	return (old & mask) != 0;
}

static inline int __test_and_clear_bit(int nr, volatile ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);
	ULONG_PTR old = *p;

	*p = old & ~mask;
	return (old & mask) != 0;
}

static inline int test_bit(int nr, const ULONG_PTR *addr)
{
#ifdef _WIN64
	return _bittest64((LONG64 *)addr, nr);
#else
	return _bittest((LONG_PTR *)addr, nr);
#endif
}

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define generic_test_le_bit(nr, addr)			test_bit(nr, addr)
#define generic___test_and_set_le_bit(nr, addr)		__test_and_set_bit(nr, addr)
#define generic___test_and_clear_le_bit(nr, addr)	__test_and_clear_bit(nr, addr)
#define generic_find_next_zero_le_bit(addr, size, offset) find_next_zero_bit(addr, size, offset)
#define generic_find_next_le_bit(addr, size, offset)	find_next_bit(addr, size, offset)
#endif

/* Undefined if input is zero.
 * http://lxr.free-electrons.com/source/include/linux/bitops.h#L215 */
static inline int __ffs(u64 i)
{
	ULONG index, found;

#if BITS_PER_LONG == 32
	found = _BitScanForward(&index, i);
#else
	found = _BitScanForward64(&index, i);
#endif
	return found ? index : 0;
}

/**
 * __ffs64 - find first set bit in a 64 bit word
 * @word: The 64 bit word
 *
 * On 64 bit arches this is a synonym for __ffs
 * The result is not defined if no bits are set, so check that @word
 * is non-zero before calling this.
 */
static inline ULONG_PTR __ffs64(u64 word)
{
#if BITS_PER_LONG == 32
	if (((u32)word) == 0UL)
		return __ffs((u32)(word >> 32)) + 32;
#elif BITS_PER_LONG != 64
#error BITS_PER_LONG not 32 or 64
#endif
	return __ffs((ULONG_PTR)word);
}

static inline unsigned fls_long(ULONG_PTR l)
{
	if (sizeof(l) == 4)
		return fls(l);
	return fls64(l);
}

#include <asm-generic/bitops/le.h>

#endif

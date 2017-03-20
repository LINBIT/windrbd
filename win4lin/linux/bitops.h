#ifndef __BITOPS_H__
#define __BITOPS_H__

#include "linux/hweight.h"

extern int test_and_change_bit(int nr, const ULONG_PTR *vaddr);
#ifdef _WIN32
extern ULONG_PTR find_first_bit(const ULONG_PTR* addr, ULONG_PTR size); //reference linux 3.x kernel. 64bit compatible
#endif
extern ULONG_PTR find_next_bit(const ULONG_PTR *addr, ULONG_PTR size, ULONG_PTR offset);
extern int find_next_zero_bit(const ULONG_PTR * addr, ULONG_PTR size, ULONG_PTR offset);

__inline
int test_and_set_bit(int bit, volatile ULONG_PTR * base)
{
#ifdef _WIN64
    return (InterlockedBitTestAndSet64((volatile __int64 *)base, bit));
#else
    return (InterlockedBitTestAndSet((volatile long *)base, bit));
#endif
}

__inline
int test_and_clear_bit(int bit, volatile ULONG_PTR * base)
{
#ifdef _WIN64
    return (InterlockedBitTestAndReset64((volatile __int64 *)base, bit));
#else
    return (InterlockedBitTestAndReset((volatile long *)base, bit));
#endif
}

__inline
void set_bit(int bit, volatile ULONG_PTR * base)
{
    test_and_set_bit(bit, base);
}

__inline
void clear_bit(int bit, volatile ULONG_PTR * base)
{
    test_and_clear_bit(bit, base);
}

#define __clear_bit(__n, __p) clear_bit(__n, __p)

static __inline void __set_bit(int nr, volatile ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);

	*p |= mask;
}

static __inline int __test_and_set_bit(int nr, volatile ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);
	ULONG_PTR old = *p;

	*p = old | mask;
	return (old & mask) != 0;
}

static __inline int __test_and_clear_bit(int nr, volatile ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);
	ULONG_PTR old = *p;

	*p = old & ~mask;
	return (old & mask) != 0;
}

static __inline int test_bit(int nr, const ULONG_PTR *addr)
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

#endif

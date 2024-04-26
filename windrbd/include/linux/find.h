#ifndef _FIND_H
#define _FIND_H

// for_each_set_bit = find_first_bit + find_next_bit => reference linux 3.x kernel.
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

ULONG_PTR find_first_zero_bit(const ULONG_PTR *addr, ULONG_PTR size);
int find_next_zero_bit(const ULONG_PTR * addr, ULONG_PTR size, ULONG_PTR offset);

extern ULONG_PTR find_first_bit(const ULONG_PTR* addr, ULONG_PTR size);
extern ULONG_PTR find_next_bit(const ULONG_PTR *addr, ULONG_PTR size, ULONG_PTR offset);

#if defined(__LITTLE_ENDIAN)

static inline ULONG_PTR find_next_zero_bit_le(const void *addr,
		ULONG_PTR size, ULONG_PTR offset)
{
	return find_next_zero_bit(addr, size, offset);
}

static inline ULONG_PTR find_next_bit_le(const void *addr,
		ULONG_PTR size, ULONG_PTR offset)
{
	return find_next_bit(addr, size, offset);
}

static inline ULONG_PTR find_first_zero_bit_le(const void *addr,
		ULONG_PTR size)
{
	return find_first_zero_bit(addr, size);
}

#elif defined(__BIG_ENDIAN)

#ifndef find_next_zero_bit_le
static inline
ULONG_PTR find_next_zero_bit_le(const void *addr, ULONG_PTR size, ULONG_PTR offset)
{
	if (small_const_nbits(size)) {
		ULONG_PTR val = *(const ULONG_PTR *)addr;

		if (unlikely(offset >= size))
			return size;

		val = swab(val) | ~GENMASK(size - 1, offset);
		return val == ~0UL ? size : ffz(val);
	}

	return _find_next_zero_bit_le(addr, size, offset);
}
#endif

#ifndef find_first_zero_bit_le
static inline
ULONG_PTR find_first_zero_bit_le(const void *addr, ULONG_PTR size)
{
	if (small_const_nbits(size)) {
		ULONG_PTR val = swab(*(const ULONG_PTR *)addr) | ~GENMASK(size - 1, 0);

		return val == ~0UL ? size : ffz(val);
	}

	return _find_first_zero_bit_le(addr, size);
}
#endif

#ifndef find_next_bit_le
static inline
ULONG_PTR find_next_bit_le(const void *addr, ULONG_PTR size, ULONG_PTR offset)
{
	if (small_const_nbits(size)) {
		ULONG_PTR val = *(const ULONG_PTR *)addr;

		if (unlikely(offset >= size))
			return size;

		val = swab(val) & GENMASK(size - 1, offset);
		return val ? __ffs(val) : size;
	}

	return _find_next_bit_le(addr, size, offset);
}
#endif

#endif	/* endian */

#endif

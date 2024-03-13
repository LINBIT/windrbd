#ifndef _FIND_H
#define _FIND_H

// for_each_set_bit = find_first_bit + find_next_bit => reference linux 3.x kernel.
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

ULONG_PTR find_first_zero_bit(const ULONG_PTR *addr, ULONG_PTR size);
int find_next_zero_bit(const ULONG_PTR * addr, ULONG_PTR size, ULONG_PTR offset);

#endif

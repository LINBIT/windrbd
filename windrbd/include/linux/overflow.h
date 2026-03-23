#ifndef _OVERFLOW_H
#define _OVERFLOW_H

#include <linux/const.h>
#include <linux/compiler.h>

/*
 * Allows for effectively applying __must_check to a macro so we can have
 * both the type-agnostic benefits of the macros while also being able to
 * enforce that the return value is, in fact, checked.
 */
static inline bool __must_check __must_check_overflow(bool overflow)
{
	return unlikely(overflow);
}

/**
 * flex_array_size() - Calculate size of a flexible array member
 *                     within an enclosing structure.
 * @p: Pointer to the structure.
 * @member: Name of the flexible array member.
 * @count: Number of elements in the array.
 *
 * Calculates size of a flexible array of @count number of @member
 * elements, at the end of structure @p.
 *
 * Return: number of bytes needed or SIZE_MAX on overflow.
 */
#define flex_array_size(p, member, count)				\
	__builtin_choose_expr(__is_constexpr(count),			\
		(count) * sizeof(*(p)->member) + __must_be_array((p)->member),	\
		size_mul(count, sizeof(*(p)->member) + __must_be_array((p)->member)))


/**
 * struct_size() - Calculate size of structure with trailing flexible array.
 * @p: Pointer to the structure.
 * @member: Name of the array member.
 * @count: Number of elements in the array.
 *
 * Calculates size of memory needed for structure of @p followed by an
 * array of @count number of @member elements.
 *
 * Return: number of bytes needed or SIZE_MAX on overflow.
 */
#define struct_size(p, member, count)					\
	__builtin_choose_expr(__is_constexpr(count),			\
		sizeof(*(p)) + flex_array_size(p, member, count),	\
		size_add(sizeof(*(p)), flex_array_size(p, member, count)))

/**
 * check_add_overflow() - Calculate addition with overflow checking
 * @a: first addend
 * @b: second addend
 * @d: pointer to store sum
 *
 * Returns 0 on success.
 *
 * *@d holds the results of the attempted addition, but is not considered
 * "safe for use" on a non-zero return value, which indicates that the
 * sum has overflowed or been truncated.
 */
#define check_add_overflow(a, b, d)	\
	__must_check_overflow(__builtin_add_overflow(a, b, d))

/**
 * check_mul_overflow() - Calculate multiplication with overflow checking
 * @a: first factor
 * @b: second factor
 * @d: pointer to store product
 *
 * Returns 0 on success.
 *
 * *@d holds the results of the attempted multiplication, but is not
 * considered "safe for use" on a non-zero return value, which indicates
 * that the product has overflowed or been truncated.
 */
#define check_mul_overflow(a, b, d)	\
	__must_check_overflow(__builtin_mul_overflow(a, b, d))

/**
 * size_mul() - Calculate size_t multiplication with saturation at SIZE_MAX
 * @factor1: first factor
 * @factor2: second factor
 *
 * Returns: calculate @factor1 * @factor2, both promoted to size_t,
 * with any overflow causing the return value to be SIZE_MAX. The
 * lvalue must be size_t to avoid implicit type conversion.
 */
static inline size_t __must_check size_mul(size_t factor1, size_t factor2)
{
	size_t bytes;

	if (check_mul_overflow(factor1, factor2, &bytes))
		return SIZE_MAX;

	return bytes;
}

/**
 * size_add() - Calculate size_t addition with saturation at SIZE_MAX
 * @addend1: first addend
 * @addend2: second addend
 *
 * Returns: calculate @addend1 + @addend2, both promoted to size_t,
 * with any overflow causing the return value to be SIZE_MAX. The
 * lvalue must be size_t to avoid implicit type conversion.
 */
static inline size_t __must_check size_add(size_t addend1, size_t addend2)
{
	size_t bytes;

	if (check_add_overflow(addend1, addend2, &bytes))
		return SIZE_MAX;

	return bytes;
}

/**
 * struct_size_t() - Calculate size of structure with trailing flexible array
 * @type: structure type name.
 * @member: Name of the array member.
 * @count: Number of elements in the array.
 *
 * Calculates size of memory needed for structure @type followed by an
 * array of @count number of @member elements. Prefer using struct_size()
 * when possible instead, to keep calculations associated with a specific
 * instance variable of type @type.
 *
 * Return: number of bytes needed or SIZE_MAX on overflow.
 */
#define struct_size_t(type, member, count)                                      \
        struct_size((type *)NULL, member, count)

/**
 * __set_flex_counter() - Set the counter associated with the given flexible
 *                        array member that has been annoated by __counted_by().
 * @FAM: Instance of flexible array member within a given struct.
 * @COUNT: Value to store to the __counted_by annotated @FAM_PTR's counter.
 *
 * This is a no-op if no annotation exists. Count needs to be checked with
 * overflows_flex_counter_type() before using this function.
 */
#define __set_flex_counter(FAM, COUNT)                          \
({                                                              \
        *_Generic(__flex_counter(FAM),                          \
                  void *:  &(size_t){ 0 },                      \
                  default: __flex_counter(FAM)) = (COUNT);      \
})

#endif

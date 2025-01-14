/*
	Copyright(C) 2007-2016, ManTechnology Co., LTD.
	Copyright(C) 2007-2016, wdrbd@mantech.co.kr

	Windows DRBD is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2, or (at your option)
	any later version.

	Windows DRBD is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Windows DRBD; see the file COPYING. If not, write to
	the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef _WINDOWS_TYPES_H
#define _WINDOWS_TYPES_H

/* TODO: */
typedef signed long long ssize_t;

/* Include this before Windows headers, else duplicate
 * Exxxx macro definitions.
 */
#include <linux/errno.h>
#include <asm/errno.h>
/* Note: these 'standard C' headers come from ReactOS now: */
#include <stdint.h>
// #include <ntstrsafe.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

/* Windows headers should be included *only* here: */

#include <ntdef.h>
#include <ntddk.h>
#include <ntdddisk.h>

#ifdef __CHECKER__
#define __bitwise	__attribute__((bitwise))
#else
#define __bitwise
#endif

#define DECLARE_BITMAP(name,bits) \
	ULONG_PTR name[BITS_TO_LONGS(bits)]

#ifdef NOTHING
#undef NOTHING
#endif

#ifdef __reserved
#undef __reserved
#endif

#include <ctype.h>
#include <stdbool.h>
#include <linux/compiler.h>
#include <linux/gfp_types.h>

typedef struct {
	int counter;
} atomic_t;

#define ATOMIC_INIT(i) { .counter = (i) }

typedef int pid_t;

typedef signed char		    __s8;
typedef unsigned char		__u8;
typedef signed short		__s16;
typedef unsigned short		__u16;
typedef signed int		    __s32;
typedef unsigned int		__u32;
typedef signed long long	__s64;
typedef unsigned long long	__u64;
typedef signed char		    s8;
typedef unsigned char		u8;
typedef signed short		s16;
typedef unsigned short		u16;
typedef signed int		    s32;
typedef unsigned int		u32;
typedef signed long long	s64;
typedef unsigned long long	u64;
typedef unsigned long long	sector_t;

typedef __u16		__le16;
typedef __u16		__be16;
typedef __u32		__le32;
typedef __u32		__be32;
typedef __u64		__le64;
typedef __u64		__be64;


typedef		__u8		u_int8_t;
typedef		__s8		int8_t;
typedef		__u16		u_int16_t;
typedef		__s16		int16_t;
typedef		__u32		u_int32_t;
typedef		__s32		int32_t;

typedef		__u8		uint8_t;
typedef		__u16		uint16_t;
typedef		__u32		uint32_t;

typedef unsigned int gfp_t;

typedef		__u64		uint64_t;
typedef		__u64		u_int64_t;
typedef		__s64		int64_t;

typedef u32 dev_t;

struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *head);
};
#define rcu_head callback_head

typedef void (*rcu_callback_t)(struct rcu_head *head);
typedef void (*call_rcu_func_t)(struct rcu_head *head, rcu_callback_t func);

#ifndef __packed
#define __packed
#endif

struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct hlist_head {
	struct hlist_node *first;
};
 
// typedef LONG_PTR ssize_t;
typedef unsigned int                fmode_t;
typedef long long loff_t;

typedef unsigned short		umode_t;

	/* TODO: always? */
// #ifdef CONFIG_64BIT
typedef struct {
	s64 counter;
} atomic64_t;
// #endif

/* Nanosecond scalar representation for kernel time values */
typedef s64	ktime_t;

/* printf format specifiers for LONG_PTR and ULONG_PTR */

#ifdef CONFIG_32BIT
#define PRI_LONG_PTR "ld"
#define PRI_ULONG_PTR "lu"
#else
#define PRI_LONG_PTR "lld"
#define PRI_ULONG_PTR "llu"
#endif

#endif

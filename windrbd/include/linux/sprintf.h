/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KERNEL_SPRINTF_H_
#define _LINUX_KERNEL_SPRINTF_H_

#include <linux/compiler_attributes.h>
#include <linux/types.h>

	/* For now use the Windows _snwprintf and the like functions. */
// #include <ntstrsafe.h>
/* TODO: we are including a MinGW compiler header here but we are
 * in kernel mode. Does this work at all?
 */
// #include <stdio.h>

/* Those implementations taken from Linux: */
__printf(3, 4) int scnprintf(char *buf, size_t size, const char *fmt, ...);
__printf(3, 0) int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
__printf(2, 3) __malloc char *kasprintf(gfp_t gfp, const char *fmt, ...);
__printf(2, 0) __malloc char *kvasprintf(gfp_t gfp, const char *fmt, va_list args);

/* Those are included in -lmingwex -lmincore of MinGW: see also stdio.h of MinGW */

extern int __cdecl __mingw_vsprintf (char * __restrict__ , const char * __restrict__ , va_list);

static inline int sprintf (char *__stream, const char *__format, ...)
{
  int __retval;
  __builtin_va_list __local_argv; __builtin_va_start( __local_argv, __format );
  __retval = __mingw_vsprintf( __stream, __format, __local_argv );
  __builtin_va_end( __local_argv );
  return __retval;
}

static inline int vsprintf (char *__stream, const char *__format, __builtin_va_list __local_argv)
{
  return __mingw_vsprintf( __stream, __format, __local_argv );
}

extern int __cdecl __mingw_vsnprintf(char * __restrict__ _DstBuf,size_t _MaxCount,const char * __restrict__ _Format, va_list _ArgList);

static inline int snprintf (char *__stream, size_t __n, const char *__format, ...)
{
  int __retval;
  __builtin_va_list __local_argv; __builtin_va_start( __local_argv, __format );
  __retval = __mingw_vsnprintf( __stream, __n, __format, __local_argv );
  __builtin_va_end( __local_argv );
  return __retval;
}

int vsnprintf (char *__stream, size_t __n, const char *__format, __builtin_va_list __local_argv)
{
  return __mingw_vsnprintf( __stream, __n, __format, __local_argv );
}

/*
#define sprintf _sprintf
#define vsprintf _vsprintf
#define snprintf _snprintf
#define vsnprintf _vsnprintf
*/

#if 0
int num_to_str(char *buf, int size, unsigned long long num, unsigned int width);

__printf(2, 3) int sprintf(char *buf, const char * fmt, ...);
__printf(2, 0) int vsprintf(char *buf, const char *, va_list);
__printf(3, 4) int snprintf(char *buf, size_t size, const char *fmt, ...);
__printf(3, 0) int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
#endif
__printf(2, 3) __malloc char *kasprintf(gfp_t gfp, const char *fmt, ...);
__printf(2, 0) __malloc char *kvasprintf(gfp_t gfp, const char *fmt, va_list args);
__printf(2, 0) const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list args);

#if 0
__scanf(2, 3) int sscanf(const char *, const char *, ...);
__scanf(2, 0) int vsscanf(const char *, const char *, va_list);

/* These are for specific cases, do not use without real need */
extern bool no_hash_pointers;
int no_hash_pointers_enable(char *str);

#endif

#endif	/* _LINUX_KERNEL_SPRINTF_H */

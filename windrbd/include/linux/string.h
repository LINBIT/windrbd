#ifndef __LINUX_STRING_H
#define __LINUX_STRING_H

#include <linux/gfp.h>
#include <linux/compiler.h>

/* Implemented. Taken from Linux 5.11 */
size_t strlcpy(char *dest, const char *src, size_t size);

extern char *kstrdup(const char *s, gfp_t gfp) __malloc;

	/* See string.c: */
extern ssize_t strscpy(char *dest, const char *src, size_t count);

/**
 * memzero_explicit - Fill a region of memory (e.g. sensitive
 *                    keying data) with 0s.
 * @s: Pointer to the start of the area.
 * @count: The size of the area.
 *
 * Note: usually using memset() is just fine (!), but in cases
 * where clearing out _local_ data at the end of a scope is
 * necessary, memzero_explicit() should be used instead in
 * order to prevent the compiler from optimising away zeroing.
 *
 * memzero_explicit() doesn't need an arch-specific version as
 * it just invokes the one of memset() implicitly.
 */
static inline void memzero_explicit(void *s, size_t count)
{
        memset(s, 0, count);
        barrier_data(s);
}

#endif

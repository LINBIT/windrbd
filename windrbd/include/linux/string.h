#ifndef __LINUX_STRING_H
#define __LINUX_STRING_H

#include <linux/gfp.h>
#include <linux/compiler.h>

/* Implemented. Taken from Linux 5.11 */
size_t strlcpy(char *dest, const char *src, size_t size);

extern char *kstrdup(const char *s, gfp_t gfp) __malloc;

	/* See string.c: */
extern ssize_t strscpy(char *dest, const char *src, size_t count);

#endif

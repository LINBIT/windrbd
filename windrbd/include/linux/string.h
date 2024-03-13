#ifndef __LINUX_STRING_H
#define __LINUX_STRING_H

#include <linux/gfp.h>
#include <linux/compiler.h>

extern char *kstrdup(const char *s, gfp_t gfp) __malloc;

#endif

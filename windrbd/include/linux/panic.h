#ifndef __LINUX_PANIC_H
#define __LINUX_PANIC_H

#include <linux/compiler.h>

extern void panic(const char *fmt, ...) __noreturn;

#endif

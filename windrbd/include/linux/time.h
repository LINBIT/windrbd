#ifndef _LINUX_TIME_H
#define _LINUX_TIME_H

// #include <linux/cache.h>
// #include <linux/math64.h>
#include <linux/time64.h>

extern struct timezone sys_tz;

void time64_to_tm(time64_t totalsecs, int offset, struct tm *result);

#endif

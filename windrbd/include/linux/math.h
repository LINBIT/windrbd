#ifndef __LINUX_MATH_H
#define __LINUX_MATH_H

#include <linux/div64.h>

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

#define sector_div(a, b) do_div(a, b)

#endif

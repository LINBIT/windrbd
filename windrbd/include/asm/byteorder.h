#ifndef __ASM_BYTEORDER_H
#define __ASM_BYTEORDER_H

#ifdef __LITTLE_ENDIAN
#include <linux/byteorder/little_endian.h>
#else
#ifdef __BIG_ENDIAN
#include <linux/byteorder/big_endian.h>
#else
#error "Must define either __LITTLE_ENDIAN or __BIG_ENDIAN"
#endif
#endif

#include <linux/byteorder/generic.h>

#endif

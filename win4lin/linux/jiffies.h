#ifndef __JIFFIES_H__
#define __JIFFIES_H__

#include <stdint.h>

__inline unsigned int jiffies_to_msecs(const UINT64 j)
{
	return (unsigned int)j;
}

#endif

#ifndef __JIFFIES_H__
#define __JIFFIES_H__

__inline unsigned int jiffies_to_msecs(const ULONG_PTR j)
{
	return (unsigned int)j;
}

#endif
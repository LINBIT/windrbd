#ifndef __HWEIGHT_H__
#define __HWEIGHT_H__
#include "linux/types.h"

extern unsigned int hweight32(unsigned int w);
extern unsigned int hweight16(unsigned int w);
extern unsigned int hweight8(unsigned int w);
#ifdef _WIN32
#ifdef _WIN64
extern unsigned long long hweight64(__u64 w);
#else
extern unsigned long hweight64(__u64 w);
#endif
#else
extern unsigned long hweight64(__u64 w);
#endif
#endif

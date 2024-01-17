#ifndef CONTAINER_OF_H
#define CONTAINER_OF_H

#include <linux/types.h>

#define container_of(ptr, type, member) \
	((type *)( \
	(PCHAR)(ptr) - \
	(ULONG_PTR)(&((type *)0)->member)))

#endif

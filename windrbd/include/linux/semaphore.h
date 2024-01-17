#ifndef _SEMAPHORE_H
#define _SEMAPHORE_H

#include <linux/types.h>

struct semaphore {
    KSEMAPHORE sem;
};

#endif

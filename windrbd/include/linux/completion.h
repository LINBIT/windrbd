#ifndef COMPLETION_H
#define COMPLETION_H

#include <linux/types.h>
#include <linux/wait.h>

struct completion {
	bool completed;
	wait_queue_head_t wait;
};

#endif

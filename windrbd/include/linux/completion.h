#ifndef COMPLETION_H
#define COMPLETION_H

#include <linux/types.h>
#include <linux/wait.h>

struct completion {
	bool completed;
	wait_queue_head_t wait;
};

extern void init_completion_debug(struct completion *c, const char *file, int line, const char *func);
extern void wait_for_completion_debug(struct completion *c, const char *file, int line, const char *func);
extern ULONG_PTR wait_for_completion_timeout_debug(struct completion *c, ULONG_PTR timeout, const char *file, int line, const char *func);
extern int wait_for_completion_interruptible_debug(struct completion *c, const char *file, int line, const char *func);
LONG_PTR wait_for_completion_interruptible_timeout_debug(struct completion *completion, ULONG_PTR timeout, const char *file, int line, const char *func);
extern void complete_debug(struct completion *c, const char *file, int line, const char *func);
extern void complete_all_debug(struct completion *c, const char *file, int line, const char *func);

#define init_completion(c) init_completion_debug(c, __FILE__, __LINE__, __func__)
#define wait_for_completion(c) wait_for_completion_debug(c, __FILE__, __LINE__, __func__)
#define wait_for_completion_timeout(c, t) wait_for_completion_timeout_debug(c, t, __FILE__, __LINE__, __func__)
#define wait_for_completion_interruptible(c) wait_for_completion_interruptible_debug(c, __FILE__, __LINE__, __func__)
#define wait_for_completion_interruptible_timeout(c, t) wait_for_completion_interruptible_timeout_debug(c, t, __FILE__, __LINE__, __func__)
#define complete(c) complete_debug(c, __FILE__, __LINE__, __func__)
#define complete_all(c) complete_all_debug(c, __FILE__, __LINE__, __func__)

#define COMPLETION_INITIALIZER_ONSTACK(work) \
	(*({ init_completion(&work); &work; }))

#endif

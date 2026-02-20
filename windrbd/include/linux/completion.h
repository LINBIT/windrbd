#ifndef COMPLETION_H
#define COMPLETION_H

#include <linux/types.h>
#include <linux/wait.h>

struct completion {
	KEVENT windows_event;
};

extern void init_completion(struct completion *c);
extern void reinit_completion(struct completion *c);
extern void wait_for_completion(struct completion *c);
extern ULONG_PTR wait_for_completion_timeout(struct completion *c, ULONG_PTR timeout);
extern int wait_for_completion_interruptible(struct completion *c);
LONG_PTR wait_for_completion_interruptible_timeout(struct completion *completion, ULONG_PTR timeout);
extern void complete(struct completion *c);
extern void complete_all(struct completion *c);

#define COMPLETION_INITIALIZER_ONSTACK(work) \
	(*({ init_completion(&work); &work; }))

#endif

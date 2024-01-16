#ifndef WINDRBD_H
#define WINDRBD_H

#include <ntddk.h>

/* TODO: Hmm ... we probably want to have a windrbd_internal.h (for
 * WinDRBD C files) and windrbd.h (for hooks being called
 * by DRBD.
 */

/* Helper functions that might be useful for others. */

NTSTATUS windrbd_create_windows_thread(void (*threadfn)(void*), void *data, void **thread_object_p);
NTSTATUS windrbd_cleanup_windows_thread(void *thread_object);

void init_windrbd_threads(void);

	/* Currently called by reply_reaper, see netlink code */
void windrbd_reap_threads(void);

	/* This waits forever, only use this on driver unload */
void windrbd_reap_all_threads(void);

struct task_struct* windrbd_find_thread(PKTHREAD id);

        /* Use this to create a task_struct for a Windows thread
         * This is needed so we can call wait_event_XXX functions
         * within those threads.
         */

struct task_struct *make_me_a_windrbd_thread(const char *name, ...);

        /* Call this when a thread returns to the calling Windows
         * kernel function.
         */

void return_to_windows(struct task_struct *t);

/* Non-zero if thread is created via the Linux emulation layer (this
 * file).
 */

bool is_windrbd_thread(struct task_struct *t);

/* Set realtime priority. Used for asender */

void windrbd_set_realtime_priority(struct task_struct *t);

/* Become super user */
void sudo(void);

#endif

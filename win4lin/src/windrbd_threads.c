#include "drbd_windows.h"
#include "windrbd_threads.h"
#include <wdm.h>

static LIST_HEAD(thread_list);
static spinlock_t thread_list_lock;

	/* NO printk's in here. Used by printk internally, would loop. */
	/* Call this with thread_list_lock held. */

static pid_t next_pid;
static spinlock_t next_pid_lock;

	/* Helper function to create and start windows kernel threads.
	 * If non-null, the kernel's PKTHREAD object is returned by
	 * reference in thread_object_p.
	 */

NTSTATUS windrbd_create_windows_thread(void (*threadfn)(void*), void *data, void **thread_object_p)
{
        HANDLE h;
        NTSTATUS status;

        status = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, threadfn, data);
        if (!NT_SUCCESS(status))
                return status;

	if (thread_object_p)
	        status = ObReferenceObjectByHandle(h, THREAD_ALL_ACCESS, NULL, KernelMode, thread_object_p, NULL);

	ZwClose(h);
	return status;
}


	/* We need this so we clean up the task struct. Linux appears
	 * to deref the task_struct on thread exit, we also should
	 * do so.
	 */

static void windrbd_thread_setup(void *targ)
{
	struct task_struct *t = targ;
	int ret;
	ULONG_PTR flags;

	ret = t->threadfn(t->data);
	if (ret != 0)
		printk(KERN_WARNING "Thread %s returned non-zero exit status. Ignored, since Windows threads are void.\n", t->comm);

	spin_lock_irqsave(&thread_list_lock, flags);
	list_del(&t->list);
	spin_unlock_irqrestore(&thread_list_lock, flags);

	kfree(t);
}

	/* Again, we try to be more close to the Linux kernel API.
	 * This really creates and starts the thread created earlier
	 * by kthread_create() as a windows kernel thread. If the
	 * start process should fail, -1 is returned (which is
	 * different from the Linux kernel API, sorry for that...)
	 * Else same as in Linux: 0: task is already running (yes,
	 * you can call this multiple times, but since there is no
	 * way to temporarily stop a windows kernel thread, always
	 * 0 is returned) or 1: task was started.
	 */

int wake_up_process(struct task_struct *t)
{
	ULONG_PTR flags;
	NTSTATUS status;

	spin_lock_irqsave(&t->thread_started_lock, flags);
	if (t->thread_started) {
		spin_unlock_irqrestore(&t->thread_started_lock, flags);
		return 0;
	}
	t->thread_started = 1;
	spin_unlock_irqrestore(&t->thread_started_lock, flags);

	status = windrbd_create_windows_thread(windrbd_thread_setup, t, &t->windows_thread);
	if (status != STATUS_SUCCESS) {
		printk("Could not start thread %s\n", t->comm);
		return -1;
	}
	return 1;
}

	/* Creates a new task_struct, but doesn't start the thread (by
	 * calling PsCreateSystemThread()) yet. This will be done by
	 * wake_up_process(struct task_struct) later.
	 *
	 * We strive to be as close as possible to the real Linux
	 * function here.
	 */

struct task_struct *kthread_create(int (*threadfn)(void *), void *data, const char *name, ...)
{
	struct task_struct *t;
	ULONG_PTR flags;
	va_list args;
	int i;

	if ((t = kzalloc(sizeof(*t), GFP_KERNEL, 'DRBD')) == NULL)
		return ERR_PTR(-ENOMEM);

		/* The thread will be created later in wake_up_process(),
		 * since Windows doesn't know of threads that are stopped
		 * when created.
		 */

	t->windows_thread = NULL;
	t->threadfn = threadfn;
	t->data = data;
	t->thread_started = 0;
	spin_lock_init(&t->thread_started_lock);

	KeInitializeEvent(&t->sig_event, SynchronizationEvent, FALSE);
	t->has_sig_event = TRUE;
	t->sig = -1;

	va_start(args, name);
	i = _vsnprintf_s(t->comm, sizeof(t->comm)-1, _TRUNCATE, name, args);
	va_end(args);
	if (i == -1) {
		kfree(t);
		return ERR_PTR(-ERANGE);
	}

	spin_lock_irqsave(&next_pid_lock, flags);
	next_pid++;
	t->pid = next_pid;
	spin_unlock_irqrestore(&next_pid_lock, flags);

	spin_lock_irqsave(&thread_list_lock, flags);
	list_add(&t->list, &thread_list);
	spin_unlock_irqrestore(&thread_list_lock, flags);

	return t;
}

struct task_struct *kthread_run(int (*threadfn)(void *), void *data, const char *name)
{
	struct task_struct *k = kthread_create(threadfn, data, name);
	if (!IS_ERR(k))
		wake_up_process(k);
	return k;
}

static struct task_struct *__find_thread(PKTHREAD id)
{
	struct task_struct *t;

	list_for_each_entry(struct task_struct, t, &thread_list, list) {
		if (t->windows_thread == id)
			return t;
	}
	return NULL;
}


	/* NO printk's here, used internally by printk (via current). */
struct task_struct* windrbd_find_thread(PKTHREAD id)
{
	struct task_struct *t;
	ULONG_PTR flags;

	spin_lock_irqsave(&thread_list_lock, flags);
	t = __find_thread(id);
	if (!t) {	/* TODO: ... */
		static struct task_struct g_dummy_current;
		t = &g_dummy_current;
		t->pid = 0;
		t->has_sig_event = FALSE;
		strcpy(t->comm, "not_drbd_thread");
	}
	spin_unlock_irqrestore(&thread_list_lock, flags);

	return t;
}

void init_windrbd_threads(void)
{
        spin_lock_init(&next_pid_lock);
        spin_lock_init(&thread_list_lock);
        INIT_LIST_HEAD(&thread_list);
}


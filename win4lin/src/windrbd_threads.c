#include "drbd_windows.h"
#include "windrbd_threads.h"
#include <wdm.h>

static LIST_HEAD(thread_list);
static spinlock_t thread_list_lock;

	/* NO printk's in here. Used by printk internally, would loop. */
	/* Call this with thread_list_lock held. */

static pid_t next_pid;
static spinlock_t next_pid_lock;

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

NTSTATUS windrbd_cleanup_windows_thread(void *thread_object)
{
	NTSTATUS status;

        status = KeWaitForSingleObject(thread_object, Executive, KernelMode, FALSE, (PLARGE_INTEGER)NULL);

        if (!NT_SUCCESS(status)) {
                printk("KeWaitForSingleObject failed with status %x\n", status);
		return status;
	}
        ObDereferenceObject(thread_object);

	return STATUS_SUCCESS;
}

	/* Called by reply_reaper (see windrbd_netlink.c). We don't want
	 * two threads having reaping some resources and this thread was
	 * there first.
	 */

void windrbd_reap_threads(void)
{
	struct task_struct *t, *tn;
	ULONG_PTR flags;
	LIST_HEAD(dead_list);

	INIT_LIST_HEAD(&dead_list);

	spin_lock_irqsave(&thread_list_lock, flags);
	list_for_each_entry_safe(struct task_struct, t, tn, &thread_list, list) {
		if (t->is_zombie) {
			list_del(&t->list);
			list_add(&t->list, &dead_list);
		}
	}
	spin_unlock_irqrestore(&thread_list_lock, flags);

	list_for_each_entry_safe(struct task_struct, t, tn, &dead_list, list) {
		windrbd_cleanup_windows_thread(t->windows_thread);
		printk("Buried %s thread\n", t->comm);

		list_del(&t->list);
		kfree(t);
	}
}

	/* To be called on shutdown. On driver unload all threads must
	 * be terminated, it is a BSOD if threads are remaining. So
	 * wait forever. printk still should work, so inform the user
 	 * that we are still alive waiting for threads to terminate.
	 */

void windrbd_reap_all_threads(void)
{
	int n = 0;

	windrbd_reap_threads();

	while (!list_empty(&thread_list)) {
		n++;
		printk("Still threads alive (%d), waiting for them to terminate ...\n", n);
			/* TODO: we might want to tell the user which threads they are ... */

		msleep(1000);
		windrbd_reap_threads();
	}
}
		
	/* We need this so we clean up the task struct. Linux appears
	 * to deref the task_struct on thread exit, we also should
	 * do so.
	 */

static void windrbd_thread_setup(void *targ)
{
	struct task_struct *t = targ;
	int ret;
	NTSTATUS status;

		/* t->windows_thread may be still invalid here, do not
		 * printk().
		 */

        status = KeWaitForSingleObject(&t->start_event, Executive, KernelMode, FALSE, (PLARGE_INTEGER)NULL);
        if (!NT_SUCCESS(status)) {
		printk("On waiting for start event: KeWaitForSingleObject failed with status %x\n", status);
		return;
	}
	ret = t->threadfn(t->data);
	if (ret != 0)
		printk(KERN_WARNING "Thread %s returned non-zero exit status. Ignored, since Windows threads are void.\n", t->comm);

	t->is_zombie = 1;
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
	KeSetEvent(&t->start_event, 0, FALSE);

	return 1;
}

	/* Creates a new task_struct, but start the thread (by
	 * calling PsCreateSystemThread()). Thread will wait for
	 * start event which is signalled by wake_up_process(struct
	 * task_struct) later.
	 *
	 * If PsCreateSystemThread should fail this returns an
	 * ERR_PTR(-ENOMEM)
	 *
	 * This now 'emulates' Linux behaviour such that no changes
	 * to driver code should be neccessary (at least not in the
	 * DRBD code).
	 */

struct task_struct *kthread_create(int (*threadfn)(void *), void *data, const char *name, ...)
{
	struct task_struct *t;
	ULONG_PTR flags;
	va_list args;
	int i;
	NTSTATUS status;

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
	t->is_zombie = 0;
	spin_lock_init(&t->thread_started_lock);

	KeInitializeEvent(&t->sig_event, SynchronizationEvent, FALSE);
	KeInitializeEvent(&t->start_event, SynchronizationEvent, FALSE);
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

	status = windrbd_create_windows_thread(windrbd_thread_setup, t, &t->windows_thread);
	if (status != STATUS_SUCCESS) {
		printk("Could not start thread %s\n", t->comm);
		return ERR_PTR(-ENOMEM);	/* or whatever */
	}

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

bool is_windrbd_thread(struct task_struct *t)
{
	if (t == NULL)
		return false;

	return t->has_sig_event;
}

void init_windrbd_threads(void)
{
        spin_lock_init(&next_pid_lock);
        spin_lock_init(&thread_list_lock);
	thread_list_lock.printk_lock = 1;
        INIT_LIST_HEAD(&thread_list);
}


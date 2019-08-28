#include "drbd_windows.h"
#include "windrbd_threads.h"

#define WINDRBD_RUN_TESTS 1

/* #define WINDRBD_RUN_RCU_LOCK_RECURSION_TEST 1 */
/* #define WINDRBD_RUN_RCU_LOCK_SYNCHRONIZE_RECURSION_TEST 1 */
/* #define WINDRBD_PRINTK_PING 1 */
/* #define WINDRBD_WAIT_EVENT_TEST 1 */

#ifdef WINDRBD_RUN_TESTS

/* This currently succeeds on Windows 7 and Windows 10. Test it also
 * with Windows Server 2016. It should stall the machine but it
 * doesn't.
 */

static int rcu_lock_recursion(void *unused)
{
	KIRQL flags1, flags2, flags3;

printk("1\n");
	flags1 = rcu_read_lock();
printk("2 flags1 is %d IRQL is %d\n", flags1, KeGetCurrentIrql());
	flags2 = rcu_read_lock();
printk("3 flags2 is %d IRQL is %d\n", flags2, KeGetCurrentIrql());
	flags3 = rcu_read_lock();
printk("4 flags3 is %d IRQL is %d\n", flags3, KeGetCurrentIrql());

	rcu_read_unlock(flags3);
printk("5 IRQL is %d\n", KeGetCurrentIrql());
	rcu_read_unlock(flags2);
printk("6 IRQL is %d\n", KeGetCurrentIrql());
	rcu_read_unlock(flags1);

printk("7 IRQL is %d\n", KeGetCurrentIrql());
	return 0;
}

/* As expected this test stalls the machine (does not dispatch
 * new threads any more)
 */
static int rcu_lock_synchronize_recursion(void *unused)
{
	KIRQL flags;

printk("1\n");
	flags = rcu_read_lock();
printk("2 flags is %d IRQL is %d\n", flags, KeGetCurrentIrql());
	synchronize_rcu();
printk("3 IRQL is %d\n", KeGetCurrentIrql());
	rcu_read_unlock(flags);
printk("4 IRQL is %d\n", KeGetCurrentIrql());

	return 0;
}

static int run_printk_ping = 1;

static int printk_ping(void *unused)
{
	int i;

	i=0;
	while (run_printk_ping) {
		printk("ping %d (drbd bus is %p)\n", i, drbd_bus_device);
		i++;
		msleep(1000);
	}
	return 0;
}

#endif

#ifdef WINDRBD_WAIT_EVENT_TEST

static int cond = 0;

static int wakeup_wait_queue(void *_w)
{
	struct wait_queue_head *w = _w;

printk("waiting a bit ...\n");
	msleep(1000);
printk("wake up queue ...\n");
	wake_up(w);

printk("waiting a bit ...\n");
	msleep(1000);
printk("setting condition to true (non-zero) ...\n");
	cond = 1;
printk("wake up queue ...\n");
	wake_up(w);
printk("wait_event_interruptible should have terminated now.\n");
	return 0;
}

static int wait_event_test(void *unused)
{
	struct wait_queue_head w;
	int ret;

printk("Waiting 3 minutes so you can uninstall windrbd\n");

	msleep(3*60*1000);

printk("starting wait_event test\n");
	init_waitqueue_head(&w);

printk("starting waker\n");
	kthread_run(wakeup_wait_queue, &w, "waker");

printk("waiting for waker\n");
	wait_event_interruptible(ret, w, cond);
printk("wait_event_interruptible returned %d\n", ret);

printk("ending test\n");
	return 0;
}

#endif

void windrbd_run_tests(void)
{
#ifdef WINDRBD_RUN_TESTS
#ifdef WINDRBD_RUN_RCU_LOCK_RECURSION_TEST
	kthread_run(rcu_lock_recursion, NULL, "rcu-lock-rec");
#endif
#ifdef WINDRBD_RUN_RCU_LOCK_SYNCHRONIZE_RECURSION_TEST
	kthread_run(rcu_lock_synchronize_recursion, NULL, "rcu-lock-sync");
#endif
#ifdef WINDRBD_PRINTK_PING
	kthread_run(printk_ping, NULL, "printk-ping");
#endif
#ifdef WINDRBD_WAIT_EVENT_TEST
	kthread_run(wait_event_test, NULL, "wait-event");
#endif
#else
	printk("WinDRBD self-tests disabled, see windrbd_test.c for how to enabled them.\n");
#endif
}


void windrbd_shutdown_tests(void)
{
#ifdef WINDRBD_PRINTK_PING
	run_printk_ping = 0;
#endif
}

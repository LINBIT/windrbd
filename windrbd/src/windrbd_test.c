#include "drbd_windows.h"
#include "windrbd_threads.h"
#include "drbd_int.h"
#include <ctype.h>
#include "disp.h"

int debug_printks_enabled = 0;

/* #define WINDRBD_RUN_TESTS 1 */

#ifdef RELEASE
#ifdef WINDRBD_RUN_TESTS
#undef WINDRBD_RUN_TESTS
#endif
#endif

/* #define WINDRBD_RUN_RCU_LOCK_RECURSION_TEST 1 */
/* #define WINDRBD_RUN_RCU_LOCK_SYNCHRONIZE_RECURSION_TEST 1 */
#define WINDRBD_PRINTK_PING 1
/* #define WINDRBD_WAIT_EVENT_TEST 1 */
/* #define WINDRBD_SCHEDULE_UNINTERRUPTIBLE_TEST 1 */

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
extern int num_pnp_requests;
extern int num_pnp_bus_requests;
extern int threads_sleeping;
struct drbd_connection *root_connection;
extern int duplicate_completions;
extern int raised_irql_waits;

static int printk_ping(void *unused)
{
	int i;
#if 0
	struct drbd_connection *connection;
#endif

	i=0;
	while (run_printk_ping) {
		printk("ping %d (drbd bus is %p) num_pnp_requests %d num_pnp_bus_requests %d currently %d threads sleeping interruptible duplicate_completions %d raised_irql_waits: %d\n", i, drbd_bus_device, num_pnp_requests, num_pnp_bus_requests, threads_sleeping, duplicate_completions, raised_irql_waits);
#if 0
		if (root_connection) {
			connection = root_connection; /* polymorph magic */
			drbd_info(connection, "root_connection %p", root_connection);
		}
#endif
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

#ifdef WINDRBD_SCHEDULE_UNINTERRUPTIBLE_TEST

/* This test just calls schedule_timeout_uninterruptible() - this
 * function BSOD'ed immediately before 5fc2788ef91.
 */

static int schedule_uninterruptible_test(void *unused)
{
	struct wait_queue_head w;
	int ret;

printk("Waiting 4 minutes so you can uninstall windrbd\n");

	msleep(4*60*1000);

printk("starting schedule uninterruptible test\n");
printk("waiting a second ...\n");
	schedule_timeout_uninterruptible(HZ);
printk("finished\n");

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
#ifdef WINDRBD_SCHEDULE_UNINTERRUPTIBLE_TEST
	kthread_run(schedule_uninterruptible_test, NULL, "schedule-unintr");
#endif
#else
	printk("WinDRBD self-tests disabled, see windrbd_test.c for how to enabled them.\n");
#endif
}


void windrbd_shutdown_tests(void)
{
#ifdef WINDRBD_RUN_TESTS
#ifdef WINDRBD_PRINTK_PING
	run_printk_ping = 0;
#endif
#endif
}

static int test_debug;

static long long non_atomic_int = 0;
static spinlock_t test_locks[2];
static struct mutex test_mutex;
static struct semaphore test_semaphore;
static struct rw_semaphore test_rw_semaphore;

#define min(a,b) ((a)<(b)?(a):(b))

unsigned long long my_strtoull(const char *nptr, const char ** endptr, int base)
{
        unsigned long long val = 0;
        char c;

        if (base <= 36 && base >= 2) {
                while (1) {
                        c = toupper(*nptr);
                        if (c >= '0' && c<'0'+min(base, 10)) {
				val *= base;
                                val += c-'0';
			} else {
                                if (c>='A' && c<'A'+base-10) {
					val *= base;
                                        val += c-'A'+10;
				} else
					break;
			}
			nptr++;
                }
        }
        if (endptr)
                *endptr = nptr;

        return val;
}

static long long rcu_n;
static spinlock_t rcu_writer_lock;

struct rcu_struct {
	long long a;
	long long b;
} *non_atomic_rcu;

enum rcu_read_methods { RRM_DEREFERENCE, RRM_DIRECT, RRM_LAST };
static char *rcu_read_methods[RRM_LAST] = {
	"dereference", "direct"
};
static enum rcu_read_methods rcu_read_method;

enum rcu_lock_methods { RCU_NONE, RCU_READ_LOCK, RCU_SPIN_LOCK, RCU_SPIN_LOCK_IRQ, RCU_CRITICAL_REGION, RCU_LAST };
static char *rcu_lock_methods[RCU_LAST] = {
	"none", "rcu_read_lock", "spin_lock", "spin_lock_irq", "critical_region"
};
static enum rcu_lock_methods rcu_lock_method;

enum rcu_writer_lock_methods { RCU_WRITER_NONE, RCU_WRITER_SPIN_LOCK, RCU_WRITER_SPIN_LOCK_IRQ, RCU_WRITER_SPIN_LOCK_LONG, RCU_WRITER_SPIN_LOCK_IRQ_LONG, RCU_WRITER_LAST };
static char *rcu_writer_lock_methods[RCU_WRITER_LAST] = {
	"none", "spin_lock", "spin_lock_irq", "spin_lock_long", "spin_lock_irq_long"
};
static enum rcu_writer_lock_methods rcu_writer_lock_method;
static int rcu_writers_finished;
static atomic_t rcu_num_read_errors;

static int rcu_reader(void *arg)
{
	long long i;
	volatile long long val1, val2;
	KIRQL flags;
	struct rcu_struct volatile *the_rcu;
	struct completion *c = arg;

	flags = 0;
	while (!rcu_writers_finished) {
		if (rcu_lock_method == RCU_READ_LOCK)
			flags = rcu_read_lock();
#if 0
		if (rcu_lock_method == RCU_SPIN_LOCK)
			spin_lock(&rcu_writer_lock);
		if (rcu_lock_method == RCU_SPIN_LOCK_IRQ)
			spin_lock_irq(&rcu_writer_lock);
#endif
		if (rcu_lock_method == RCU_CRITICAL_REGION)
			KeEnterCriticalRegion();

		if (rcu_read_method == RRM_DEREFERENCE) {
			the_rcu = rcu_dereference((struct rcu_struct volatile *) non_atomic_rcu);
			val1 = the_rcu->a;
			val2 = the_rcu->b;
		} else {
			val1 = non_atomic_rcu->a;
			val2 = non_atomic_rcu->b;
		}

		if (rcu_lock_method == RCU_READ_LOCK)
			rcu_read_unlock(flags);
#if 0
		if (rcu_lock_method == RCU_SPIN_LOCK)
			spin_unlock(&rcu_writer_lock);
		if (rcu_lock_method == RCU_SPIN_LOCK_IRQ)
			spin_unlock_irq(&rcu_writer_lock);
#endif
		if (rcu_lock_method == RCU_CRITICAL_REGION)
			KeLeaveCriticalRegion();

		if (val1 != val2) {
			printk("val1 (%llu) != val2 (%llu)\n", val1, val2);
			atomic_inc(&rcu_num_read_errors);
			complete(c);
			return -1;
		}
	}
	complete(c);

	return 0;
}

static int rcu_writer(void *arg)
{
	long long i;
	volatile long long val;
	struct rcu_struct *new_rcu, *old_rcu;
	struct completion *c = arg;

	for (i=0;i<rcu_n;i++) {
#if 0
		if (rcu_writer_lock_method == RCU_WRITER_SPIN_LOCK ||
		    rcu_writer_lock_method == RCU_WRITER_SPIN_LOCK_LONG)
			spin_lock(&rcu_writer_lock);
		if (rcu_writer_lock_method == RCU_WRITER_SPIN_LOCK_IRQ ||
		    rcu_writer_lock_method == RCU_WRITER_SPIN_LOCK_IRQ_LONG)
			spin_lock_irq(&rcu_writer_lock);
#endif

		old_rcu = non_atomic_rcu;
		new_rcu = kmalloc(sizeof(*new_rcu), 0, '1234');
		if (new_rcu == NULL) {
			printk("no memory\n");
#if 0
			if (rcu_writer_lock_method == RCU_WRITER_SPIN_LOCK ||
		    	    rcu_writer_lock_method == RCU_WRITER_SPIN_LOCK_LONG)
				spin_unlock(&rcu_writer_lock);
			if (rcu_writer_lock_method == RCU_WRITER_SPIN_LOCK_IRQ ||
		    	    rcu_writer_lock_method == RCU_WRITER_SPIN_LOCK_IRQ_LONG)
				spin_unlock_irq(&rcu_writer_lock);
#endif

			complete(c);
			return -1;
		}
		*new_rcu = *non_atomic_rcu;

		val = new_rcu->a;
		val++;
		new_rcu->a = val;

		val = new_rcu->b;
		val++;
		new_rcu->b = val;

		rcu_assign_pointer(non_atomic_rcu, new_rcu);
#if 0
		if (rcu_writer_lock_method == RCU_WRITER_SPIN_LOCK)
			spin_unlock(&rcu_writer_lock);
		if (rcu_writer_lock_method == RCU_WRITER_SPIN_LOCK_IRQ)
			spin_unlock_irq(&rcu_writer_lock);
#endif

		synchronize_rcu();

/* too noisy 
		if (test_debug)
			printk("about to free old RCU at %p\n", old_rcu);
*/
		kfree(old_rcu);

#if 0
		if (rcu_writer_lock_method == RCU_WRITER_SPIN_LOCK_LONG)
			spin_unlock(&rcu_writer_lock);
		if (rcu_writer_lock_method == RCU_WRITER_SPIN_LOCK_IRQ_LONG)
			spin_unlock_irq(&rcu_writer_lock);
#endif
	}
	complete(c);

	return 0;
}

static void rcu_test(int argc, const char **argv)
{
	const char *s;
	int num_readers;
	int num_writers;
	int i;
	struct completion **completions;
	enum rcu_lock_methods m;
	enum rcu_writer_lock_methods mw;
	enum rcu_read_methods rrm;
	size_t len;

	test_debug = 0;
	rcu_writers_finished = 0;

	i=1;
	if (argv[1][0] == '-') {
		switch (argv[1][1]) {
		case 'd': test_debug = 1; break;
		default: goto usage;
		}
		i++;
	}
	if (argc != i+6)
		goto usage;

	num_readers = my_strtoull(argv[i], &s, 10);
	if (*s != '\0')
		goto usage;

	num_writers = my_strtoull(argv[i+1], &s, 10);
	if (*s != '\0')
		goto usage;

	rcu_n = my_strtoull(argv[i+2], &s, 10);
	if (*s != '\0')
		goto usage;

	for (m=RCU_NONE;m<RCU_LAST;m++) {
		len = strlen(rcu_lock_methods[m]);
		if (strncmp(rcu_lock_methods[m], argv[i+3], len) == 0 &&
		   (argv[i+3][len] == '\0'))
			break;
	}
	if (m == RCU_LAST) 
		goto usage;
	rcu_lock_method = m;

	for (mw=RCU_WRITER_NONE;mw<RCU_WRITER_LAST;mw++) {
		len = strlen(rcu_writer_lock_methods[mw]);
		if (strncmp(rcu_writer_lock_methods[mw], argv[i+4], len) == 0 &&
		   (argv[i+4][len] == '\0'))
			break;
	}
	if (mw == RCU_WRITER_LAST) 
		goto usage;
	rcu_writer_lock_method = mw;

	for (rrm=RRM_DEREFERENCE;rrm<RRM_LAST;rrm++) {
		len = strlen(rcu_read_methods[rrm]);
		if (strncmp(rcu_read_methods[rrm], argv[i+5], len) == 0 &&
		   (argv[i+5][len] == '\0'))
			break;
	}
	if (rrm == RRM_LAST) 
		goto usage;
	rcu_read_method = rrm;

	printk("rcu_lock_method is %d (%s) rcu_writer_lock_method is %d (%s)\n", rcu_lock_method, rcu_lock_methods[rcu_lock_method], rcu_writer_lock_method, rcu_writer_lock_methods[rcu_writer_lock_method]);

	non_atomic_rcu = kmalloc(sizeof(*non_atomic_rcu), 0, '1234');
	if (non_atomic_rcu == NULL) {
		printk("No memory\n");
		return;
	}
	non_atomic_rcu->a = 0;
	non_atomic_rcu->b = 0;

	atomic_set(&rcu_num_read_errors, 0);

	if (test_debug)
		printk("alloc %d bytes for completion\n", sizeof(*completions)*(num_readers+num_writers));

	completions = kmalloc(sizeof(*completions)*(num_readers+num_writers), 0, '1234');
	if (completions == NULL) {
		printk("No memory\n");
		return;
	}
	spin_lock_init(&rcu_writer_lock);

	for (i=0;i<num_writers;i++) {
		if (test_debug)
			printk("alloc writer %d\n", i);

		completions[i] = kmalloc(sizeof(struct completion), 0, '1234');
		if (completions[i] == NULL) {
			printk("Not enough memory\n");
			return;
		}

		init_completion(completions[i]);
		kthread_run(rcu_writer, completions[i], "rcu_writer");
	}
	for (;i<num_readers+num_writers;i++) {
		if (test_debug)
			printk("alloc reader %d\n", i);

		completions[i] = kmalloc(sizeof(struct completion), 0, '1234');
		if (completions[i] == NULL) {
			printk("Not enough memory\n");
			return;
		}

		init_completion(completions[i]);
		kthread_run(rcu_reader, completions[i], "rcu_reader");
	}
	for (i=0;i<num_writers;i++) {
		if (test_debug)
			printk("wait for completion writer %d\n", i);

		wait_for_completion(completions[i]);
		if (test_debug)
			printk("thread %i completed\n", i);
		kfree(completions[i]);
	}
	rcu_writers_finished = 1;
	for (;i<num_readers+num_writers;i++) {
		if (test_debug)
			printk("wait for completion reader %d\n", i);

		wait_for_completion(completions[i]);
		if (test_debug)
			printk("thread %i completed\n", i);
		kfree(completions[i]);
	}
	kfree(completions);

	printk("non_atomic_rcu->a is %lld non_atomic_rcu->b is %lld\n",
		non_atomic_rcu->a, non_atomic_rcu->b);
	kfree(non_atomic_rcu);

	if (atomic_read(&rcu_num_read_errors) > 0)
		printk("%d read errors\n", atomic_read(&rcu_num_read_errors));
	else
		printk("Test succeeded\n");

	return;
usage:
	printk("Usage: rcu_test <num-readers> <num-writers> <n> <none|rcu_read_lock|spin_lock|spin_lock_irq> <none|spin_lock|spin_lock_irq|spin_lock_long|spin_lock_irq_long> <dereference|direct>\n");
}

static unsigned long long n;
static unsigned long long num_threads;

enum lock_methods { LM_NONE, LM_SPIN_LOCK, LM_SPIN_LOCK_IRQ, LM_SPIN_LOCK_IRQSAVE, LM_MUTEX, LM_CRITICAL_REGION, LM_TWO_SPINLOCKS, LM_TWO_SPINLOCKS_PASSIVE_LEVEL, LM_SEMAPHORE, LM_RW_SEMAPHORE_READ, LM_RW_SEMAPHORE_WRITE, LM_LAST };
static char *lock_methods[LM_LAST] = {
	"none", "spin_lock", "spin_lock_irq", "spin_lock_irqsave", "mutex", "critical_region", "two_spinlocks", "two_spinlocks_passive_level", "semaphore", "rw_semaphore_read", "rw_semaphore_write"
};
static enum lock_methods lock_method;

struct params {
	int thread_num;
	struct completion *c;
};

int concurrency_thread(void *p)
{
	long long j;
	volatile long long val;
	struct params *param = p;
	struct completion *completion = param->c;
	KIRQL flags;

	flags = 0;
	for (j=0;j<n;j++) {
		switch (lock_method) {
		case LM_RW_SEMAPHORE_READ:
			down_read(&test_rw_semaphore);
			break;

		case LM_RW_SEMAPHORE_WRITE:
			down_write(&test_rw_semaphore);
			break;

		case LM_SEMAPHORE:
			down(&test_semaphore);
			break;

#if 0
		case LM_TWO_SPINLOCKS_PASSIVE_LEVEL:
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d before spin_lock\n", KeGetCurrentIrql());
			spin_lock(&test_locks[param->thread_num & 1]);
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d after spin_lock\n", KeGetCurrentIrql());
			break;

		case LM_TWO_SPINLOCKS:
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d before spin_lock\n", KeGetCurrentIrql());
			spin_lock_irq(&test_locks[param->thread_num & 1]);
			if (KeGetCurrentIrql() != DISPATCH_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d after spin_lock\n", KeGetCurrentIrql());
			break;
#endif

		case LM_CRITICAL_REGION:
			KeEnterCriticalRegion();
			break;

		case LM_MUTEX:
			mutex_lock(&test_mutex);
			break;

#if 0
		case LM_SPIN_LOCK:
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d before spin_lock\n", KeGetCurrentIrql());
			spin_lock(&test_locks[0]);
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d after spin_lock\n", KeGetCurrentIrql());
			break;

		case LM_SPIN_LOCK_IRQ:
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d before spin_lock\n", KeGetCurrentIrql());
			spin_lock_irq(&test_locks[0]);
			if (KeGetCurrentIrql() != DISPATCH_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d after spin_lock\n", KeGetCurrentIrql());
			break;
#endif

		case LM_SPIN_LOCK_IRQSAVE:
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d before spin_lock\n", KeGetCurrentIrql());
			spin_lock_irqsave(&test_locks[0], flags); /* is a macro */
			if (KeGetCurrentIrql() != DISPATCH_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d after spin_lock\n", KeGetCurrentIrql());
			if (flags != PASSIVE_LEVEL)
				printk("Warning: flags is %d\n", flags);
			break;
		case LM_NONE:
			break;
		default:
			printk("lock method %d not supported.\n", lock_method);
			return -1;
		}

		val = non_atomic_int;
		val++;
		non_atomic_int = val;

		switch (lock_method) {
		case LM_RW_SEMAPHORE_READ:
			up_read(&test_rw_semaphore);
			break;

		case LM_RW_SEMAPHORE_WRITE:
			up_write(&test_rw_semaphore);
			break;

		case LM_SEMAPHORE:
			up(&test_semaphore);
			break;

		case LM_TWO_SPINLOCKS_PASSIVE_LEVEL:
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d before spin_lock\n", KeGetCurrentIrql());
			spin_unlock(&test_locks[param->thread_num & 1]);
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d after spin_lock\n", KeGetCurrentIrql());
			break;

#if 0
		case LM_TWO_SPINLOCKS:
			if (KeGetCurrentIrql() != DISPATCH_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d before spin_lock\n", KeGetCurrentIrql());
			spin_unlock_irq(&test_locks[param->thread_num & 1]);
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d after spin_lock\n", KeGetCurrentIrql());
			break;
#endif

		case LM_CRITICAL_REGION:
			KeLeaveCriticalRegion();
			break;

		case LM_MUTEX:
			mutex_unlock(&test_mutex);
			break;

#if 0
		case LM_SPIN_LOCK:
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d before spin_unlock\n", KeGetCurrentIrql());
			spin_unlock(&test_locks[0]);
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d after spin_unlock\n", KeGetCurrentIrql());
			break;
		case LM_SPIN_LOCK_IRQ:
			if (KeGetCurrentIrql() != DISPATCH_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d before spin_lock\n", KeGetCurrentIrql());
			spin_unlock_irq(&test_locks[0]);
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d after spin_lock\n", KeGetCurrentIrql());
			break;
#endif
		case LM_SPIN_LOCK_IRQSAVE:
			if (KeGetCurrentIrql() != DISPATCH_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d before spin_lock\n", KeGetCurrentIrql());
			spin_unlock_irqrestore(&test_locks[0], flags);
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				printk("Warning: KeGetCurrentIrql() is %d after spin_lock\n", KeGetCurrentIrql());
			break;
		case LM_NONE:
			break;
		default:
			printk("lock method %d not supported.\n", lock_method);
			return -1;
		}
	}

	if (test_debug)
		printk("thread #%d finished\n", param->thread_num);

	complete(completion);
	return 0;
}

/* windrbd run-test 'concurrency_test 100 10000000 spin_lock' */

void concurrency_test(int argc, const char **argv)
{
	unsigned long long i;
	const char *s;
	size_t len;
	struct completion **completions;
	struct params **params;
	enum lock_methods m;

	test_debug = 0;

	if (argc < 4)
		goto usage;

	i=1;
	if (argv[1][0] == '-') {
		switch (argv[1][1]) {
		case 'd': test_debug = 1; break;
		default: goto usage;
		}
		i++;
	}
	if (argc != i+3)
		goto usage;

	num_threads = my_strtoull(argv[i], &s, 10);
	if (*s != '\0')
		goto usage;

	i++;
	n = my_strtoull(argv[i], &s, 10);
	if (*s != '\0')
		goto usage;

	i++;
	for (m=LM_NONE;m<LM_LAST;m++) {
		len = strlen(lock_methods[m]);
		if (strncmp(lock_methods[m], argv[i], len) == 0 &&
		   (argv[i][len] == '\0'))
			break;
	}
	if (m == LM_LAST) 
		goto usage;
	lock_method = m;

	if (test_debug) {
		printk("n is %llu num_threads is %llu lock_method is %s\n", n, num_threads, lock_methods[m]);
		printk("sizeof(non_atomic_int) is %d\n", sizeof(non_atomic_int));
	}

	non_atomic_int = 0;
	spin_lock_init(&test_locks[0]);
	spin_lock_init(&test_locks[1]);
	mutex_init(&test_mutex);
	sema_init(&test_semaphore, 1);
	init_rwsem(&test_rw_semaphore);

	completions = kmalloc(sizeof(*completions)*num_threads, 0, '1234');
	if (completions == NULL) {
		printk("Not enough memory\n");
		return;
	}
	params = kmalloc(sizeof(*params)*num_threads, 0, '1234');
	if (params == NULL) {
		printk("Not enough memory\n");
		return;
	}

	for (i=0;i<num_threads;i++) {
		completions[i] = kmalloc(sizeof(struct completion), 0, '1234');
		if (completions[i] == NULL) {
			printk("Not enough memory\n");
			return;
		}

		init_completion(completions[i]);
		params[i] = kmalloc(sizeof(struct params), 0, '1234');
		if (params[i] == NULL) {
			printk("Not enough memory\n");
			return;
		}
		params[i]->c = completions[i];
		params[i]->thread_num = i;

		if (test_debug)
			printk("about to start thread %i\n", i);

		kthread_run(concurrency_thread, params[i], "concurrency_test");
	}
	for (i=0;i<num_threads;i++) {
		wait_for_completion(completions[i]);
		if (test_debug)
			printk("thread %i completed\n", i);
		kfree(completions[i]);
		kfree(params[i]);
	}
	kfree(completions);
	kfree(params);

	if (non_atomic_int != n*num_threads) {
		printk("Test failed\n");
	}
	printk("non_atomic_int is %lld (should be %lld)\n", non_atomic_int, n*num_threads);
	return;

usage:
	printk("Usage: concurrency_test [-d] <num_threads> <n> <lock-method>\n");
}

void mutex_trylock_test(void)
{
	static struct mutex m, m2;
	int i, i2;

	mutex_init(&m);
	mutex_init(&m2);

		/* TODO: muteces are recursive ... */
	i = mutex_trylock(&m);
	if (i) {
		i2 = mutex_trylock(&m);
		if (i2)
			printk("mutex_trylock succeeded twice\n");
	}
	while (mutex_is_locked(&m)) {
		printk("mutex_unlock ...\n");
		mutex_unlock(&m);
	}
		/* here all mutexes must be unlocked (=signalled state)
		 * else BSOD on returning to user space.
		 */
}

struct object {
	struct work_struct work;
	int counter;
};

static void workqueue_worker(struct work_struct *work)
{
	struct object *obj = container_of(work, struct object, work);

	obj->counter++;
}

struct workqueue_params {
	struct object *obj;
	struct workqueue_struct *w;
	long long n;
	int thread_num;
	struct completion completion;
};

static int queue_work_thread(void *pp)
{
	struct workqueue_params *p = pp;
	long long i;

printk("thread %d before queue_work\n", p->thread_num);
	for (i=0;i<p->n;i++)
		queue_work(p->w, &p->obj->work);

printk("thread %d after queue_work\n", p->thread_num);

	complete(&p->completion);

printk("queue_work thread %d completed\n", p->thread_num);

	return 0;
}

/* windrbd 'workqueue-test 1000000 10' freezes the machine sometimes */
/* with new implementation windrbd 'workqueue-test 10000000 100' does
   not freeze (however counter is less than expected value because
   of pending logic). */

static void workqueue_test(int argc, const char ** argv)
{
	struct workqueue_struct *w;
	struct object *obj;

	long long i, n;
	int j, num_threads;

	struct workqueue_params *params;

	n = 100;
	num_threads = 1;

	if (argc > 1)
		n = my_strtoull(argv[1], NULL, 10);
	if (argc > 2)
		num_threads = my_strtoull(argv[2], NULL, 10);

	w = alloc_ordered_workqueue("test%d", 0, 1);
	if (w == NULL) {
		printk("could not allocate workqueue\n");
		return;
	}
	obj = kmalloc(sizeof(*obj), 0, 'DRBD');
	if (obj == NULL) {
		printk("could not allocate object\n");
		return;
	}
	obj->counter = 0;
	INIT_WORK(&obj->work, workqueue_worker);

	params = kmalloc(sizeof(*params)*num_threads, 0, 'DRBD');
	if (params == NULL) {
		printk("Could not allocate params\n");
		return;
	}
	for (j=0;j<num_threads;j++) {
		params[j].n = n;
		params[j].obj = obj;
		params[j].w = w;
		params[j].thread_num = j;
		init_completion(&params[j].completion);

		kthread_run(queue_work_thread, &params[j], "workqueue_submitter");
	}
printk("threads started now waiting for completion.\n");
	for (j=0;j<num_threads;j++)
		wait_for_completion(&params[j].completion);

printk("threads completed now waiting for workqueue.\n");
	flush_workqueue(w);
	printk("obj->counter is %d (should be max %d)\n", obj->counter, n*num_threads);

	kfree(obj);
	destroy_workqueue(w);
	kfree(params);
}

enum wq_test { WQ_NO_WAIT, WQ_SIMPLE, WQ_FAST, WQ_NO_SLEEP, WQ_LOOP, WQ_LOOP_NO_SLEEP, WQ_LAST };
static char *wq_test_str[WQ_LAST] = {
	"no-wait", "simple", "fast", "no-sleep", "loop", "loop-no-sleep"
};

static int cond = 0;
static atomic_t num_wakers_running = { 0 };

static enum wq_test wt;
static wait_queue_head_t wq;
static wait_queue_head_t wq2;
static int waker_loops = 1000;
static int waiter_loops = 1000;

static int waker_task(void *unused)
{
	int msec = 0;
	int loop_cnt = 1;

	switch (wt) {
	case WQ_SIMPLE: msec = 1000; break;
	case WQ_FAST: 
	case WQ_LOOP: msec = 10; break; 
	case WQ_LOOP_NO_SLEEP:
	case WQ_NO_SLEEP: msec = 0; break;
	}
	if (wt == WQ_LOOP || wt == WQ_LOOP_NO_SLEEP)
		loop_cnt = waker_loops;

printk("waker started\n");
	for (;loop_cnt>0;--loop_cnt) {
		if (msec > 0)
			msleep(msec);
#if 0
printk("waking up #1 (loop_cnt is %d)\n", loop_cnt);
		cond = 0;
		wake_up(&wq);
		if (msec > 0)
			msleep(msec);
#endif
printk("waking up #2 (with cond true) (loop_cnt is %d)\n", loop_cnt);
		cond = 1;
		wake_up(&wq);
printk("waiting for waiter ...\n");
		wait_event(wq2, !cond);
	}
printk("waker end\n");
	atomic_dec(&num_wakers_running);
	wake_up(&wq);

	return 0;
}

static int waiter_task(void *unused)
{
	int msec = 0;
	int loop_cnt = 1;

	if (wt == WQ_LOOP || wt == WQ_LOOP_NO_SLEEP)
		loop_cnt = waiter_loops;

	for (;loop_cnt>0;loop_cnt--) {
		cond = 0;
		if (wt == WQ_NO_WAIT)
			cond = 1;

printk("into wait_event ... loop_cnt is %d\n", loop_cnt);
		wait_event(wq, cond || atomic_read(&num_wakers_running) == 0);
		if (atomic_read(&num_wakers_running) == 0) {
			printk("no more wakers, exiting waiter\n");
			break;
		}
		cond = 0;
		wake_up(&wq2);
printk("out of wait_event cond is %d loop_cnt is %d\n", cond, loop_cnt);
	}
	return 0;
}

static void wait_event_test(int argc, const char ** argv)
{
	int i, t;
	int len;
	int num_wakers;
	int num_waiters;

	if (argc != 6)
		goto usage;

	i=1;
	for (wt=0;wt<WQ_LAST;wt++) {
		len = strlen(wq_test_str[wt]);
		if (strncmp(wq_test_str[wt], argv[i], len) == 0 &&
		   (argv[i][len] == '\0'))
			break;
	}
	if (wt == WQ_LAST) 
		goto usage;

	num_wakers = my_atoi(argv[2]);
	num_waiters = my_atoi(argv[3]);
	waker_loops = my_atoi(argv[4]);
	waiter_loops = my_atoi(argv[5]);

	init_waitqueue_head(&wq);
	init_waitqueue_head(&wq2);
	if (wt != WQ_NO_WAIT) {
		for (t=0;t<num_wakers;t++) {
			struct task_struct *k;

			atomic_inc(&num_wakers_running);
			k = kthread_create(waker_task, NULL, "waker%d", t);
printk("thread is %p t is %d\n", k, t);
			wake_up_process(k);
		}
		for (t=0;t<num_waiters;t++) {
			struct task_struct *k;

			k = kthread_create(waiter_task, NULL, "waiter%d", t);
printk("thread is %p t is %d\n", k, t);
			wake_up_process(k);
		}
	}

printk("exiting waiter\n");

	return;
usage:
	printk("usage: wait_event_test <no-wait|simple|fast|no-sleep|loop> <num-wakers> <num-waiters> <waker-loops> <waiter-loops>\n");
}

void argv_test(int argc, char ** argv)
{
	int i;

	for (i=0; i<argc; i++)
		printk("argv[%d] is %s\n", i, argv[i]);
}

#if (NTDDI_VERSION >= NTDDI_VISTA)

// #include <windows.h>
#include <bcrypt.h>

int crypto_test(int argc, char ** argv)
{
#if 0
	HCRYPTPROV provider;
	BOOL ret;

	ret = CryptAcquireContext(&provider, (char*) 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	if (!ret)
		printk("CryptAcquireContext failed\n");
	else
		printk("CryptAcquireContext succeeded\n");
	
	return 0;
#endif
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlg = NULL;

//	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status)) {
		printk("BCryptOpenAlgorithmProvider failed, status is %x\n", status);
		return -1;
	}
	printk("BCryptOpenAlgorithmProvider succeeded\n");
	return 0;
}

#endif

extern void start_tiktok(int argc, const char ** argv);

extern void write_to_eventlog(int loglevel, const char *msg);
extern void split_message_and_write_to_eventlog(int loglevel, const char *msg);

static void test_event_log(int argc, char ** argv)
{
	int i;

	for (i=1; i<argc; i++) {
		printk("argv[%d] is %s\n", i, argv[i]);
		write_to_eventlog(i, argv[i]);
	}
}


static void test_event_log_split(int argc, char ** argv)
{
	int i;

	for (i=1; i<argc; i++) {
		printk("argv[%d] is %s\n", i, argv[i]);
		split_message_and_write_to_eventlog(i, argv[i]);
	}
}

static void test_event_log_level(int argc, char ** argv)
{
	printk("info default");

/* those should go to error log: */
	printk(KERN_EMERG "emerg");
	printk(KERN_ALERT "alert");
	printk(KERN_CRIT  "crit");
	printk(KERN_ERR   "error");
/* This to warnings: */
	printk(KERN_WARNING "warning");
/* these to Info: */
	printk(KERN_NOTICE "notice");
	printk(KERN_INFO "info");
	printk(KERN_DEBUG "debug");
}

static void set_event_log_level_test(int argc, char ** argv)
{
	int level;

	if (argc == 2) {
		level = my_atoi(argv[1]);
		set_event_log_threshold(level);
	} else {
		printk("Usage: set_event_log_level_test <loglevel>\n");
	}
}

static void force_unlock(int argc, char ** argv)
{
	printk("Forcing driver unlock, sc stop windrbd should work now...\n");
	mvolDriverObject->DriverExtension->AddDevice = NULL;
}

static void print_add_device(int argc, char ** argv)
{
	printk("AddDevice is %p\n", mvolDriverObject->DriverExtension->AddDevice);
}

enum free_test { UNDEFINED, KMALLOC, EXALLOCATEPOOL, CONCURRENT, CORRUPTAFTER };

#define NUM_POINTERS 256
#define NUM_ROUNDS 10*1024
#define NUM_MEMALLOC_THREADS 10

static int malloc_free_task(void *unused)
{
	void *pointers[NUM_POINTERS];
	int i, j;

	for (j=0; j<NUM_ROUNDS; j++) {
		if (j % 100 == 0)
			printk("Round %d ...\n", j);

		for (i=0; i<NUM_POINTERS; i++) {
			pointers[i] = kmalloc(4096, 0, 'DRBD');
			if (pointers[i] == NULL) {
				printk("Bad! Out of memory.\n");
				return 1;
			}
		}
		for (i=0; i<NUM_POINTERS; i++) {
			kfree(pointers[i]);
		}
	}
	return 0;
}


static void double_free_test(int argc, char ** argv)
{
	void *p;
	enum free_test free_test = UNDEFINED;
	int i;
	struct task_struct *k;

	if (argc >= 2) {
		if (strcmp(argv[1], "kmalloc") == 0)
			free_test = KMALLOC;
		if (strcmp(argv[1], "exallocatepool") == 0)
			free_test = EXALLOCATEPOOL;
		if (strcmp(argv[1], "concurrent") == 0)
			free_test = CONCURRENT;
		if (strcmp(argv[1], "corruptafter") == 0)
			free_test = CORRUPTAFTER;
	}

	switch (free_test) {
	case UNDEFINED:
		printk("Usage: windrbd run-test double_free_test <test-method>\n");
		printk("Currently implemented test methods are: kmalloc exallocatepool concurrent\n");
		break;

	case KMALLOC:		/* might be IRQL BSOD */
		p=kmalloc(4096, 0, 'DRBD');
		if (p==NULL) {
			printk("Oops. Out of memory.\n");
			return;
		}
		kfree(p);
		kfree(p);	/* expecing this to be ignored. */
		break;

	case EXALLOCATEPOOL:	/* BAD_POOL_HEADER */
		p=ExAllocatePoolWithTag(NonPagedPool, 4096, 'DRBD');
		if (p==NULL) {
			printk("Oops. Out of memory.\n");
			return;
		}
		ExFreePool(p);
/* This is intentional but codeql static verifier complains, so commented out */
#if 0
		ExFreePool(p);	/* expecing this to crash somehow. */
#endif
		break;
	case CONCURRENT:
		for (i=0; i<NUM_MEMALLOC_THREADS; i++) {
			k = kthread_create(malloc_free_task, NULL, "memory-%d", i);
			wake_up_process(k);
		}
		break;
	case CORRUPTAFTER:
		p=kmalloc(4096, 0, 'DRBD');
		if (p==NULL) {
			printk("Oops. Out of memory.\n");
			return;
		}
		((char*)p)[4096] = 0xaa;	/* memory check should find this */
		break;
	}
}

static void rtl_zero_memory_test(int argc, char ** argv)
{
	printk("About to RtlZeroMemory(NULL, ...) ...\n");
	msleep(1000);
#pragma warning (disable: 6387)
	/* This is intentional: should BSOD */
	RtlZeroMemory(NULL, 24);
	printk("Still alive?\n");
}

	/* With driver verifier on or debugging this currently BSODs ... */

extern char *copy_first_640k(void);

static void io_map_test(int argc, char ** argv)
{
	char *mem;

	printk("About to read first 640K of memory ...\n");
	msleep(1000);
	mem = copy_first_640k();

	printk("Still alive?\n");
	printk("mem is %p\n", mem);
	kfree(mem);
}

static void leak_test(int argc, char ** argv)
{
	char *mem;
	size_t bytes;

	if (argc >= 2) {
		bytes = my_atoi(argv[1]);
		mem = kmalloc(bytes, 0, 'DRBD');
		printk("Leaked %d bytes ...\n", bytes);
	} else {
		printk("Usage: windrbd run-test leak_test <size-in-bytes>\n");
	}
}

void test_main(const char *arg)
{
	char *arg_mutable, *s;
	char **argv;
	int argc;
	int i;

	arg_mutable = kstrdup(arg, 0);
	if (arg_mutable == NULL) {
		printk("Sorry no memory.\n");
		return;
	}
	s = arg_mutable;
	argc = 0;

	while (1) {
		while (*s == ' ') s++;
		if (*s == '\0')
			break;
		argc++;
		while (*s != ' ' && *s != '\0') s++;
	}
	argv = kmalloc(sizeof(*argv)*(argc+1), 0, 'DRBD');
	if (argv == NULL) {
		printk("Sorry no memory.\n");
		goto kfree_arg_mutable;
	}

	i = 0;
	s = arg_mutable;
	while (1) {
		while (*s == ' ') s++;
		if (*s == '\0')
			break;
		argv[i] = s;
		i++;
		while (*s != ' ' && *s != '\0') s++;
		if (*s != '\0') {
			*s = '\0';
			s++;
		}
	}
	if (i!=argc) {
		printk("Bug: i (%d) != argc(%d)\n", i, argc);
		goto kfree_argv;
	}

	if (strcmp(argv[0], "mutex_trylock_test") == 0)
		mutex_trylock_test();
	if (strcmp(argv[0], "concurrency_test") == 0)
		concurrency_test(argc, argv);
	if (strcmp(argv[0], "argv_test") == 0)
		argv_test(argc, argv);
#if (NTDDI_VERSION >= NTDDI_VISTA)
	if (strcmp(argv[0], "crypto_test") == 0)
		crypto_test(argc, argv);
#endif
	if (strcmp(argv[0], "rcu_test") == 0)
		rcu_test(argc, argv);
	if (strcmp(argv[0], "enable_debug_printks") == 0)
		debug_printks_enabled = 1;
	if (strcmp(argv[0], "disable_debug_printks") == 0)
		debug_printks_enabled = 0;
	if (strcmp(argv[0], "workqueue_test") == 0)
		workqueue_test(argc, argv);
	if (strcmp(argv[0], "wait_event_test") == 0)
		wait_event_test(argc, argv);
	if (strcmp(argv[0], "start_tiktok") == 0)
		start_tiktok(argc, argv);
	if (strcmp(argv[0], "event_log") == 0)
		test_event_log(argc, argv);
	if (strcmp(argv[0], "event_log_level_test") == 0)
		test_event_log_level(argc, argv);
	if (strcmp(argv[0], "event_log_split") == 0)
		test_event_log_split(argc, argv);
	if (strcmp(argv[0], "set_event_log_level") == 0)
		set_event_log_level_test(argc, argv);
	if (strcmp(argv[0], "force_unlock") == 0)
		force_unlock(argc, argv);
	if (strcmp(argv[0], "print_add_device") == 0)
		print_add_device(argc, argv);
	if (strcmp(argv[0], "double_free_test") == 0)
		double_free_test(argc, argv);
	if (strcmp(argv[0], "rtl_zero_memory_test") == 0)
		rtl_zero_memory_test(argc, argv);
	if (strcmp(argv[0], "io_map_test") == 0)
		io_map_test(argc, argv);
	if (strcmp(argv[0], "leak_test") == 0)
		leak_test(argc, argv);

kfree_argv:
	kfree(argv);
kfree_arg_mutable:
	kfree(arg_mutable);
}

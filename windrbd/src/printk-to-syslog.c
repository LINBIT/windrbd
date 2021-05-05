#include <wdm.h>
#include "drbd_windows.h"
#include <Ntstrsafe.h>
#include <linux/net.h>
#include <linux/socket.h>

/* We have three logging 'targets': One is the standard DbgPrint
   facility provided by Windows. Use a tool like DbgView to view
   them on the local host or use a remote kernel debugger (WinDbg)
   to see them. The mem printk just writes into the ring buffer.
   It might be useful when Windows runs in a Virtual machine
   or the Windows dump kernel memory on BSOD is enabled.
   One can dump the memory core via the virtual machine manager
   to see the logs (use string utility to make the image a
   little smaller). The last target is the network. We send
   UDP packets (later TCP/IP optionally) to a syslog server
   (this also might be a netcat). This is the standard way
   we use when debugging under normal conditions. The drawback
   is that network packets cannot be sent when IRQL is raised
   (we store messages sent at raised IRQL and send them later
   but if we blue screen before IRQL is lowered again, we don't
   see them. Another drawback is that logging via net might
   affect system stability, so this should be turned off
   for production releases.
*/

/* Later: have ioctl to control these, also have ioctl to configure
 * syslog ip and maybe port and also the protocol (UDP or TCP).
 */

static int no_windows_printk = 1;
static int no_memory_printk = 0;
static int no_net_printk = 1;

/* TODO: use (and test) O_NONBLOCK sending again, once weird printk
 * losses are fixed.
 */

#define RING_BUFFER_SIZE 1048576

static char syslog_ip[64];

static struct socket *printk_udp_socket;
static SOCKADDR_IN printk_udp_target;

static char ring_buffer[RING_BUFFER_SIZE];
static size_t ring_buffer_head;
static size_t ring_buffer_tail;
static spinlock_t ring_buffer_lock;
static struct mutex send_mutex;
static int printk_shut_down;

static unsigned long long serial_number;
static spinlock_t serial_number_lock;

static spinlock_t in_printk_lock;
static int in_printk;

static unsigned long long when_to_start_sending;
static int initial_send_delay = 5;	/* in seconds */
static int printk_thread_started;

int initialize_syslog_printk(void)
{
	spin_lock_init(&ring_buffer_lock);
	spin_lock_init(&in_printk_lock);
	spin_lock_init(&serial_number_lock);

		/* don't debug them ... to avoid endless loop */
	ring_buffer_lock.printk_lock = true;
	in_printk_lock.printk_lock = true;
	serial_number_lock.printk_lock = true;

	mutex_init(&send_mutex);
	in_printk = 0;

	return 0;
}

static void stop_net_printk(void)
{
	if (printk_udp_socket) {
		printk("shutting down printk ...\n");
		sock_release(printk_udp_socket);
		printk_udp_socket = NULL;
	}
}

void set_syslog_ip(const char *ip)
{
	if (strcmp(ip, syslog_ip) == 0)
		return;

	strncpy(syslog_ip, ip, ARRAY_SIZE(syslog_ip)-1);
	syslog_ip[ARRAY_SIZE(syslog_ip)-1] = '\0';

	stop_net_printk();

		/* will be started again with next printk */

	printk("syslog_ip set to %s\n", syslog_ip);
}

	/* Call this before shuting down socket layer, it would stall
	 * on releasing the provider network programming interface
	 * (NPI) when there are any sockets open.
	 */

void shutdown_syslog_printk(void)
{
	stop_net_printk();

	printk_shut_down = 1;
}

/* To enable UDP logging in rsyslogd
 * put (or uncomment) following lines into /etc/rsyslog.conf:
module(load="imudp")
input(type="imudp" port="514")
 * then do a 
bash$ sudo service syslog restart
 */

int my_inet_aton(const char *cp, struct in_addr *inp)
{
	unsigned char ip[4];
	int i, j;

	j = 0;
	for (i=0;i<4;i++) {
		ip[i] = 0;
		while (isdigit(cp[j])) {
			ip[i] *= 10;
			ip[i] += cp[j]-'0';
			j++;
		}
		if (i != 3) {
			if (cp[j] != '.')
				return -1;
			j++;
		}
	}
	inp->s_addr = ip[0] + (ip[1] << 8) + (ip[2] << 16) + (ip[3] << 24);
	return 0;
}

/* Reverse of the above. Non threadsafe (returns static variable).
 */
char *my_inet_ntoa(struct in_addr *addr)
{
        static char s[30];

        snprintf(s, sizeof(s)-1, "%d.%d.%d.%d", addr->s_addr & 0xff, addr->s_addr >> 8 & 0xff, addr->s_addr >> 16 & 0xff, addr->s_addr >> 24);
        return s;
}

static int wait_a_bit_and_then_printk(void *unused)
{
	msleep((initial_send_delay + 2) * 1000);

	printk_thread_started = 0;

		/* If we still can't send, this printk will
		 * call open_syslog_socket and create a new
		 * thread that tries again.
		 */

	printk("Starting sending printk's over network\n");

	return 0;
}

static int open_syslog_socket(void)
{
	int err;
	NTSTATUS status;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Initializing syslog logging\n");
	if (printk_shut_down) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Cannot create printk socket, printk already shut down.\n");
		return 0;
	}
	if (printk_udp_socket == NULL) {
		struct sockaddr_in local;

		when_to_start_sending = 0;

		printk_udp_target.sin_family = AF_INET;
		printk_udp_target.sin_port = htons(514);

		if (my_inet_aton(syslog_ip, &printk_udp_target.sin_addr) < 0) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Invalid syslog IP address: %s\nYou will NOT see any output produced by printk (and pr_err, ...)\n", syslog_ip);
			return -1;
		}

		local.sin_family = AF_INET;
		local.sin_addr.s_addr = 0;
		local.sin_port = 0;

		err = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &printk_udp_socket);
		if (err == 0) {
			status = printk_udp_socket->ops->bind(printk_udp_socket, (struct sockaddr *) &local, sizeof(local));
			if (!NT_SUCCESS(status)) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to Bind socket, status is %x\n", status);

				sock_release(printk_udp_socket);
				printk_udp_socket = NULL;
			} else {
				/* TODO: UDP sockets now can 'repair'
				 * themselves ... this probe is needed
				 * however since SendTo in printk isn't
				 * retried at the moment. Fix this
				 * somehow later.
				 */
				char *probe = "Starting printk ...\n";
				err = SendTo(printk_udp_socket,
						probe,
						strlen(probe),
						(PSOCKADDR)&printk_udp_target);

					/* -ENETUNREACH on booting */
				if (err < 0) {
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to SendTo to syslog IP %s, err is %x\n", syslog_ip, err);

					sock_release(printk_udp_socket);
					printk_udp_socket = NULL;
				}
			}
		} else {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Could not create syslog socket for sending log messages to\nsyslog facility (error is %d). You will NOT see any output produced by printk (and pr_err, ...)\n", err);
			return -1;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "socket opened, ring_buffer_head: %d ring_buffer_tail: %d\n", ring_buffer_head, ring_buffer_tail);

		when_to_start_sending = jiffies + initial_send_delay * HZ;

		if (!printk_thread_started) {
			printk_thread_started = 1;
			kthread_run(wait_a_bit_and_then_printk, NULL, "printk-init");
		}
	}
	return 0;
}


int currently_in_printk(void)
{
	KIRQL flags;

	spin_lock_irqsave(&in_printk_lock, flags);
	if (in_printk) {
		spin_unlock_irqrestore(&in_printk_lock, flags);
		return 1;
	}
	in_printk = 1;
	spin_unlock_irqrestore(&in_printk_lock, flags);

	return 0;
}

/* Prints the message via DbgPrintEx and sends it to logging host
 * via syslog UDP if we may sleep. Stores message in ring buffer
 * so we also see messages from raised IRQL once we are being 
 * called with lower IRQL.
 */

int _printk(const char *func, const char *fmt, ...)
{
	char buffer[1024];
	char *s;
	char line[512];	/* Must fit in one UDP packet */
	size_t line_pos;
    
	int level = '1';
	const char *fmt_without_level;
	size_t pos, len, len_ret;
	LARGE_INTEGER time;
	LARGE_INTEGER hr_timer, hr_frequency;
	va_list args;
	NTSTATUS status;
	int hour, min, sec, msec, sec_day;
	static int printks_in_irq_context = 0;
	static int buffer_overflows = 0;
	KIRQL flags;

	buffer[0] = '\0';

	if (KeGetCurrentIrql() < DISPATCH_LEVEL && in_printk == 0) {
			/* Indicate how much might be lost on UDP */
		if (printks_in_irq_context > 0) {
			if (printks_in_irq_context == 1)
				status = RtlStringCbPrintfA(buffer, sizeof(buffer)-1, " [last message was in IRQ context or recursive]\n");
			else
				status = RtlStringCbPrintfA(buffer, sizeof(buffer)-1, " [last %d messages were in IRQ context or recursive]\n", printks_in_irq_context);
			printks_in_irq_context = 0;
		}
	}

	fmt_without_level = fmt;
	if (fmt[0] == '<' && fmt[2] == '>') {
		level = fmt[1];
		fmt_without_level = fmt + 3;
	}

	KeQuerySystemTime(&time);
	sec_day = (time.QuadPart / (ULONG_PTR)1e7) % 86400;
	sec = sec_day % 60;
	min = (sec_day / 60) % 60;
	hour = sec_day / 3600;
	msec = (time.QuadPart / 10000) % (ULONG_PTR)1e3; // 100nsec to msec

	spin_lock_irqsave(&serial_number_lock, flags);
	serial_number++;
	spin_unlock_irqrestore(&serial_number_lock, flags);

	hr_timer = KeQueryPerformanceCounter(&hr_frequency);

	pos = strlen(buffer);
	status = RtlStringCbPrintfA(buffer+pos, sizeof(buffer)-1-pos, "<%c> U%02d:%02d:%02d.%03d (%llu/%llu)|%08.8x(%s) #%llu %s ",
	    level, hour, min, sec, msec,
	    hr_timer.QuadPart, hr_frequency.QuadPart,
	    /* The upper bits of the thread ID are useless; and the lowest 4 as well. */
//	    ((ULONG_PTR)PsGetCurrentThread()) & 0xffffffff,
	    current,
            current->comm,
            serial_number,
	    func
	);
	if (! NT_SUCCESS(status)) {
		if (!no_windows_printk)
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Message not sent, RtlStringCbPrintfA returned error (status = %d).\n", status);

		buffer_overflows++;
		return -EINVAL;
	}

	pos = strlen(buffer);
	va_start(args, fmt);
	status = RtlStringCbVPrintfA(buffer+pos, sizeof(buffer)-1-pos,
		    fmt, args);
/* TODO: va_end ! */
	if (! NT_SUCCESS(status))
	{
		if (!no_windows_printk)
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Message not sent (2), RtlStringCbPrintfA returned error (status = %d).\n", status);
		buffer_overflows++;
		return -EINVAL;
	}
	/* Print messages to debugging facility, use a tool like
	 * DbgViewer to see them.
	 */
	if (!no_windows_printk)
		DbgPrintEx(DPFLTR_IHVDRIVER_ID,
		   (level <= KERN_ERR[0]  ? DPFLTR_ERROR_LEVEL :
		    level >= KERN_INFO[0] ? DPFLTR_INFO_LEVEL  :
		    DPFLTR_WARNING_LEVEL),
		    buffer);

	len_ret = strlen(buffer);

	if (no_memory_printk)
		return len_ret;

		/* Include the trailing \0 */
	len = len_ret+1;

	if (len > RING_BUFFER_SIZE) {
		s = buffer+len-RING_BUFFER_SIZE;
		len = RING_BUFFER_SIZE;
	} else {
		s = buffer;
	}

	spin_lock_irqsave(&ring_buffer_lock, flags);
	if (len + ring_buffer_head > RING_BUFFER_SIZE) {
		memcpy(ring_buffer + ring_buffer_head, s, RING_BUFFER_SIZE-ring_buffer_head);
		len -= RING_BUFFER_SIZE-ring_buffer_head;
		s += RING_BUFFER_SIZE-ring_buffer_head;
		if (ring_buffer_tail > ring_buffer_head)
			ring_buffer_tail = 1;
		ring_buffer_head = 0;
	}
	memcpy(ring_buffer + ring_buffer_head, s, len);
	ring_buffer_head += len;
	if (ring_buffer_tail > ring_buffer_head-len &&
	    ring_buffer_tail <= ring_buffer_head) {
		ring_buffer_tail = ring_buffer_head+1;
		if (ring_buffer_tail == RING_BUFFER_SIZE)
			ring_buffer_tail = 0;
	}
	spin_unlock_irqrestore(&ring_buffer_lock, flags);

	if (no_net_printk)
		return len_ret;

		/* When in a DPC or similar context, we must not 
		 * call waiting functions, like SendTo(). Also
		 * if called recursively (currently in printk)
		 * don't recurse. 
		 */

	if (KeGetCurrentIrql() < DISPATCH_LEVEL && !currently_in_printk()) {
		mutex_lock(&send_mutex);
		if (printk_udp_socket == NULL) {
			open_syslog_socket();
		}

		if (printk_udp_socket != NULL && when_to_start_sending != 0 && jiffies > when_to_start_sending) {
			size_t last_tail = ring_buffer_tail;

			for (line_pos = 0;
			     ring_buffer_tail != ring_buffer_head;
			     ring_buffer_tail = (ring_buffer_tail+1) % RING_BUFFER_SIZE) {
				line[line_pos] = ring_buffer[ring_buffer_tail];
				
				if (line[line_pos] == '\n' || 
				    line[line_pos] == '\0' ||
				    line_pos >= sizeof(line)-2) {
					if (line[line_pos] == '\n')
						line_pos++;
		/* do not send '\0' after '\n', will return send error */
					if (line_pos == 0)
						continue;

					status = SendTo(printk_udp_socket,
							line,
							line_pos,
							(PSOCKADDR)&printk_udp_target);
					if (status < 0) {
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Message not sent, SendTo returned error: %s\n", buffer);

						ring_buffer_tail = last_tail;

						mutex_unlock(&send_mutex);
						return 1;
					} else
						last_tail = ring_buffer_tail;

					line_pos = 0;
				} else 
					line_pos++;
			}
		} else {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Message not sent, no socket: %s\n", buffer);
		}
		mutex_unlock(&send_mutex);

		in_printk = 0;	/* set to 1 by currently_in_printk function */
	} else {
		printks_in_irq_context++;
	}
	return len_ret;
}


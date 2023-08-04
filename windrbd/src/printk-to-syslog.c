/* Enable all warnings throws lots of those warnings: */
#pragma warning(disable: 4061 4062 4255 4388 4668 4820 5032 4711 5045)

#include <wdm.h>
#include "drbd_windows.h"
#include <linux/net.h>
#include <linux/socket.h>

/* This file will be generated by mc.exe during the make
 * process. It contains message IDs for use with event log
 * messages.
 */

#include "windrbd-event-log.h"

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

static int no_event_log_printk = 0;
static int no_windows_printk = 0;
static int no_memory_printk = 0;
static int no_net_printk = 0;

	/* Write messages with this Linux loglevel or less */

	/* The first few messages on booting always go into event log */

#define DEFAULT_EVENT_LOG_LEVEL 5
static int event_log_level_threshold = DEFAULT_EVENT_LOG_LEVEL; /* KERN_NOTICE */

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

	/* Lightweight printk that only prints to memory. For
	 * debugging purposes with windbg and a lot of output.
	 */

static char mem_printk_buffer[64*1024][256];
static spinlock_t mem_printk_lock;
static int mem_printk_slot;
static int mem_printk_serial_number;

int initialize_syslog_printk(void)
{
	spin_lock_init(&ring_buffer_lock);
	spin_lock_init(&in_printk_lock);
	spin_lock_init(&serial_number_lock);
	spin_lock_init(&mem_printk_lock);

		/* don't debug them ... to avoid endless loop */
	ring_buffer_lock.printk_lock = true;
	in_printk_lock.printk_lock = true;
	serial_number_lock.printk_lock = true;

	mutex_init(&send_mutex);
	in_printk = 0;

	return 0;
}

void init_event_log(void)
{
	get_registry_int(L"event_log_level", &event_log_level_threshold, DEFAULT_EVENT_LOG_LEVEL);
	printk("Event log threshold is %d\n", event_log_level_threshold);
}

void set_event_log_threshold(int level)
{
	event_log_level_threshold = level;
	printk("Event log threshold is %d\n", event_log_level_threshold);
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
//			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Invalid syslog IP address: %s\nYou will NOT see any output produced by printk (and pr_err, ...)\n", syslog_ip);
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
//			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Could not create syslog socket for sending log messages to\nsyslog facility (error is %d). You will NOT see any output produced by printk (and pr_err, ...)\n", err);
			return -1;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "socket opened, ring_buffer_head: %lld ring_buffer_tail: %lld\n", ring_buffer_head, ring_buffer_tail);

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


int linux_loglevel_to_windows_severity(int log_level)
{
	switch (log_level) {
		/* see definitions of string markers in drbd_windows.h */
		/* WARNING, SUCCESS and CRITICAL do not work .. */
	case 0:
	case 1:
	case 2:
	case 3: return WINDRBD_ERROR_MESSAGE;
	case 4: return WINDRBD_WARNING_MESSAGE;
	default: return WINDRBD_INFO_MESSAGE;	/* warning notice info  debug, ... */
	}
}

	/* see https://driverentry.com.br/en/blog/?p=348 */

void write_to_eventlog(int log_level, const char *msg)
{
	struct _IO_ERROR_LOG_PACKET *log_packet;
	ANSI_STRING msg_a;
	UNICODE_STRING msg_u;
	size_t total_size, msg_size;	/* all in bytes */
	wchar_t *target;

	RtlInitAnsiString(&msg_a, msg);
	RtlAnsiStringToUnicodeString(&msg_u, &msg_a, TRUE);

		/* msg_u.Length is size in bytes. We need a 0 terminator */

	/* MUST NOT EXCEED ERROR_LOG_MAXIMUM_SIZE (=240) */

	total_size = sizeof(IO_ERROR_LOG_PACKET) + msg_u.Length + sizeof(wchar_t);
	msg_size = msg_u.Length;
	if (total_size > ERROR_LOG_MAXIMUM_SIZE) {
		msg_size -= total_size - ERROR_LOG_MAXIMUM_SIZE;
		total_size = ERROR_LOG_MAXIMUM_SIZE;
	}

    //-f--> It allocates the event entry. We should sum
    //      the used bytes by the DumpData array. That
    //      size should always be a multiple of sizeof(ULONG).

	log_packet = IoAllocateErrorLogEntry(mvolDriverObject, total_size);

		/* can't do anything .. */

	if (log_packet == NULL) {
		RtlFreeUnicodeString(&msg_u);
		return;
	}


    //-f--> It Initializes the whole structure.
// mem_printk("RtlZeroMemory %p %d\n", log_packet, total_size);
	RtlZeroMemory(log_packet, total_size);

    //-f--> Puts up the desired message
	/* see generated .h file */
	log_packet->ErrorCode = linux_loglevel_to_windows_severity(log_level);
	log_packet->StringOffset = sizeof(IO_ERROR_LOG_PACKET);
	log_packet->NumberOfStrings = 1;

// printk("log level is %d error code is %x\n", log_level, log_packet->ErrorCode);

	target = (wchar_t*) (((char*) log_packet) + sizeof(IO_ERROR_LOG_PACKET));

	wcsncpy(target, msg_u.Buffer, msg_size / sizeof(wchar_t));
	target[msg_size / sizeof(wchar_t)] = 0;

	IoWriteErrorLogEntry(log_packet);

	RtlFreeUnicodeString(&msg_u);
}

void split_message_and_write_to_eventlog(int log_level, const char *msg)
{
#define MAX_CHARS ((ERROR_LOG_MAXIMUM_SIZE - sizeof(IO_ERROR_LOG_PACKET) - 1) / sizeof(wchar_t))
	/* so we get messages up to 4500 characters */
#define MAX_CHUNKS 50
#define min(a,b) (((a) < (b)) ? (a) : (b))
	char buf[MAX_CHUNKS][MAX_CHARS];
	size_t len, total_len, num_chars, offset;
	const char *pos;
	int chunk;

	pos = msg;
	num_chars = MAX_CHARS-5;
	chunk = 0;
	while (chunk < MAX_CHUNKS) {
		total_len = strlen(pos);
		if (total_len == 0)
			break;
		offset = 0;
		if (chunk > 0) {
			strncpy(buf[chunk], "... ", strlen("... "));
			offset = strlen("... ");
		}
		len = min(total_len, num_chars);
		strncpy(&buf[chunk][offset], pos, len);
		if (len == num_chars) {
			strncpy(&buf[chunk][num_chars+offset], " ...", strlen(" ..."));
			buf[chunk][num_chars+offset+4] = '\0';
		} else {
			buf[chunk][len+offset] = '\0';
		}
		pos+=len;
		num_chars = MAX_CHARS-9;
		chunk++;
	}
	for (chunk--;chunk>=0;chunk--)
		write_to_eventlog(log_level, buf[chunk]);
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
    
	int level;
	const char *fmt_without_level;
	size_t pos, len, len_ret;
	LARGE_INTEGER time;
	LARGE_INTEGER hr_timer, hr_frequency;
	va_list args;
	NTSTATUS status;
	static int printks_in_irq_context = 0;
	static int buffer_overflows = 0;
	KIRQL flags;
	struct _TIME_FIELDS time_fields;

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
	level = '6';	/* KERN_INFO */
	if (strlen(fmt) > 2) {
		if (fmt[0] == '<' && fmt[2] == '>') {
			level = fmt[1];
			fmt_without_level = fmt + 3;
		}
	}

	KeQuerySystemTime(&time);
	RtlTimeToTimeFields(&time, &time_fields);

	spin_lock_irqsave(&serial_number_lock, flags);
	serial_number++;
	spin_unlock_irqrestore(&serial_number_lock, flags);

	hr_timer = KeQueryPerformanceCounter(&hr_frequency);

	pos = strlen(buffer);
	status = RtlStringCbPrintfA(buffer+pos, sizeof(buffer)-1-pos, "<%c> %02d.%02d.%04d U%02d:%02d:%02d.%03d (%llu/%llu)|%08.8p(%s) #%llu %s ",
	    level,
	    time_fields.Day, time_fields.Month, time_fields.Year,
	    time_fields.Hour, time_fields.Minute, time_fields.Second, time_fields.Milliseconds,
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
		    fmt_without_level, args);
	va_end(args);

	if (! NT_SUCCESS(status))
	{
		if (!no_windows_printk)
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Message not sent (2), RtlStringCbPrintfA returned error (status = %d).\n", status);
		buffer_overflows++;
		return -EINVAL;
	}
		/* We use Rtl string functions which are only available
		 * at PASSIVE_LEVEL (on DISPATCH_LEVEL they may BSOD.
		 */
	if ((KeGetCurrentIrql() == PASSIVE_LEVEL) && 
	    (!no_event_log_printk) && 
	    ((level-'0') >= 0) && ((level-'0') <= event_log_level_threshold))
		split_message_and_write_to_eventlog(level-'0', buffer+pos);
	
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

// mem_printk("printk: %s\n", buffer);
		/* TODO: adjust buffer tail */
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

int _mem_printk(const char *file, int line, const char *func, const char *fmt, ...)
{
	va_list args;
	size_t pos;
	KIRQL flags;

	pos = snprintf(mem_printk_buffer[mem_printk_slot], sizeof(mem_printk_buffer[mem_printk_slot]), "#%d [%s] %s:%d %s(): ", mem_printk_serial_number, current->comm, file, line, func);

	va_start(args, fmt);
	pos += _vsnprintf(&mem_printk_buffer[mem_printk_slot][pos], sizeof(mem_printk_buffer[mem_printk_slot])-pos, fmt, args);
	va_end(args);

	spin_lock_irqsave(&mem_printk_lock, flags);
	mem_printk_serial_number++;
	mem_printk_slot++;
	if (mem_printk_slot >= ARRAY_SIZE(mem_printk_buffer))
		mem_printk_slot = 0;
	spin_unlock_irqrestore(&mem_printk_lock, flags);

	return pos;
}

#include <wdm.h>
#include "drbd_windows.h"
#include <Ntstrsafe.h>
#include <linux/net.h>
#include <linux/socket.h>

// #include <dpfilter.h> // included by wdm.h already

#define RING_BUFFER_SIZE 1048576

char g_syslog_ip[SYSLOG_IP_SIZE];

static struct socket *printk_udp_socket;
static SOCKADDR_IN printk_udp_target;

static char ring_buffer[RING_BUFFER_SIZE];
static size_t ring_buffer_head;
static size_t ring_buffer_tail;
static spinlock_t ring_buffer_lock;
static struct mutex send_mutex;
static int printk_shut_down;

int initialize_syslog_printk(void)
{
	spin_lock_init(&ring_buffer_lock);
	mutex_init(&send_mutex);
	return 0;
}

void shutdown_syslog_printk(void)
{
	if (printk_udp_socket) {
		printk("shutting down printk ...\n");
		sock_release(printk_udp_socket);
		printk_udp_socket = NULL;
	}
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

		printk_udp_target.sin_family = AF_INET;
		printk_udp_target.sin_port = htons(514);

		if (my_inet_aton(g_syslog_ip, &printk_udp_target.sin_addr) < 0) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Invalid syslog IP address: %s\nYou will NOT see any output produced by printk (and pr_err, ...)\n", g_syslog_ip);
			return -1;
		}

		local.sin_family = AF_INET;
		local.sin_addr.s_addr = 0;
		local.sin_port = 0;

		err = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			NULL, NULL, WSK_FLAG_DATAGRAM_SOCKET, &printk_udp_socket);
		if (err == 0) {
			status = printk_udp_socket->ops->bind(printk_udp_socket, (struct sockaddr *) &local, sizeof(local));
			if (!NT_SUCCESS(status)) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to Bind socket, status is %x\n", status);

				sock_release(printk_udp_socket);
				printk_udp_socket = NULL;
			} else {
				char *probe = "Starting printk ...\n";
				err = SendTo(printk_udp_socket,
						probe,
						strlen(probe),
						(PSOCKADDR)&printk_udp_target);

					/* -ENETUNREACH on booting */
				if (err < 0) {
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to SendTo to syslog IP %s, err is %x\n", g_syslog_ip, err);

					sock_release(printk_udp_socket);
					printk_udp_socket = NULL;
				}
			}
		} else {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Could not create syslog socket for sending log messages to\nsyslog facility. You will NOT see any output produced by printk (and pr_err, ...)\n");
			return -1;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "socket opened, ring_buffer_head: %d ring_buffer_tail: %d\n", ring_buffer_head, ring_buffer_tail);
	}
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
	size_t pos, len;
	LARGE_INTEGER time;
	va_list args;
	NTSTATUS status;
	int hour, min, sec, msec, sec_day;
	static int printks_in_irq_context = 0;
	static int buffer_overflows = 0;

	int is_bind = (strcmp(func, "Bind") == 0);
	int is_sendto = (strcmp(func, "SendTo") == 0);

	if (is_bind || is_sendto) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Message not sent, printk called from Bind() or SendTo() (which we need interally).\n");
	/* TODO: return?? */
	}

	buffer[0] = '\0';

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
		printks_in_irq_context++;
	} else {
	/* Indicate how much might be lost on UDP */
		if (printks_in_irq_context) {
			if (printks_in_irq_context == 1)
				status = RtlStringCbPrintfA(buffer, sizeof(buffer)-1, " [last message was in IRQ context]\n");
			else
				status = RtlStringCbPrintfA(buffer, sizeof(buffer)-1, " [last %d messages were in IRQ context]\n", printks_in_irq_context);
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

	pos = strlen(buffer);
	status = RtlStringCbPrintfA(buffer+pos, sizeof(buffer)-1-pos, "<%c> U%02d:%02d:%02d.%03d|%08.8x(%s) %s ",
	    level, hour, min, sec, msec,
	    /* The upper bits of the thread ID are useless; and the lowest 4 as well. */
//	    ((ULONG_PTR)PsGetCurrentThread()) & 0xffffffff,
	    current,
            current->comm,
	    func
	);
	if (! NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Message not sent, RtlStringCbPrintfA returned error (status = %d).\n", status);
		buffer_overflows++;
		return -EINVAL;
	}

	pos = strlen(buffer);
	va_start(args, fmt);
	status = RtlStringCbVPrintfA(buffer+pos, sizeof(buffer)-1-pos,
		    fmt, args);
	if (! NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Message not sent (2), RtlStringCbPrintfA returned error (status = %d).\n", status);
		buffer_overflows++;
		return -EINVAL;
	}

	/* Always print messages to debugging facility, use a tool like
	 * DbgViewer to see them.
	 */
	DbgPrintEx(DPFLTR_IHVDRIVER_ID,
		   (level <= KERN_ERR[0]  ? DPFLTR_ERROR_LEVEL :
		    level >= KERN_INFO[0] ? DPFLTR_INFO_LEVEL  :
		    DPFLTR_WARNING_LEVEL),
		    buffer);

		/* Include the trailing \0 */
	len = strlen(buffer)+1;

	if (len > RING_BUFFER_SIZE) {
		s = buffer+len-RING_BUFFER_SIZE;
		len = RING_BUFFER_SIZE;
	} else {
		s = buffer;
	}

	spin_lock_irq(&ring_buffer_lock);
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
	spin_unlock_irq(&ring_buffer_lock);

		/* When in a DPC or similar context, we must not 
		 * call waiting functions, like SendTo(). 
		 */

	if (KeGetCurrentIrql() < DISPATCH_LEVEL) {
		mutex_lock(&send_mutex);
		if (printk_udp_socket == NULL) {
			open_syslog_socket();
		}

		if (printk_udp_socket != NULL) {
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
	}
	return 1;	/* TODO: strlen(buffer) */
}


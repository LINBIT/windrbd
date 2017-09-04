#include <wdm.h>
#include <wsk2.h>
#include <Ntstrsafe.h>
// #include <dpfilter.h> // included by wdm.h already

#define RING_BUFFER_SIZE 4096

static PWSK_SOCKET printk_udp_socket = NULL;
static SOCKADDR_IN printk_udp_target;

static char ring_buffer[RING_BUFFER_SIZE];
size_t ring_buffer_head;
size_t ring_buffer_tail;

char my_host_name[256];

int initialize_syslog_printk(void)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Initializing syslog logging\n");
	if (!printk_udp_socket) {
		SOCKADDR_IN local;

		printk_udp_target.sin_family = AF_INET;
			/* Same as htons(514) ;) */
		printk_udp_target.sin_port = 514;

		/* TODO: This doesn't work on our setup. I am pretty sure
		 * that it was never supposed to work. */
		/* printk_udp_target.sin_addr.s_addr = 0xffffffff; */

		/* TODO: this is a hardcoded IP address in network byte
		 * order. You need to put the IPv4 address of a Linux
		 * box running rsyslogd with remote logging on UDP
		 * enabled here. To enable UDP logging in rsyslogd
		 * put (or uncomment) following lines into /etc/rsyslog.conf:
module(load="imudp")
input(type="imudp" port="514")
		 * then do a 
bash$ sudo service syslog restart
		 * . */

		printk_udp_target.sin_addr.s_addr = 0x6738a8c0;

		local.sin_family = AF_INET;
		local.sin_addr.s_addr = 0;
		local.sin_port = 0;

		printk_udp_socket = CreateSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			NULL, NULL, WSK_FLAG_DATAGRAM_SOCKET);
		if (printk_udp_socket) {
			Bind(printk_udp_socket, (SOCKADDR *)&local);
		} else {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Could not create syslog socket for sending log messages to\nsyslog facility. You will NOT see any output produced by printk (and pr_err, ...)\n");
			return -1;
		}
	}
	return 0;
}

/* For now, we only push messages via a UDP socket.
 * Later on, we can also */
int _printk(const char *func, const char *fmt, ...)
{
	char buffer[1024];
	char *s;
	char line[512];	/* Must fit in one UDP packet */
	size_t line_pos;
    
    int level = '1';
    const char *fmt_without_level;
    ULONG pos, len;
    LARGE_INTEGER time;
    va_list args;
    NTSTATUS status;
    int hour, min, sec, msec, sec_day;
    static int printks_in_irq_context = 0;

    fmt_without_level = fmt;
    if (fmt[0] == '<' && fmt[2] == '>') {
	level = fmt[1];
	fmt_without_level = fmt + 3;
    }

    if (!my_host_name) {
	pos = sizeof(my_host_name);
	//	GetComputerName(my_host_name, &pos); // TODO FIXME
	strcpy(my_host_name, "WIN");
    }

    KeQuerySystemTime(&time);
    sec_day = (time.QuadPart / (ULONG_PTR)1e7) % 86400;
    sec = sec_day % 60;
    min = (sec_day / 60) % 60;
    hour = sec_day / 3600;
    msec = (time.QuadPart / 10000) % (ULONG_PTR)1e3; // 100nsec to msec
    status = RtlStringCbPrintfA(buffer, sizeof(buffer)-1, "<%c> U%02d:%02d:%02d.%03d|%08.8x %s ",
	    level, hour, min, sec, msec,
	    /* The upper bits of the thread ID are useless; and the lowest 4 as well. */
	    ((ULONG_PTR)PsGetCurrentThread()) & 0xffffffff,
	    func // my_host_name
	    );
    if (! NT_SUCCESS(status)) {
//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Message not sent, RtlStringCbPrintfA returned error (status = %d).\n", status);
	return -EINVAL;
    }

    pos = (ULONG)strlen(buffer);
    va_start(args, fmt);
    status = RtlStringCbVPrintfA(buffer + pos, sizeof(buffer)-1-pos,
	    fmt, args);
    if (! NT_SUCCESS(status))
    {
//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Message not sent (2), RtlStringCbPrintfA returned error (status = %d).\n", status);
	return -EINVAL;
    }

    len = (ULONG)strlen(buffer);

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
	/* When in a DPC or similar context, we must not call waiting functions. */
		printks_in_irq_context++;
	} else {
	/* Indicate how much might be lost on UDP */
		if (printks_in_irq_context) {
		/* TODO: This should go before the new message .. */
			if (printks_in_irq_context == 1)
				status = RtlStringCbPrintfA(buffer, sizeof(buffer)-1 - len, " [last message was in IRQ context]\n");
			else
				status = RtlStringCbPrintfA(buffer, sizeof(buffer)-1 - len, " [last %d messages were in IRQ context]\n", printks_in_irq_context);
			printks_in_irq_context = 0;
			len = (ULONG)strlen(buffer);
		}
	}

/* TODO: locking. use a spin lock */

	/* Always print messages to debugging facility, use a tool like
	 * DbgViewer to see them.
	 */
	DbgPrintEx(DPFLTR_IHVDRIVER_ID,
		   (level <= KERN_ERR[0]  ? DPFLTR_ERROR_LEVEL :
		    level >= KERN_INFO[0] ? DPFLTR_INFO_LEVEL  :
		    DPFLTR_WARNING_LEVEL),
		    buffer);

	if (len > RING_BUFFER_SIZE) {
		s = buffer+len-RING_BUFFER_SIZE;
		len = RING_BUFFER_SIZE;
	} else {
		s = buffer;
	}

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

	if (KeGetCurrentIrql() < DISPATCH_LEVEL) {
		if (printk_udp_socket == NULL) {
			initialize_syslog_printk();
		}

		if (printk_udp_socket) {
			for (line_pos = 0;
			     ring_buffer_tail != ring_buffer_head;
			     ring_buffer_tail = (ring_buffer_tail+1) % RING_BUFFER_SIZE) {
				line[line_pos] = ring_buffer[ring_buffer_tail];
				
				if (line[line_pos] == '\n' || 
				    line[line_pos] == '\0' ||
				    line_pos >= sizeof(line)-2) {
					if (line[line_pos] == '\n')
						line_pos++;
					status = SendTo(printk_udp_socket, 
							line,
							line_pos,
							(PSOCKADDR)&printk_udp_target);
					if (status < 0) {
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Message not sent, SendTo returned error: %s\n", buffer);
					}
					line_pos = 0;
				} else 
					line_pos++;
			}
		} else {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Message not sent, no socket: %s\n", buffer);
		}
	}
	return 1;	/* TODO: strlen(buffer) */
}


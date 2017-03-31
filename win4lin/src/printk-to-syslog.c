#include <wdm.h>
#include <wsk2.h>
#include <Ntstrsafe.h>
// #include <dpfilter.h> // included by wdm.h already


static PWSK_SOCKET printk_udp_socket = NULL;
static SOCKADDR_IN printk_udp_target;

char my_host_name[256];


/* For now, we only push messages via a UDP socket.
 * Later on, we can also */
int _printk(const char *func, const char *fmt, ...)
{
    char buffer[1024];
    int level = '1';
    const char *fmt_without_level;
    ULONG pos, len;
    LARGE_INTEGER time;
    va_list args;
    NTSTATUS status;
    int hour, min, sec, msec, sec_day;


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
    if (! NT_SUCCESS(status))
	return -EINVAL;

    pos = (ULONG)strlen(buffer);
    va_start(args, fmt);
    status = RtlStringCbVPrintfA(buffer + pos, sizeof(buffer)-1-pos,
	    fmt, args);
    if (! NT_SUCCESS(status))
	return -EINVAL;

    len = (ULONG)strlen(buffer);

    /* While this initialization might be racy normally, it's already done from
       DriverEntry, where only a single thread is active. */
    if (!printk_udp_socket) {
	SOCKADDR_IN local;

	printk_udp_target.sin_family = AF_INET;
	printk_udp_target.sin_port = 514;
	printk_udp_target.sin_addr.s_addr = 0xffffffff;

	local.sin_family = AF_INET;
	local.sin_addr.s_addr = 0;
	local.sin_port = 0;

	printk_udp_socket = CreateSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
		NULL, NULL, WSK_FLAG_DATAGRAM_SOCKET);
	Bind(printk_udp_socket, (SOCKADDR *)&local);
    }

    DoTraceMessage(TRCINFO, buffer);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
	    (level <= KERN_ERR[0]  ? DPFLTR_ERROR_LEVEL :
	     level >= KERN_INFO[0] ? DPFLTR_INFO_LEVEL  :
	     DPFLTR_WARNING_LEVEL),
	    buffer);

    if (printk_udp_socket) {
	status = SendTo(printk_udp_socket, buffer, len,
		(PSOCKADDR)&printk_udp_target);
    }
#if 0
    WriteEventLogEntryData(msgids[level_index], 0, 0, 1, L"%S", buf);

    if (bEventLog) {
	save_to_system_event(buf, length, level_index);
    }

    if (bDbgLog)
	DbgPrintEx(FLTR_COMPONENT, printLevel, buf);
#endif
    return 1;
}


#include <wdm.h>
#include "drbd_windows.h"

static LARGE_INTEGER hr_timer;

static const char *from_file;
static int from_line;
static const char *from_func;

void tik_debug(const char *file, int line, const char *func)
{
	hr_timer = KeQueryPerformanceCounter(NULL);

	from_file = file;
	from_line = line;
	from_func = func;
}

void tok_debug(const char *file, int line, const char *func)
{
	LARGE_INTEGER hr_timer2, hr_freq;

	hr_timer2 = KeQueryPerformanceCounter(&hr_freq);
	printk("%s:%d (%s) until %s:%d (%s) took %llu ticks (1/%llu th seconds)\n", from_file, from_line, from_func, file, line, func, hr_timer2.QuadPart - hr_timer.QuadPart, hr_freq.QuadPart);
}

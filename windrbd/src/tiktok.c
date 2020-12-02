#include <wdm.h>
#include "drbd_windows.h"

#define MAX_TIKTOKS 10

struct tiktok {
	LARGE_INTEGER hr_timer;

	const char *from_file;
	int from_line;
	const char *from_func;
};

static struct tiktok tiktoks[MAX_TIKTOKS];

void tik_debug(int n, const char *file, int line, const char *func)
{
	if (n < 0 || n >= MAX_TIKTOKS) {
		printk("Warning: n (%d) out of range\n", n);
		return;
	}
	tiktoks[n].hr_timer = KeQueryPerformanceCounter(NULL);

	tiktoks[n].from_file = file;
	tiktoks[n].from_line = line;
	tiktoks[n].from_func = func;
}

void tok_debug(int n, const char *file, int line, const char *func)
{
	LARGE_INTEGER hr_timer2, hr_freq;

	if (n < 0 || n >= MAX_TIKTOKS) {
		printk("Warning: n (%d) out of range\n", n);
		return;
	}

	hr_timer2 = KeQueryPerformanceCounter(&hr_freq);
	printk("TIKTOK channel %d %s:%d (%s) until %s:%d (%s) took %llu ticks (1/%llu th seconds)\n", n, tiktoks[n].from_file, tiktoks[n].from_line, tiktoks[n].from_func, file, line, func, hr_timer2.QuadPart - tiktoks[n].hr_timer.QuadPart, hr_freq.QuadPart);
}

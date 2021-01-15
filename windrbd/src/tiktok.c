#include <wdm.h>
#include "drbd_windows.h"

#define MAX_TIKTOKS 50

struct tiktok {
	int n;
	LARGE_INTEGER hr_timer;
	LARGE_INTEGER start_timer;
	LARGE_INTEGER timer_sum;

	const char *from_file;
	int from_line;
	const char *from_func;
	const char *desc;
};

static struct tiktok tiktoks[MAX_TIKTOKS];

void tik_debug(int n, const char *desc, const char *file, int line, const char *func)
{
	if (n < 0 || n >= MAX_TIKTOKS) {
		printk("Warning: n (%d) out of range\n", n);
		return;
	}
	tiktoks[n].hr_timer = KeQueryPerformanceCounter(NULL);

	tiktoks[n].desc = desc;
	tiktoks[n].from_file = file;
	tiktoks[n].from_line = line;
	tiktoks[n].from_func = func;

	if (tiktoks[n].n == 0)
		tiktoks[n].start_timer = tiktoks[n].hr_timer;
	tiktoks[n].n++;

	printk("TIKTOK channel %d \"%s\" (#%d) started at %s:%d (%s) 0 ticks\n", n, tiktoks[n].desc, tiktoks[n].n, file, line, func);
}

void tok_debug(int n, const char *file, int line, const char *func)
{
	LARGE_INTEGER hr_timer2, hr_freq;
	LARGE_INTEGER total_runtime;
	float percentage;

	if (n < 0 || n >= MAX_TIKTOKS) {
		printk("Warning: n (%d) out of range\n", n);
		return;
	}

	hr_timer2 = KeQueryPerformanceCounter(&hr_freq);
	tiktoks[n].timer_sum.QuadPart += hr_timer2.QuadPart;
	total_runtime.QuadPart = hr_timer2.QuadPart - tiktoks[n].start_timer.QuadPart;

	percentage = 100*tiktoks[n].timer_sum.QuadPart/total_runtime.QuadPart;

	printk("TIKTOK channel %d \"%s\" (#%d) %s:%d (%s) until %s:%d (%s) took %llu ticks (1/%llu th seconds)\n", n, tiktoks[n].desc, tiktoks[n].n, tiktoks[n].from_file, tiktoks[n].from_line, tiktoks[n].from_func, file, line, func, hr_timer2.QuadPart - tiktoks[n].hr_timer.QuadPart, hr_freq.QuadPart);
	printk("TIKTOK channel %d \"%s\" (#%d) %s:%d (%s) percentage is %.02f total runtime is %llu ticks time spent in region %llu ticks.\n", n, tiktoks[n].desc, tiktoks[n].n, file, line, func, percentage, total_runtime.QuadPart, tiktoks[n].timer_sum.QuadPart);
}

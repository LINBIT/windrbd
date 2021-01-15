#include <wdm.h>
#include "drbd_windows.h"

#define MAX_TIKTOKS 50

enum op { OP_NONE, OP_TIK, OP_TOK };

struct tiktok {
	int n;
	enum op op;
	LARGE_INTEGER hr_timer;
	LARGE_INTEGER start_timer;
	LARGE_INTEGER timer_sum;

	const char *from_file;
	int from_line;
	const char *from_func;
	const char *desc;
};

static struct tiktok tiktoks[MAX_TIKTOKS] = { 0 };

void tik_debug(int n, const char *desc, const char *file, int line, const char *func)
{
	if (n < 0 || n >= MAX_TIKTOKS) {
		printk("TIKTOK Warning: n (%d) out of range\n", n);
		return;
	}
	if (tiktoks[n].op == OP_TIK)
		printk("TIKTOK Warning: tiktok sequence mismatch is %d expected something other than %d\n", tiktoks[n].op, OP_TIK);
	tiktoks[n].op = OP_TIK;

	tiktoks[n].hr_timer = KeQueryPerformanceCounter(NULL);

	tiktoks[n].desc = desc;
	tiktoks[n].from_file = file;
	tiktoks[n].from_line = line;
	tiktoks[n].from_func = func;

	if (tiktoks[n].n == 0) {
		tiktoks[n].start_timer = tiktoks[n].hr_timer;
		tiktoks[n].timer_sum.QuadPart = 0ULL;
	}
	tiktoks[n].n++;

	printk("TIKTOK channel %d \"%s\" (#%d) started at %s:%d (%s) current ticks is %llu\n", n, tiktoks[n].desc, tiktoks[n].n, file, line, func, tiktoks[n].hr_timer.QuadPart);
}

void tok_debug(int n, const char *file, int line, const char *func)
{
	LARGE_INTEGER hr_timer2, hr_freq;
	LARGE_INTEGER total_runtime, this_runtime;
	LARGE_INTEGER percentage;

	if (n < 0 || n >= MAX_TIKTOKS) {
		printk("TIKTOK Warning: n (%d) out of range\n", n);
		return;
	}
	if (tiktoks[n].op != OP_TIK)
		printk("TIKTOK Warning: tiktok sequence mismatch is %d expected %d\n", tiktoks[n].op, OP_TIK);
	tiktoks[n].op = OP_TOK;


	hr_timer2 = KeQueryPerformanceCounter(&hr_freq);
	this_runtime.QuadPart = hr_timer2.QuadPart - tiktoks[n].hr_timer.QuadPart;
	tiktoks[n].timer_sum.QuadPart += this_runtime.QuadPart;
	total_runtime.QuadPart = hr_timer2.QuadPart - tiktoks[n].start_timer.QuadPart;

	percentage.QuadPart = 10000*tiktoks[n].timer_sum.QuadPart/total_runtime.QuadPart;

	printk("TIKTOK channel %d \"%s\" (#%d) %s:%d (%s) until %s:%d (%s) took %llu ticks (1/%llu th seconds), started at %llu\n", n, tiktoks[n].desc, tiktoks[n].n, tiktoks[n].from_file, tiktoks[n].from_line, tiktoks[n].from_func, file, line, func, this_runtime.QuadPart, hr_freq.QuadPart, tiktoks[n].hr_timer.QuadPart);
	printk("TIKTOK channel %d \"%s\" (#%d) %s:%d (%s) percentage is %llu.%.02d total runtime is %llu ticks total time spent in region %llu ticks.\n", n, tiktoks[n].desc, tiktoks[n].n, file, line, func, percentage.QuadPart/100, percentage.QuadPart%100, total_runtime.QuadPart, tiktoks[n].timer_sum.QuadPart);
}

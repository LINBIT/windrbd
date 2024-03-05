#ifndef PRINTK_H
#define PRINTK_H

#include <linux/kern_levels.h>

#define printk(args...)   \
    _printk(__FUNCTION__, args)

#ifdef DEBUG
#define dbg(args...)   \
    _printk(__FUNCTION__, args)
#else
#define dbg(args...) do { } while (0)
#endif

extern int _mem_printk(const char *file, int line, const char *func, const char *fmt, ...);

#define mem_printk(args...)   \
    _mem_printk(__FILE__, __LINE__, __FUNCTION__, args)

extern int debug_printks_enabled;

#define cond_printk(args...) \
	if (debug_printks_enabled) \
		_printk(__FUNCTION__, args)

extern int initialize_syslog_printk(void);
extern void shutdown_syslog_printk(void);
extern void set_syslog_ip(const char *ip);

extern int _printk(const char * func, const char * format, ...);
extern void printk_reprint(size_t bytes);

#endif

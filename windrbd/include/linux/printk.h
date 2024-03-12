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

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

/**
 * pr_err - Print an error-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_ERR loglevel. It uses pr_fmt() to
 * generate the format string.
 */
#define pr_err(fmt, ...) \
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)

/**
 * pr_warn - Print a warning-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_WARNING loglevel. It uses pr_fmt()
 * to generate the format string.
 */
#define pr_warn(fmt, ...) \
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)

/**
 * pr_info - Print an info-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_INFO loglevel. It uses pr_fmt() to
 * generate the format string.
 */
#define pr_info(fmt, ...) \
	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)

#endif

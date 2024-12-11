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

extern int _printk(const char * func, const char * format, ...);

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

/**
 * pr_alert - Print an alert-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_ALERT loglevel. It uses pr_fmt() to
 * generate the format string.
 */
#define pr_alert(fmt, ...) \
	printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)

/**
 * pr_crit - Print a critical-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_CRIT loglevel. It uses pr_fmt() to
 * generate the format string.
 */
#define pr_crit(fmt, ...) \
	printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)

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
 * pr_notice - Print a notice-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_NOTICE loglevel. It uses pr_fmt() to
 * generate the format string.
 */
#define pr_notice(fmt, ...) \
	printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)

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

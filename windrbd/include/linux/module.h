#ifndef LINUX_MODULE_H
#define LINUX_MODULE_H

#include <linux/types.h>	/* for bool */
#include <linux/moduleparam.h>
#include <linux/export.h>

#define MODULE_AUTHOR(unused, ...)
#define MODULE_DESCRIPTION(unused, ...)
#define MODULE_VERSION(unused)
#define MODULE_LICENSE(unused)
#define MODULE_ALIAS_BLOCKDEV_MAJOR(unused)
#define MODULE_SOFTDEP(_softdep)

struct module {
	const char *version;
	atomic_t refcnt;
};

extern struct module windrbd_module;

/* Note: under Windows there is no seperate transport module,
 * the module code (sorry, TCP/IP only) is compiled into the
 * windrbd driver.
 */

#define THIS_MODULE (&windrbd_module)

extern bool try_module_get(struct module *module);
extern void module_put(struct module *module);

	/* DRBD and DRBD transport TCP are currently the only modules,
	 * so call them manually from DriverInit().
	 */

extern int (* drbd_init_fn)(void);
extern int (* dtt_initialize_fn)(void);

extern void (* drbd_cleanup_fn)(void);
extern void (* dtt_cleanup_fn)(void);

#define module_init(fn)	\
	int (* fn ## _fn)(void) = fn;
#define module_exit(fn)	\
	void (* fn ## _fn)(void) = fn;

#endif

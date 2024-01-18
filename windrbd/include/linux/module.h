#ifndef LINUX_MODULE_H
#define LINUX_MODULE_H

#include <linux/types.h>	/* for bool */

#define MODULE_AUTHOR(unused, ...)
#define MODULE_DESCRIPTION(unused, ...)
#define MODULE_VERSION(unused)
#define MODULE_LICENSE(unused)
#define MODULE_PARM_DESC(unused, ...)
#define MODULE_ALIAS_BLOCKDEV_MAJOR(unused)
#define MODULE_PARM_DESC(unused, ...)

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

#endif

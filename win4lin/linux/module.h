#ifndef LINUX_MODULE_H
#define LINUX_MODULE_H

#include <linux/types.h>	/* for bool */
#include "drbd_windows.h"	/* for atomic_t */

struct module {
        char version[1];
//	struct kref kref;
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

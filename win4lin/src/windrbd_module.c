#include <linux/module.h>
#include <disp.h>	/* for root device object */
#include <drbd_windows.h>	/* for printk */

struct module windrbd_module;

bool try_module_get(struct module *module)
{
	if (module != &windrbd_module)
		printk("try_module_get for something besides the windrbd_module.\n");

	ObReferenceObject(mvolRootDeviceObject);

	return true;
}

void module_put(struct module *module)
{
	if (module != &windrbd_module)
		printk("module_put for something besides the windrbd_module.\n");

	ObDereferenceObject(mvolRootDeviceObject);
}



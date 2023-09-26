#include <linux/module.h>
#include <disp.h>	/* for root device object */
#include <drbd_windows.h>	/* for printk */
#include "windrbd_version.h"

	/* undef this to disable driver unload */
#define DRIVER_UNLOAD 1

struct module windrbd_module = {
	.version = WINDRBD_VERSION,
	.refcnt = 0
};

bool try_module_get(struct module *module)
{
	NTSTATUS status;

	if (module != &windrbd_module) {
		printk("try_module_get for something besides the windrbd_module.\n");
		return true;
	}

	if (atomic_inc_return(&module->refcnt) == 1) {
		printk("Driver in use, cannot unlock it now.\n");
	}
	return true;
}

void module_put(struct module *module)
{
	if (module != &windrbd_module) {
		printk("module_put for something besides the windrbd_module.\n");
		return;
	}

	if (atomic_dec_return(&module->refcnt) == 0) {
		printk("Unlocking module by setting AddDevice to NULL should work now (use windrbd unlock-driver to unlock)\n");
	}
}

int set_driver_locked_state(int state)
{
	if (state == 0) {
		if (atomic_read(&windrbd_module.refcnt) > 0) {
			printk("Request for unlocking driver but module is in use (%d).\n", atomic_read(&windrbd_module.refcnt));
			return -EBUSY;
		} else {
			printk("Unlocking module by setting AddDevice to NULL, sc stop windrbd should work now.\n");
			mvolDriverObject->DriverExtension->AddDevice = NULL;
		}
	} else {
		printk("Locking module by setting AddDevice to %p, sc stop windrbd should not work (do a drbdadm down all first)\n", mvolAddDevice);
		mvolDriverObject->DriverExtension->AddDevice = mvolAddDevice;
	}
	return 0;
}

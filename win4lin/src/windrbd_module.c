#include <linux/module.h>
#include <disp.h>	/* for root device object */
#include <drbd_windows.h>	/* for printk */

struct module windrbd_module;

bool try_module_get(struct module *module)
{
	NTSTATUS status;

	if (module != &windrbd_module)
		printk("try_module_get for something besides the windrbd_module.\n");

printk("Referencing root device object (%p)\n", mvolRootDeviceObject);
	status = ObReferenceObjectByPointer(mvolRootDeviceObject, THREAD_ALL_ACCESS, NULL, KernelMode);
printk("status is %x\n", status);

printk("Referencing driver object (%p)\n", mvolDriverObject);
	status = ObReferenceObjectByPointer(mvolDriverObject, THREAD_ALL_ACCESS, NULL, KernelMode);
printk("status is %x\n", status);

	HANDLE f;
	IO_STATUS_BLOCK iostat;
	OBJECT_ATTRIBUTES attr;
	UNICODE_STRING rootdev;

        RtlInitUnicodeString(&rootdev, L"\\DosDevices\\" WINDRBD_ROOT_DEVICE_NAME);
        InitializeObjectAttributes(&attr, &rootdev, OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwOpenFile(&f, GENERIC_READ, &attr, &iostat, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);

printk("ZwOpenFile status is %x\n", status);

	/* leave it open */

	return true;
}

void module_put(struct module *module)
{
	if (module != &windrbd_module)
		printk("module_put for something besides the windrbd_module.\n");

printk("Dereferencing root device object (%p)\n", mvolRootDeviceObject);
	ObDereferenceObject(mvolRootDeviceObject);
printk("Dereferencing driver object (%p)\n", mvolDriverObject);
	ObDereferenceObject(mvolDriverObject);
}



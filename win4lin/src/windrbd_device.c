#include <wdm.h>
#include <ntddk.h>
#include <ntdddisk.h>

#include "drbd_windows.h"
#include "windrbd_device.h"

static NTSTATUS windrbd_not_implemented(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	
	printk(KERN_DEBUG "device: %p irp: %p s: %p s->MajorFunction: %x s->MinorFunction: %x s->Parameters.DeviceIoControl.IoControlCode: %x\n", device, irp, s, s->MajorFunction, s->MinorFunction, s->Parameters.DeviceIoControl.IoControlCode);
	irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;

//	return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS windrbd_device_control(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);

	printk(KERN_DEBUG "IoCtl: device: %p irp: %p s: %p s->MajorFunction: %x s->MinorFunction: %x s->Parameters.DeviceIoControl.IoControlCode: %x\n", device, irp, s, s->MajorFunction, s->MinorFunction, s->Parameters.DeviceIoControl.IoControlCode);
	switch (s->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_DISK_GET_DRIVE_GEOMETRY:
		printk(KERN_DEBUG "get drive geometry.\n");
		break;
	default: ;
	}

	irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
}

void windrbd_set_major_functions(struct _DRIVER_OBJECT *obj)
{
	int i;

	for (i=0; i<IRP_MJ_MAXIMUM_FUNCTION; i++)
		obj->MajorFunction[i] = windrbd_not_implemented;

	obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = windrbd_device_control;

}

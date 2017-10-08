#include <wdm.h>
#include <ntddk.h>

#include "drbd_windows.h"
#include "windrbd_device.h"

static NTSTATUS windrbd_not_implemented(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	return STATUS_NOT_IMPLEMENTED;
}

void windrbd_set_major_functions(struct _DRIVER_OBJECT *obj)
{
	int i;

	for (i=0; i<IRP_MJ_MAXIMUM_FUNCTION; i++)
		obj->MajorFunction[i] = windrbd_not_implemented;
}

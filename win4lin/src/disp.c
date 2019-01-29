/*
        Copyright(C) 2017-2018, Johannes Thoma <johannes@johannesthoma.com>
        Copyright(C) 2017-2018, LINBIT HA-Solutions GmbH  <office@linbit.com>
	Copyright(C) 2007-2016, ManTechnology Co., LTD.
	Copyright(C) 2007-2016, wdrbd@mantech.co.kr

	Windows DRBD is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2, or (at your option)
	any later version.

	Windows DRBD is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Windows DRBD; see the file COPYING. If not, write to
	the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <wdm.h>
#include <wdmsec.h>
#include <ntstrsafe.h>
#include <ntddk.h>
#include "drbd_windows.h"
#include "windrbd_device.h"
#include "drbd_wingenl.h"	
#include "disp.h"
#include "windrbd_ioctl.h"

#include "drbd_int.h"
#include "drbd_wrappers.h"

	/* TODO: find some headers where this fits. */
void drbd_cleanup(void);
void idr_shutdown(void);

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD mvolUnload;
DRIVER_ADD_DEVICE mvolAddDevice;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS            		status;
	PDEVICE_OBJECT      		deviceObject;
	UNICODE_STRING      		nameUnicode, linkUnicode;
	int ret;

	/* Init windrbd primitives (spinlocks, ...) before doing anything
	 * else .. needed for printk.
	 */
	init_windrbd();

	/* Then, initialize the printk subsystem (ring buffer). Logging
	 * can be seen only later when booting is finished (depending on
	 * OS), on most OSes this is when the first printk on behalf of
	 * a drbdadm command happens.
	 */
	initialize_syslog_printk();

	printk(KERN_INFO "Windrbd Driver Loading (compiled " __DATE__ " " __TIME__ ") ...\n");

#ifdef KMALLOC_DEBUG
	init_kmalloc_debug();
	printk("kmalloc_debug initialized.\n");
#endif
	/* Next, the threads subsystem (so DRBD can create threads) */
	init_windrbd_threads();

	/* TODO: This will go away soon */
	initRegistry(RegistryPath);

	RtlInitUnicodeString(&nameUnicode, L"\\Device\\" WINDRBD_ROOT_DEVICE_NAME);
	status = IoCreateDeviceSecure(DriverObject, sizeof(ROOT_EXTENSION),
			 &nameUnicode, FILE_DEVICE_UNKNOWN,
			FILE_DEVICE_SECURE_OPEN, FALSE,
			&SDDL_DEVOBJ_SYS_ALL_ADM_ALL, NULL, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		WDRBD_ERROR("Can't create root, err=%x\n", status);
		return status;
	}

	RtlInitUnicodeString(&linkUnicode, L"\\DosDevices\\" WINDRBD_ROOT_DEVICE_NAME);
	status = IoCreateSymbolicLink(&linkUnicode, &nameUnicode);
	if (!NT_SUCCESS(status))
	{
		WDRBD_ERROR("cannot create symbolic link, err=%x\n", status);
		IoDeleteDevice(deviceObject);
		return status;
	}

	mvolDriverObject = DriverObject;
	mvolRootDeviceObject = deviceObject;

	windrbd_set_major_functions(DriverObject);
/* Remove this line to make driver removable (driver removing currently
 * BSOD's sometimes):
 */
//	DriverObject->DriverExtension->AddDevice = mvolAddDevice;
	DriverObject->DriverUnload = mvolUnload;

	downup_rwlock_init(&transport_classes_lock); //init spinlock for transport 
	mutex_init(&notification_mutex);
		/* TODO: this is unneccessary */
	KeInitializeSpinLock(&transport_classes_lock);

	dtt_initialize();

	system_wq = alloc_ordered_workqueue("system workqueue", 0);
	if (system_wq == NULL) {
		pr_err("Could not allocate system work queue\n");
		return STATUS_NO_MEMORY;
	}

	ret = drbd_init();
	if (ret != 0) {
		printk(KERN_ERR "cannot init drbd, error is %d", ret);
		IoDeleteDevice(deviceObject);

		return STATUS_TIMEOUT;
	}

	windrbd_init_netlink();
	windrbd_init_usermode_helper();
	windrbd_init_wsk();

	printk(KERN_INFO "Windrbd Driver loaded.\n");

	return STATUS_SUCCESS;
}

void mvolUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNICODE_STRING linkUnicode;
	NTSTATUS status;

	printk("Unloading windrbd driver.\n");

	drbd_cleanup();
	printk("DRBD cleaned up.\n");

	dtt_cleanup();
	printk("TCP transport layer cleaned up.\n");

	destroy_workqueue(system_wq);
	printk("System workqueue destroyed.\n");

	RtlInitUnicodeString(&linkUnicode, L"\\DosDevices\\" WINDRBD_ROOT_DEVICE_NAME);
	status = IoDeleteSymbolicLink(&linkUnicode);
	if (!NT_SUCCESS(status))
		printk("Cannot delete root device link, status is %x.\n", status);

        IoDeleteDevice(mvolRootDeviceObject);

	printk("Root device deleted.\n");

	idr_shutdown();
	printk("IDR layer shut down.\n");

	windrbd_shutdown_netlink();
	printk("Netlink layer shut down.\n");

	printk("WinSocket layer shut down.\n");
#ifdef KMALLOC_DEBUG
	shutdown_kmalloc_debug();
	printk("kmalloc_debug shut down, there should be no memory leaks now.\n");
#endif
	shutdown_syslog_printk();
	windrbd_shutdown_wsk();
}

NTSTATUS
mvolAddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT PhysicalDeviceObject)
{
	printk(KERN_INFO "AddDevice NOT DONE\n");
	return STATUS_NO_SUCH_DEVICE;
}

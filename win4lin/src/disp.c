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
#ifdef NTDDI_VERSION
#undef NTDDI_VERSION
#endif
#define NTDDI_VERSION 0x06010000

#include <ntddk.h>
#include "drbd_windows.h"
#include "windrbd_device.h"
#include "drbd_wingenl.h"	
#include "disp.h"
#include "windrbd_ioctl.h"

#include "drbd_int.h"
#include "drbd_wrappers.h"

NTSTATUS NTAPI IoReportRootDevice(PDRIVER_OBJECT driver);
NTSTATUS NTAPI IoReportDetectedDevice(
  PDRIVER_OBJECT DriverObject,
  INTERFACE_TYPE LegacyBusType,
  ULONG BusNumber,
  ULONG SlotNumber,
  PCM_RESOURCE_LIST ResourceList,
  PIO_RESOURCE_REQUIREMENTS_LIST ResourceRequirements,
  BOOLEAN ResourceAssigned,
  PDEVICE_OBJECT *DeviceObject
);

	/* TODO: find some headers where this fits. */
void drbd_cleanup(void);
void idr_shutdown(void);

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD mvolUnload;
DRIVER_ADD_DEVICE mvolAddDevice;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

PDEVICE_OBJECT drbd_bus_device;
static PDEVICE_OBJECT drbd_bus_device2;
static PDEVICE_OBJECT drbd_legacy_bus_object;
static PDEVICE_OBJECT drbd_physical_bus_device;

KEVENT bus_ready_event;

int create_bus_device(void)
{
	NTSTATUS status;
	PDEVICE_OBJECT new_device;
	PDEVICE_OBJECT new_device2;
	UNICODE_STRING bus_device_name;

#if 0
	RtlInitUnicodeString(&bus_device_name, L"\\Device\\WinDRBD");

	status = IoCreateDevice(mvolDriverObject,
				4,	/* 0? */	
				&bus_device_name,
//				FILE_DEVICE_CONTROLLER,
				FILE_DEVICE_BUS_EXTENDER,
                                FILE_DEVICE_SECURE_OPEN,
                                FALSE,
                                &new_device);

	if (status != STATUS_SUCCESS || new_device == NULL) {
		printk("Could not create WinDRBD bus object, status is %x.\n", status);
		return -1;
	}
	drbd_bus_device = new_device;


printk("drbd_bus_device is %p\n", drbd_bus_device);
printk("characteristics is before %x\n", drbd_bus_device->Characteristics);
	drbd_bus_device->Characteristics |= FILE_CHARACTERISTIC_PNP_DEVICE;
printk("characteristics is after %x\n", drbd_bus_device->Characteristics);
	drbd_bus_device->Flags &= ~DO_DEVICE_INITIALIZING;
#endif

printk("1\n");
//	status = IoReportDetectedDevice(mvolDriverObject, InterfaceTypeUndefined, -1, -1, NULL, NULL, FALSE, &drbd_bus_device);
printk("2\n");
	new_device2 = NULL;
	status = IoReportDetectedDevice(mvolDriverObject, InterfaceTypeUndefined, -1, -1, NULL, NULL, FALSE, &new_device2);
printk("3 %p\n", new_device2);
	if (status != STATUS_SUCCESS) {
		printk("Could not report WinDRBD bus object, status is %x.\n", status);
		return -1;
	}
	drbd_bus_device = new_device2;
printk("4 flags is %x\n", drbd_bus_device->Flags);

printk("characteristics is before %x\n", drbd_bus_device->Characteristics);
	drbd_bus_device->Characteristics |= FILE_CHARACTERISTIC_PNP_DEVICE;
printk("characteristics is after %x\n", drbd_bus_device->Characteristics);

	drbd_bus_device->Flags &= ~DO_DEVICE_INITIALIZING;
printk("5 flags is %x\n", drbd_bus_device->Flags);

	return 0;
}

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

	/* Next, the threads subsystem (so DRBD can create threads).
         * Also makes current valid (needed in spinlock debugging).
         */
	init_windrbd_threads();

	/* Then, initialize the printk subsystem (ring buffer). Logging
	 * can be seen only later when booting is finished (depending on
	 * OS), on most OSes this is when the first printk on behalf of
	 * a drbdadm command happens.
	 */
	initialize_syslog_printk();

#ifdef KMALLOC_DEBUG
		/* no printk's before this: */
	init_kmalloc_debug();
	printk("kmalloc_debug initialized.\n");
#endif

	printk(KERN_INFO "Windrbd Driver Loading (compiled " __DATE__ " " __TIME__ ") ...\n");

#ifdef SPIN_LOCK_DEBUG
	spinlock_debug_init();
	printk("spinlock_debug initialized.\n");
#endif

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
	DriverObject->DriverExtension->AddDevice = mvolAddDevice;
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

	create_bus_device();

	printk(KERN_INFO "Windrbd Driver loaded.\n");

	windrbd_run_tests();

#if 0
	IoReportDetectedDevice(DriverObject, InterfaceTypeUndefined, -1, -1, NULL, NULL, FALSE, &drbd_legacy_bus_object);
printk("drbd_legacy_bus_object is %p\n", drbd_legacy_bus_object);
/*
	status = mvolAddDevice(DriverObject, drbd_bus_object1);
	if (status != STATUS_SUCCESS)
		printk("mvolAddDevice failed status is %x\n", status);
	else
		printk("mvolAddDevice bus object succeeded\n");
*/
#endif
	KeInitializeEvent(&bus_ready_event, NotificationEvent, FALSE);

#if 0
	status = IoReportRootDevice(DriverObject);
	if (status != STATUS_SUCCESS)
		printk("IoReportRootDevice failed status is %x\n", status);
	else
		printk("IoReportRootDevice succeeded\n");
#endif

	printk("Attempting to start boot device\n");
	windrbd_init_boot_device();
	printk("Start boot device stage1 returned\n");

	return STATUS_SUCCESS;
}

int windrbd_wait_for_bus_object(void)
{
	NTSTATUS status;

	status = KeWaitForSingleObject(&bus_ready_event, Executive, KernelMode, FALSE, NULL);

	if (status != STATUS_SUCCESS)
		return -1;

	return 0;
}

void windrbd_bus_is_ready(void)
{
	KeSetEvent(&bus_ready_event, 0, FALSE);
}

int windrbd_rescan_bus(void)
{
printk("1 %p\n", drbd_bus_device);
	if (drbd_bus_device != NULL) {
printk("2\n");
		IoInvalidateDeviceRelations(drbd_bus_device, BusRelations);
printk("3\n");
		return 0;
	}
	printk("Warning: physical bus device does not exist (yet)\n");
	return -1;
}

void mvolUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNICODE_STRING linkUnicode;
	NTSTATUS status;

	printk("Unloading windrbd driver.\n");

	windrbd_shutdown_tests();
	printk("Terminated tests\n");

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

#ifdef SPIN_LOCK_DEBUG
	spinlock_debug_shutdown();
	printk("spinlock_debug shut down.\n");
#endif

	windrbd_shutdown_netlink();
	printk("Netlink layer shut down.\n");

	printk("WinSocket layer shut down.\n");

	windrbd_reap_all_threads();
	printk("Reaped remaining DRBD threads\n");

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
	UNICODE_STRING drbd_bus, drbd_bus_dos;
	NTSTATUS status;
	struct _DEVICE_OBJECT *bus_device;
	struct _BUS_EXTENSION *bus_extension;

	printk(KERN_INFO "AddDevice: PhysicalDeviceObject is %p\n", PhysicalDeviceObject);

#if 0
	if (drbd_bus_device == NULL) {
		RtlInitUnicodeString(&drbd_bus, L"\\Device\\WinDRBD");
		RtlInitUnicodeString(&drbd_bus_dos, L"\\DosDevices\\WinDRBD");

		status = IoCreateDevice(DriverObject, sizeof(BUS_EXTENSION), &drbd_bus, FILE_DEVICE_CONTROLLER, FILE_DEVICE_SECURE_OPEN, FALSE, &bus_device);
		if (status != STATUS_SUCCESS)
			printk("IoCreateDevice bus device returned %x\n", status);
		else
			printk("Bus device object created bus_device is %p\n", bus_device);

		status = IoCreateSymbolicLink(&drbd_bus_dos, &drbd_bus);

		if (status != STATUS_SUCCESS)
			printk("IoCreateSymbolicLink bus device returned %x\n", status);
		else
			printk("Bus device object symlink created\n");

		bus_device->Flags |= DO_DIRECT_IO;                  // FIXME?
		bus_device->Flags |= DO_POWER_INRUSH;               // FIXME?

		bus_extension = (struct _BUS_EXTENSION*) bus_device->DeviceExtension;

		if (PhysicalDeviceObject != NULL) {
			bus_extension->lower_device = IoAttachDeviceToDeviceStack(bus_device, PhysicalDeviceObject);
			if (bus_extension->lower_device == NULL)
				printk("IoAttachDeviceToDeviceStack failed.\n");
			else
				printk("IoAttachDeviceToDeviceStack returned object %p.\n", bus_extension->lower_device);
		} else {
			printk("PhysicalDeviceObject is NULL\n");
		}
		bus_device->Flags &= ~DO_DEVICE_INITIALIZING;

		drbd_bus_device = bus_device;
		drbd_physical_bus_device = PhysicalDeviceObject;
	}
#endif
#if 0
 else {
		struct block_device_reference *ref;
		struct block_device_reference *new_ref;
		struct block_device *bdev;
		struct _DEVICE_OBJECT *new_disk_device;
		struct _DEVICE_OBJECT *attached_disk_device;

		printk("AddDevice called but bus object (%p) already there, maybe it is a DISK device.\n", drbd_bus_device);

		ref = PhysicalDeviceObject->DeviceExtension;
			/* TODO: we shoud really have a magic in the
			 * device extension to check if it is really
			 * Windows block device for a DRBD minor.
			 */
		if (ref == NULL || ref->bdev == NULL) {
			printk("This is not a valid WinDRBD block device.\n");
		} else {
			if (ref->magic != BLOCK_DEVICE_UPPER_MAGIC) {
				printk("This is not a valid WinDRBD block device, magic is %x (expected %x).\n", ref->magic, BLOCK_DEVICE_UPPER_MAGIC);
			} else {
				bdev = ref->bdev;

				status = IoCreateDevice(DriverObject, sizeof(struct block_device_reference), NULL, FILE_DEVICE_DISK, FILE_AUTOGENERATED_DEVICE_NAME | FILE_DEVICE_SECURE_OPEN, FALSE, &new_disk_device);
				if (status != STATUS_SUCCESS) {
					printk("Couldn't create disk device, status is %x\n", status);
				} else {
					printk("New upper device object is %p\n", new_disk_device);
					new_ref = new_disk_device->DeviceExtension;
					new_ref->bdev = bdev;
					new_ref->magic = BLOCK_DEVICE_ATTACHED_MAGIC;
					bdev->upper_windows_device = new_disk_device;
					if (PhysicalDeviceObject != NULL) {
						bdev->attached_windows_device = IoAttachDeviceToDeviceStack(new_disk_device, PhysicalDeviceObject);
						if (bdev->attached_windows_device == NULL)
							printk("IoAttachDeviceToDeviceStack failed.\n");
						else
							printk("IoAttachDeviceToDeviceStack returned object %p.\n", bdev->attached_windows_device);
					} else {
						printk("PhysicalDeviceObject is NULL\n");
					}
				}
			}
		}
	}
#endif

	return STATUS_SUCCESS;
}

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
#include <initguid.h>
#include <devguid.h>
#include "drbd_windows.h"
#include "windrbd_device.h"
#include "drbd_wingenl.h"	
#include "disp.h"
#include "windrbd/windrbd_ioctl.h"
#include <linux/module.h>
/* #include "windrbd/windrbd_ioctl.h" */

#include "drbd_int.h"
#include "drbd_wrappers.h"

void drbd_cleanup(void);
void idr_shutdown(void);

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD mvolUnload;
DRIVER_ADD_DEVICE mvolAddDevice;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

PDEVICE_OBJECT	mvolRootDeviceObject;
PDEVICE_OBJECT	user_device_object;
PDRIVER_OBJECT	mvolDriverObject;

int seq_file_idx = 0;

struct ratelimit_state drbd_ratelimit_state;

/* https://vxlab.info/wasm/print.php-article=npi_subvert.htm */
const NPIID NPI_WSK_INTERFACE_ID = {
	0x2227E803, 0x8D8B, 0x11D4,
	{0xAB, 0xAD, 0x00, 0x90, 0x27, 0x71, 0x9E, 0x09}
};

PDEVICE_OBJECT drbd_bus_device;
static PDEVICE_OBJECT drbd_bus_device2;
static PDEVICE_OBJECT drbd_legacy_bus_object;
static PDEVICE_OBJECT drbd_physical_bus_device;

extern void init_transport(void);

KEVENT bus_ready_event;

static NTSTATUS create_device(const char *name, const UNICODE_STRING *sddl_perms, struct _DEVICE_OBJECT **d)
{
	NTSTATUS status;
	PDEVICE_OBJECT deviceObject;
	UNICODE_STRING nameUnicode, linkUnicode;
	wchar_t tmp[100], tmp2[100];

	_snwprintf(tmp, ARRAY_SIZE(tmp), L"\\Device\\%S", name);
	RtlInitUnicodeString(&nameUnicode, tmp);
	printk("About to create device %S with permissions %S\n", nameUnicode.Buffer, sddl_perms->Buffer);
	status = IoCreateDeviceSecure(mvolDriverObject, sizeof(ROOT_EXTENSION),
			 &nameUnicode, FILE_DEVICE_UNKNOWN,
			FILE_DEVICE_SECURE_OPEN, FALSE,
			sddl_perms, NULL, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		printk("Can't create root, err=%x\n", status);
		return status;
	}

	_snwprintf(tmp2, ARRAY_SIZE(tmp2), L"\\DosDevices\\%S", name);
	RtlInitUnicodeString(&linkUnicode, tmp2);
	printk("About to create symbolic link from %S to %S\n", linkUnicode.Buffer, nameUnicode.Buffer);
	status = IoCreateSymbolicLink(&linkUnicode, &nameUnicode);
	if (!NT_SUCCESS(status))
	{
		printk("cannot create symbolic link, err=%x\n", status);
		IoDeleteDevice(deviceObject);
		return status;
	}
	if (d)
		*d = deviceObject;

	return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS            		status;
	int ret;

		/* Needed for event log */
	mvolDriverObject = DriverObject;

	/* Init windrbd primitives (spinlocks, ...) before doing anything
	 * else .. needed for printk.
	 */
	init_windrbd();
	init_locking();
	init_waitqueue();

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
	printk(KERN_DEBUG "kmalloc_debug initialized.\n");
#endif

	init_transport();
	init_free_bios();

	make_me_a_windrbd_thread("driver-init");
	sudo();

	printk(KERN_NOTICE "Windrbd Driver Loading (compiled " __DATE__ " " __TIME__ ") ...\n");

#ifdef SPIN_LOCK_DEBUG
	spinlock_debug_init();
	printk(KERN_DEBUG "spinlock_debug initialized.\n");
#endif

	initRegistry(RegistryPath);
	init_event_log();

	status = create_device(WINDRBD_ROOT_DEVICE_NAME, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, &mvolRootDeviceObject);
	if (status != STATUS_SUCCESS)
		return status;

	status = create_device(WINDRBD_USER_DEVICE_NAME, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_R, &user_device_object);
	if (status != STATUS_SUCCESS)
		return status;

	windrbd_set_major_functions(DriverObject);
/* Remove this line to make driver removable (driver removing currently
 * BSOD's sometimes):
 */
	DriverObject->DriverExtension->AddDevice = mvolAddDevice;
	DriverObject->DriverUnload = mvolUnload;

		/* For bus object: TODO: don't do this if there
		 * is no bus object. (Maybe move to AddDevice)
		 */

	try_module_get(&windrbd_module);

	dtt_initialize();

	system_wq = alloc_ordered_workqueue("system workqueue", 0);
	if (system_wq == NULL) {
		printk("Could not allocate system work queue\n");
		IoDeleteDevice(mvolRootDeviceObject);
		IoDeleteDevice(user_device_object);

		return STATUS_NO_MEMORY;
	}

	ret = drbd_init();
	if (ret != 0) {
		printk(KERN_ERR "cannot init drbd, error is %d", ret);
		IoDeleteDevice(mvolRootDeviceObject);
		IoDeleteDevice(user_device_object);

		return STATUS_TIMEOUT;
	}

	windrbd_init_netlink();
	windrbd_init_usermode_helper();
	windrbd_init_wsk();

	printk(KERN_INFO "Windrbd Driver loaded.\n");

	windrbd_run_tests();

	KeInitializeEvent(&bus_ready_event, NotificationEvent, FALSE);

/*
	printk("NOT starting boot device\n");
*/
	printk("Attempting to start boot device\n");

	windrbd_init_boot_device();
	printk("Start boot device stage1 returned\n");

	return_to_windows(current);

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
	if (drbd_physical_bus_device != NULL) {
		IoInvalidateDeviceRelations(drbd_physical_bus_device, BusRelations);
		return 0;
	}
	printk("Warning: physical bus device does not exist (yet)\n");
	return -1;
}

void mvolUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNICODE_STRING linkUnicode, userLinkUnicode;
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

	RtlInitUnicodeString(&userLinkUnicode, L"\\DosDevices\\" WINDRBD_USER_DEVICE_NAME);
	status = IoDeleteSymbolicLink(&userLinkUnicode);
	if (!NT_SUCCESS(status))
		printk("Cannot delete user device link, status is %x.\n", status);

        IoDeleteDevice(mvolRootDeviceObject);
        IoDeleteDevice(user_device_object);

	printk("Root device deleted.\n");

	idr_shutdown();
	printk("IDR layer shut down.\n");

#ifdef SPIN_LOCK_DEBUG
	spinlock_debug_shutdown();
	printk("spinlock_debug shut down.\n");
#endif

	shutdown_free_bios();
	printk("Free bios shut down.\n");

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
	UNICODE_STRING bus_device_name;

	printk(KERN_INFO "AddDevice: PhysicalDeviceObject is %p\n", PhysicalDeviceObject);

	/* This assumes that the bus device object is the first
	 * object being attached, which is 'normally' the case.
	 */

	if (drbd_bus_device == NULL) {
		RtlInitUnicodeString(&drbd_bus, L"\\Device\\windrbd_bus_device");
		RtlInitUnicodeString(&drbd_bus_dos, L"\\DosDevices\\windrbd_bus_device");

		status = IoCreateDevice(DriverObject, sizeof(BUS_EXTENSION), &drbd_bus, FILE_DEVICE_BUS_EXTENDER, FILE_DEVICE_SECURE_OPEN, FALSE, &bus_device);
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
			status = IoRegisterDeviceInterface(PhysicalDeviceObject,
					&GUID_DEVCLASS_SCSIADAPTER,
					NULL,
					&bus_device_name);
			printk("IoRegisterDeviceInterface returned %x\n", status);
			printk("bus_device_name is %S\n", bus_device_name.Buffer);

			bus_extension->lower_device = IoAttachDeviceToDeviceStack(bus_device, PhysicalDeviceObject);
			if (bus_extension->lower_device == NULL)
				printk("IoAttachDeviceToDeviceStack failed.\n");
			else
				printk("IoAttachDeviceToDeviceStack returned object %p.\n", bus_extension->lower_device);
#if 0
			bus_extension->lower_device = NULL;
			printk("Set bus_extension->lower_device to NULL\n");
#endif
		} else {
			printk("PhysicalDeviceObject is NULL\n");
		}
		bus_device->Flags &= ~DO_DEVICE_INITIALIZING;

		drbd_bus_device = bus_device;
		drbd_physical_bus_device = PhysicalDeviceObject;
	}

	return STATUS_SUCCESS;
}

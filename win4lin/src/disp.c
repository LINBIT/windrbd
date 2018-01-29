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
#include <ntstrsafe.h>
#include <ntddk.h>
#include "drbd_windows.h"
#include "windrbd_device.h"
#include "drbd_wingenl.h"	
#include "disp.h"
#include "mvolmsg.h"

#include "drbd_int.h"
#include "drbd_wrappers.h"

#ifdef _WIN32_WPP
karin
#include "disp.tmh"
#endif


DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD mvolUnload;
DRIVER_ADD_DEVICE mvolAddDevice;

UINT32 windows_ret_codes[] = {
    [EROFS] = STATUS_MEDIA_WRITE_PROTECTED,
};

UINT32 translate_drbd_error(int i)
{
    unsigned int j;
    UINT32 err;

    if (i >= 0)
    /* No error. */
	return i;

    j = -i;
    if (j >= ARRAY_SIZE(windows_ret_codes))
	return STATUS_UNSUCCESSFUL;

    err = windows_ret_codes[j];
    return err ? err : STATUS_UNSUCCESSFUL;
}


#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS            		status;
	PDEVICE_OBJECT      		deviceObject;
	PROOT_EXTENSION			RootExtension = NULL;
	UNICODE_STRING      		nameUnicode, linkUnicode;
	ULONG				i;
	static volatile LONG      IsEngineStart = FALSE;
	int ret;

	// init logging system first
	initialize_syslog_printk();

	WDRBD_TRACE("DRBD Driver Loading (compiled " __DATE__ " " __TIME__ ") ...\n");

	initRegistry(RegistryPath);

	gbShutdown = FALSE;
		
	RtlInitUnicodeString(&nameUnicode, L"\\Device\\mvolCntl");
	status = IoCreateDevice(DriverObject, sizeof(ROOT_EXTENSION),
       		 &nameUnicode, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		WDRBD_ERROR("Can't create root, err=%x\n", status);
		return status;
	}

	RtlInitUnicodeString(&linkUnicode, L"\\DosDevices\\mvolCntl");
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
	DriverObject->DriverExtension->AddDevice = mvolAddDevice;
	DriverObject->DriverUnload = mvolUnload;

	RootExtension = deviceObject->DeviceExtension;
	RootExtension->Magic = MVOL_MAGIC;
	RootExtension->Count = 0;
	ucsdup(&RootExtension->RegistryPath, RegistryPath->Buffer, RegistryPath->Length);
	RootExtension->PhysicalDeviceNameLength = nameUnicode.Length;
	RtlCopyMemory(RootExtension->PhysicalDeviceName, nameUnicode.Buffer, nameUnicode.Length);

	KeInitializeSpinLock(&mvolVolumeLock);
	KeInitializeMutex(&mvolMutex, 0);
	KeInitializeMutex(&eventlogMutex, 0);
	downup_rwlock_init(&transport_classes_lock); //init spinlock for transport 
	mutex_init(&g_genl_mutex);
	mutex_init(&notification_mutex);
	KeInitializeSpinLock(&transport_classes_lock);

	dtt_initialize();

	system_wq = alloc_ordered_workqueue("system workqueue", 0);
	if (system_wq == NULL) {
		pr_err("Could not allocate system work queue\n");
		return STATUS_NO_MEMORY;
	}


#ifdef _WIN32_WPP
	WPP_INIT_TRACING(DriverObject, RegistryPath);
	DoTraceMessage(TRCINFO, "WDRBD V9(1:1) MVF Driver loaded.");
#endif
    // Init DRBD engine
	ret = drbd_init();
	if (ret) { /* TODO: ?? */
		WDRBD_ERROR("cannot init drbd, %d", ret);
  //      IoDeleteDevice(deviceObject);
		return STATUS_TIMEOUT;
	}

	WDRBD_INFO("MVF Driver loaded.\n");

	if (FALSE == InterlockedCompareExchange(&IsEngineStart, TRUE, FALSE))
	{
		HANDLE		hNetLinkThread = NULL;
		HANDLE		hLogLinkThread = NULL;
		NTSTATUS	Status = STATUS_UNSUCCESSFUL;

        // Init WSK and StartNetLinkServer
		Status = PsCreateSystemThread(&hNetLinkThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, InitWskNetlink, NULL);
		if (!NT_SUCCESS(Status))
		{
			WDRBD_ERROR("PsCreateSystemThread failed with status 0x%08X\n", Status);
			return Status;
		}

		Status = ObReferenceObjectByHandle(hNetLinkThread, THREAD_ALL_ACCESS, NULL, KernelMode, &g_NetlinkServerThread, NULL);
		ZwClose(hNetLinkThread);

		if (!NT_SUCCESS(Status))
		{
			WDRBD_ERROR("ObReferenceObjectByHandle() failed with status 0x%08X\n", Status);
			return Status;
		}
    }

    return STATUS_SUCCESS;
}

void mvolUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	
	printk("Unloading windrbd driver.\n");
}

/* TODO: This should not be called. Change type of driver so that
   this is not neccessary */
NTSTATUS
mvolAddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT PhysicalDeviceObject)
{
	printk(KERN_INFO "AddDevice NOT DONE\n");
	return STATUS_NO_SUCH_DEVICE;
}


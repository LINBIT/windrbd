/*
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
#include "proto.h"

#include "drbd_int.h"
#include "drbd_wrappers.h"

#ifdef _WIN32_WPP
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
mvolRunIrpSynchronous(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

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
	wdrbd_logger_init();

    WDRBD_TRACE("DRBD Driver Loading (compiled " __DATE__ " " __TIME__ ") ...\n");

	initRegistry(RegistryPath);

	windrbd_set_major_functions(DriverObject);
	DriverObject->DriverExtension->AddDevice = mvolAddDevice;
	DriverObject->DriverUnload = mvolUnload;

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

    RootExtension = deviceObject->DeviceExtension;
    RootExtension->Magic = MVOL_MAGIC;
    RootExtension->Head = NULL;
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
    if (ret) {
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

VOID
mvolUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
#ifdef _WIN32_WPP
	WPP_CLEANUP(DriverObject);
#endif
	wdrbd_logger_cleanup();
}

static
NTSTATUS _QueryVolumeNameRegistry(
	_In_ PMOUNTDEV_UNIQUE_ID pmuid,
	_Out_ PVOLUME_EXTENSION pvext)
{
	OBJECT_ATTRIBUTES           attributes;
	PKEY_FULL_INFORMATION       keyInfo = NULL;
	PKEY_VALUE_FULL_INFORMATION valueInfo = NULL;
	size_t                      valueInfoSize = sizeof(KEY_VALUE_FULL_INFORMATION) + 1024 + sizeof(ULONGLONG);

	UNICODE_STRING mm_reg_path;
	NTSTATUS status;
	HANDLE hKey = NULL;
	ULONG size;
	int Count;

	PAGED_CODE();

	RtlUnicodeStringInit(&mm_reg_path, L"\\Registry\\Machine\\System\\MountedDevices");

	InitializeObjectAttributes(&attributes,
		&mm_reg_path,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwOpenKey(&hKey, KEY_READ, &attributes);
	if (!NT_SUCCESS(status)) {
		goto cleanup;
	}

	status = ZwQueryKey(hKey, KeyFullInformation, NULL, 0, &size);
	if (status != STATUS_BUFFER_TOO_SMALL) {
		ASSERT(!NT_SUCCESS(status));
		goto cleanup;
	}

	keyInfo = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, size, '00DW');
	if (!keyInfo) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}

	status = ZwQueryKey(hKey, KeyFullInformation, keyInfo, size, &size);
	if (!NT_SUCCESS(status)) {
		goto cleanup;
	}

	Count = keyInfo->Values;

	valueInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoSize, '10DW');
	if (!valueInfo) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}

	for (int i = 0; i < Count; ++i) {
		RtlZeroMemory(valueInfo, valueInfoSize);

		status = ZwEnumerateValueKey(hKey, i, KeyValueFullInformation, valueInfo, valueInfoSize, &size);
		if (!NT_SUCCESS(status)) {
			if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
				goto cleanup;
			}
		}

		if (REG_BINARY == valueInfo->Type && pmuid->UniqueIdLength == valueInfo->DataLength) {
			PWCHAR key = ExAllocatePoolWithTag(PagedPool, valueInfo->NameLength + sizeof(WCHAR), '20DW');
			if (!key) {
				goto cleanup;
			}
			RtlZeroMemory(key, valueInfo->NameLength + sizeof(WCHAR));
			RtlCopyMemory(key, valueInfo->Name, valueInfo->NameLength);

			if (((SIZE_T)pmuid->UniqueIdLength == RtlCompareMemory(pmuid->UniqueId, (PCHAR)valueInfo + valueInfo->DataOffset, pmuid->UniqueIdLength))) {
				if (wcsstr(key, L"\\DosDevices\\")) {
					ucsdup(&pvext->MountPoint, L" :", 4);
					pvext->MountPoint.Buffer[0] = toupper((CHAR)(*(key + wcslen(L"\\DosDevices\\"))));
					pvext->VolIndex = pvext->MountPoint.Buffer[0] - 'C';
				}
				else if (wcsstr(key, L"\\??\\Volume")) {	// registry's style
					RtlUnicodeStringInit(&pvext->VolumeGuid, key);
					key = NULL;
				}
			}

			kfree(key);
		}
	}

cleanup:
	kfree(keyInfo);
	kfree(valueInfo);

	if (hKey) {
		ZwClose(hKey);
	}

	return status;
}

/* TODO: This should not be called. Change type of driver so that
   this is not neccessary */
NTSTATUS
mvolAddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT PhysicalDeviceObject)
{
	printk(KERN_INFO "AddDevice NOT DONE\n");
	return STATUS_NO_SUCH_DEVICE;
}


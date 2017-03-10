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


_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH mvolCreate;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH mvolClose;
_Dispatch_type_(IRP_MJ_SHUTDOWN) DRIVER_DISPATCH mvolShutdown;
_Dispatch_type_(IRP_MJ_FLUSH_BUFFERS) DRIVER_DISPATCH mvolFlush;
_Dispatch_type_(IRP_MJ_POWER) DRIVER_DISPATCH mvolDispatchPower;
_Dispatch_type_(IRP_MJ_SYSTEM_CONTROL) DRIVER_DISPATCH mvolSystemControl;
_Dispatch_type_(IRP_MJ_READ) DRIVER_DISPATCH mvolRead;
_Dispatch_type_(IRP_MJ_WRITE) DRIVER_DISPATCH mvolWrite;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH mvolDeviceControl;
_Dispatch_type_(IRP_MJ_PNP) DRIVER_DISPATCH mvolDispatchPnp;

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

	// init logging system first
	wdrbd_logger_init();

    WDRBD_TRACE("MVF Driver Loading...\n");

    initRegistry(RegistryPath);

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = mvolSendToNextDriver;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = mvolCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = mvolClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = mvolRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = mvolWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = mvolDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = mvolShutdown;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = mvolFlush;
    DriverObject->MajorFunction[IRP_MJ_PNP] = mvolDispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = mvolSystemControl;
    DriverObject->MajorFunction[IRP_MJ_POWER] = mvolDispatchPower;

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

#ifdef _WIN32_WPP
	WPP_INIT_TRACING(DriverObject, RegistryPath);
	DoTraceMessage(TRCINFO, "WDRBD V9(1:1) MVF Driver loaded.");
#endif
    // Init DRBD engine
    drbd_init();

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

NTSTATUS
mvolAddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT PhysicalDeviceObject)
{
    NTSTATUS            status;
    PDEVICE_OBJECT      AttachedDeviceObject = NULL;
    PDEVICE_OBJECT      ReferenceDeviceObject = NULL;
    PVOLUME_EXTENSION   VolumeExtension = NULL;
    ULONG               deviceType = 0;


    ReferenceDeviceObject = IoGetAttachedDeviceReference(PhysicalDeviceObject);
    deviceType = ReferenceDeviceObject->DeviceType; //deviceType = 0x7 = FILE_DEVICE_DISK 
    ObDereferenceObject(ReferenceDeviceObject);

    status = IoCreateDevice(mvolDriverObject, sizeof(VOLUME_EXTENSION), NULL,
        deviceType, FILE_DEVICE_SECURE_OPEN, FALSE, &AttachedDeviceObject);
    if (!NT_SUCCESS(status))
    {
        mvolLogError(mvolRootDeviceObject, 102, MSG_ADD_DEVICE_ERROR, status);
        WDRBD_ERROR("cannot create device, err=0x%x\n", status);
        return status;
    }

    AttachedDeviceObject->Flags |= (DO_DIRECT_IO | DO_POWER_PAGABLE);
    AttachedDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    VolumeExtension = AttachedDeviceObject->DeviceExtension;
    RtlZeroMemory(VolumeExtension, sizeof(VOLUME_EXTENSION));
    VolumeExtension->DeviceObject = AttachedDeviceObject;
    VolumeExtension->PhysicalDeviceObject = PhysicalDeviceObject;
    VolumeExtension->Magic = MVOL_MAGIC;
    VolumeExtension->Flag = 0;
    VolumeExtension->IrpCount = 0;
    VolumeExtension->TargetDeviceObject =
        IoAttachDeviceToDeviceStack(AttachedDeviceObject, PhysicalDeviceObject);
    if (VolumeExtension->TargetDeviceObject == NULL)
    {
        mvolLogError(mvolRootDeviceObject, 103, MSG_ADD_DEVICE_ERROR, STATUS_NO_SUCH_DEVICE);
        IoDeleteDevice(AttachedDeviceObject);
        return STATUS_NO_SUCH_DEVICE;
    }

	IoInitializeRemoveLock(&VolumeExtension->RemoveLock, '00FS', 0, 0);
	KeInitializeMutex(&VolumeExtension->CountMutex, 0);

    status = GetDeviceName(PhysicalDeviceObject,
        VolumeExtension->PhysicalDeviceName, MAXDEVICENAME * sizeof(WCHAR)); // -> \Device\HarddiskVolumeXX
    if (!NT_SUCCESS(status))
    {
        mvolLogError(mvolRootDeviceObject, 101, MSG_ADD_DEVICE_ERROR, status);
		IoDeleteDevice(AttachedDeviceObject);
        return status;
    }
    VolumeExtension->PhysicalDeviceNameLength = wcslen(VolumeExtension->PhysicalDeviceName) * sizeof(WCHAR);

	PMOUNTDEV_UNIQUE_ID pmuid = QueryMountDUID(PhysicalDeviceObject);
	if (pmuid) {
		_QueryVolumeNameRegistry(pmuid, VolumeExtension);
		ExFreePool(pmuid);
	}

    MVOL_LOCK();
    mvolAddDeviceList(VolumeExtension);
    MVOL_UNLOCK();
    
#ifdef _WIN32_MVFL
    if (do_add_minor(VolumeExtension->VolIndex))
    {
        status = mvolInitializeThread(VolumeExtension, &VolumeExtension->WorkThreadInfo, mvolWorkThread);
        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("Failed to initialize WorkThread. status(0x%x)\n", status);
            //return status;
        }

        VolumeExtension->Active = TRUE;
    }
#endif

	// DW-1109: create block device in add device routine, it won't be destroyed at least we put ref in remove device routine.
	VolumeExtension->dev = create_drbd_block_device(VolumeExtension);

    WDRBD_INFO("VolumeExt(0x%p) Device(%ws) VolIndex(%d) Active(%d) MountPoint(%wZ)\n",
        VolumeExtension,
        VolumeExtension->PhysicalDeviceName,
        VolumeExtension->VolIndex,
        VolumeExtension->Active,
        &VolumeExtension->MountPoint);

    return STATUS_SUCCESS;
}

NTSTATUS
mvolSendToNextDriver(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;
	NTSTATUS 	status = STATUS_SUCCESS;
	
    if (DeviceObject == mvolRootDeviceObject) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		status = IoAcquireRemoveLock(&VolumeExtension->RemoveLock, NULL);
		if (!NT_SUCCESS(status)) {
			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = 0;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return status;
		}
	}
		
    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		IoReleaseRemoveLock(&VolumeExtension->RemoveLock, NULL);
	}

	return status;
}

NTSTATUS
mvolCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;
    int err;

    if (DeviceObject == mvolRootDeviceObject) {
	WDRBD_TRACE("mvolRootDevice Request\n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
    }

    if (VolumeExtension->Active)
    {
	struct drbd_device *device = get_device_with_vol_ext(VolumeExtension, TRUE);
	struct block_device *bdev = VolumeExtension->dev;
	PIO_STACK_LOCATION psl;


	psl = IoGetCurrentIrpStackLocation(Irp);

	/* https://msdn.microsoft.com/en-us/library/windows/hardware/ff548630(v=vs.85).aspx
	 * https://msdn.microsoft.com/en-us/library/windows/hardware/ff550729(v=vs.85).aspx
	 * https://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx
	 * */
	err = drbd_open(bdev,
		(psl->Parameters.Create.SecurityContext->DesiredAccess &
		 (FILE_WRITE_DATA  | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
		  FILE_APPEND_DATA | GENERIC_WRITE)) ? FMODE_WRITE : 0);

	if (err < 0)
	{
	    kref_put(&device->kref, drbd_destroy_device);

	    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	    IoCompleteRequest(Irp, IO_NO_INCREMENT);

	    return translate_drbd_error(err);
	} else {
	    return STATUS_SUCCESS;
	}
    }
    return mvolSendToNextDriver(DeviceObject, Irp);
}

NTSTATUS
mvolClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;
    if (DeviceObject == mvolRootDeviceObject) {
	WDRBD_TRACE("mvolRootDevice Request\n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    } else {
	struct drbd_device *device = get_device_with_vol_ext(VolumeExtension, TRUE);
	kref_put(&device->kref, drbd_destroy_device);
    }
    return STATUS_SUCCESS;
}

void drbd_cleanup_by_win_shutdown(PVOLUME_EXTENSION VolumeExtension);

NTSTATUS
mvolShutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;

	drbd_cleanup_by_win_shutdown(VolumeExtension);

    return mvolSendToNextDriver(DeviceObject, Irp);
    //status = mvolRunIrpSynchronous(DeviceObject, Irp); // DW-1146 disable cleaunup logic. for some case, hang occurred while shutdown
	//return status;
}

NTSTATUS
mvolFlush(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS	status = STATUS_SUCCESS;
	PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;
	 
	if (g_mj_flush_buffers_filter && VolumeExtension->Active) {
		// DW-1300: get device and get reference.
		struct drbd_device *device = get_device_with_vol_ext(VolumeExtension, TRUE);
        if (device) {
			PMVOL_THREAD				pThreadInfo;
			pThreadInfo = &VolumeExtension->WorkThreadInfo;
            IoMarkIrpPending(Irp);
            ExInterlockedInsertTailList(&pThreadInfo->ListHead,
                &Irp->Tail.Overlay.ListEntry, &pThreadInfo->ListLock);
            IO_THREAD_SIG(pThreadInfo);
			// DW-1300: put device reference count when no longer use.
			kref_put(&device->kref, drbd_destroy_device);
			return STATUS_PENDING;
        } else {
        	Irp->IoStatus.Information = 0;
            Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return STATUS_INVALID_DEVICE_REQUEST;
        }
	}
		
	status = mvolSendToNextDriver(DeviceObject, Irp);

	return status;
}

_Use_decl_annotations_
NTSTATUS
mvolSystemControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;

    if (DeviceObject == mvolRootDeviceObject)
    {
        WDRBD_TRACE("mvolRootDevice Request\n");

        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    // TODO: what would we do here?
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_INVALID_DEVICE_REQUEST;

#if 0

#ifdef _WIN32_MVFL
    if (VolumeExtension->Active)
    {
		// DW-1300: get device and get reference.
		struct drbd_device *device = get_device_with_vol_ext(VolumeExtension, TRUE);
		// DW-1300: prevent mounting volume when device is failed or below.
		if (device && device->resource->bTempAllowMount == FALSE && ((R_PRIMARY != device->resource->role[NOW]) || (device->resource->bPreDismountLock == TRUE) || device->disk_state[NOW] <= D_FAILED))   // V9
		{
			//PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
			//WDRBD_TRACE("DeviceObject(0x%x), MinorFunction(0x%x) STATUS_INVALID_DEVICE_REQUEST\n", DeviceObject, irpSp->MinorFunction);
			// DW-1300: put device reference count when no longer use.
			kref_put(&device->kref, drbd_destroy_device);

			Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);

			return STATUS_INVALID_DEVICE_REQUEST;
		}
		// DW-1300: put device reference count when no longer use.
		else if (device)
			kref_put(&device->kref, drbd_destroy_device);
    }
#endif
    IoSkipCurrentIrpStackLocation(Irp);

    return IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
#endif
}

NTSTATUS
mvolDispatchPower(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    return mvolSendToNextDriver(DeviceObject, Irp);
}

_Use_decl_annotations_
NTSTATUS
mvolRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS 	status = STATUS_SUCCESS;
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;

    if (DeviceObject == mvolRootDeviceObject)
    {
        goto invalid_device;
    }

    status = mvolReadWriteDevice(VolumeExtension, Irp, IRP_MJ_READ);
    if (status != STATUS_SUCCESS)
    {
	mvolLogError(VolumeExtension->DeviceObject, 111, MSG_INSUFFICIENT_RESOURCES, status);
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, (CCHAR)(NT_SUCCESS(Irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
    }
    return status;

    /* TODO read balancing */
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);

#if  0
    struct drbd_device *device = get_device_quick(VolumeExtension);

async_read_filter:
    {
#ifdef DRBD_TRACE
        PIO_STACK_LOCATION readIrpSp = IoGetCurrentIrpStackLocation(Irp);
        WDRBD_TRACE("\n\nupper driver READ request start! vol:%c: sect:0x%llx sz:%d --------------------------------!\n",
            VolumeExtension->Letter, (readIrpSp->Parameters.Read.ByteOffset.QuadPart / 512), readIrpSp->Parameters.Read.Length);
#endif
        PMVOL_THREAD pThreadInfo = &VolumeExtension->WorkThreadInfo;

        IoMarkIrpPending(Irp);
        ExInterlockedInsertTailList(&pThreadInfo->ListHead, &Irp->Tail.Overlay.ListEntry, &pThreadInfo->ListLock);
        IO_THREAD_SIG(pThreadInfo);
    }
    return STATUS_PENDING;
#endif

invalid_device:
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS
mvolWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;

    if (DeviceObject == mvolRootDeviceObject)
    {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    status = mvolReadWriteDevice(VolumeExtension, Irp, IRP_MJ_WRITE);
    if (status != STATUS_SUCCESS)
    {
	mvolLogError(VolumeExtension->DeviceObject, 111, MSG_WRITE_ERROR, status);
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, (CCHAR)(NT_SUCCESS(Irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
    }
    return status;

#if 0
    if (VolumeExtension->Active) {
		// DW-1300: get device and get reference.
		struct drbd_device *device = get_device_with_vol_ext(VolumeExtension, TRUE);
		// DW-1363: prevent writing when device is failed or below.
		if (device && device->resource && (device->resource->role[NOW] == R_PRIMARY) && (device->resource->bPreSecondaryLock == FALSE) && (device->disk_state[NOW] > D_FAILED)) {
        	
			PIO_STACK_LOCATION pisl = IoGetCurrentIrpStackLocation(Irp);
			ULONGLONG offset_sector = (ULONGLONG)(pisl->Parameters.Write.ByteOffset.QuadPart) >> 9;
			ULONG size_sector = pisl->Parameters.Write.Length >> 9;
			sector_t vol_size_sector = drbd_get_capacity(device->this_bdev);

			// if io offset is larger than volume size oacassionally,
			// then allow to lower device, so not try to send to peer
			if (offset_sector + size_sector > vol_size_sector) {
				WDRBD_TRACE("Upper driver WRITE vol(%wZ) sect(0x%llx+%u) VolumeExtension->IrpCount(%d) ......................Skipped Irp:%p Irp->Flags:%x\n",
					&VolumeExtension->MountPoint, offset_sector, size_sector, VolumeExtension->IrpCount, Irp, Irp->Flags);	
				// DW-1300: put device reference count when no longer use.
				kref_put(&device->kref, drbd_destroy_device);
				goto skip;
			}

            PMVOL_THREAD				pThreadInfo;
#ifdef DRBD_TRACE
			WDRBD_TRACE("Upper driver WRITE vol(%wZ) sect(0x%llx+%u) ................Queuing(%d)!\n",
				&VolumeExtension->MountPoint, offset_sector, size_sector, VolumeExtension->IrpCount);
#endif

#ifdef MULTI_WRITE_HOOKER_THREADS
            pThreadInfo = &deviceExtension->WorkThreadInfo[deviceExtension->Rr];
            IoMarkIrpPending(Irp);
            ExInterlockedInsertTailList(&pThreadInfo->ListHead,
                &Irp->Tail.Overlay.ListEntry, &pThreadInfo->ListLock);

            IO_THREAD_SIG(pThreadInfo);
            if (++deviceExtension->Rr >= 5)
            {
                deviceExtension->Rr = 0;
            }
#else
            pThreadInfo = &VolumeExtension->WorkThreadInfo;
            IoMarkIrpPending(Irp);
            ExInterlockedInsertTailList(&pThreadInfo->ListHead,
                &Irp->Tail.Overlay.ListEntry, &pThreadInfo->ListLock);
            IO_THREAD_SIG(pThreadInfo);
#endif
			// DW-1300: put device reference count when no longer use.
			kref_put(&device->kref, drbd_destroy_device);
            return STATUS_PENDING;
        }
        else
        {
			// DW-1300: put device reference count when no longer use.
			if (device)
				kref_put(&device->kref, drbd_destroy_device);

			WDRBD_TRACE("Upper driver WRITE vol(%wZ) VolumeExtension->IrpCount(%d) STATUS_INVALID_DEVICE_REQUEST return Irp:%p Irp->Flags:%x\n",
					&VolumeExtension->MountPoint, VolumeExtension->IrpCount, Irp, Irp->Flags);	
			
            Irp->IoStatus.Information = 0;
            Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return STATUS_INVALID_DEVICE_REQUEST;
        }
    }

skip:
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		status = IoAcquireRemoveLock(&VolumeExtension->RemoveLock, NULL);
		if (!NT_SUCCESS(status)) {
			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = 0;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return status;
		}
	}

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		IoReleaseRemoveLock(&VolumeExtension->RemoveLock, NULL);
	}
	return status;
#endif
}

extern int seq_file_idx;
extern int drbd_seq_show(struct seq_file *seq, void *v);

NTSTATUS
mvolDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS		status;
    PIO_STACK_LOCATION	irpSp = NULL;
    PVOLUME_EXTENSION	VolumeExtension = DeviceObject->DeviceExtension;

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_MVOL_GET_PROC_DRBD:
        {
            PMVOL_VOLUME_INFO p = NULL;

            p = (PMVOL_VOLUME_INFO)Irp->AssociatedIrp.SystemBuffer;

            MVOL_LOCK();
            seq_file_idx = 0;
            drbd_seq_show((struct seq_file *)&p->Seq, 0);
            MVOL_UNLOCK();

            irpSp->Parameters.DeviceIoControl.OutputBufferLength = sizeof(MVOL_VOLUME_INFO);
            MVOL_IOCOMPLETE_REQ(Irp, STATUS_SUCCESS, sizeof(MVOL_VOLUME_INFO));
        }

        case IOCTL_MVOL_GET_VOLUME_COUNT:
        {
            PROOT_EXTENSION RootExtension = mvolRootDeviceObject->DeviceExtension;

            *(PULONG)(Irp->AssociatedIrp.SystemBuffer) = RootExtension->Count;
            MVOL_IOCOMPLETE_REQ(Irp, STATUS_SUCCESS, sizeof(ULONG));
        }

        case IOCTL_MVOL_GET_VOLUMES_INFO:
        {
            ULONG size = 0;

            status = IOCTL_GetAllVolumeInfo(Irp, &size);
            MVOL_IOCOMPLETE_REQ(Irp, status, size);
        }

        case IOCTL_MVOL_GET_VOLUME_INFO:
        {
            ULONG size = 0;

            status = IOCTL_GetVolumeInfo(DeviceObject, Irp, &size);
            MVOL_IOCOMPLETE_REQ(Irp, status, size);
        }

        case IOCTL_MVOL_VOLUME_START:
        {
            status = IOCTL_VolumeStart(DeviceObject, Irp);
            MVOL_IOCOMPLETE_REQ(Irp, status, 0);
        }

        case IOCTL_MVOL_VOLUME_STOP:
        {
            status = IOCTL_VolumeStop(DeviceObject, Irp);
            MVOL_IOCOMPLETE_REQ(Irp, status, 0);
        }

        case IOCTL_MVOL_GET_VOLUME_SIZE:
        {
            status = IOCTL_GetVolumeSize(DeviceObject, Irp);
            MVOL_IOCOMPLETE_REQ(Irp, status, sizeof(LARGE_INTEGER));
        }

        case IOCTL_MVOL_GET_COUNT_INFO:
        {
            ULONG			size = 0;

            status = IOCTL_GetCountInfo(DeviceObject, Irp, &size);
            MVOL_IOCOMPLETE_REQ(Irp, status, size);
        }

        case IOCTL_MVOL_MOUNT_VOLUME:
        {
			ULONG size = 0;

            status = IOCTL_MountVolume(DeviceObject, Irp, &size);
			if (!NT_SUCCESS(status))
			{
				WDRBD_WARN("IOCTL_MVOL_MOUNT_VOLUME. %wZ Volume fail. status(0x%x)\n",
					&VolumeExtension->MountPoint, status);
			}
			else if (!size)
			{	// ok
				WDRBD_INFO("IOCTL_MVOL_MOUNT_VOLUME. %wZ Volume is mounted\n",
					&VolumeExtension->MountPoint);
			}

			MVOL_IOCOMPLETE_REQ(Irp, status, size);
        }

		case IOCTL_MVOL_SET_SIMUL_DISKIO_ERROR: 
		{
			status = IOCTL_SetSimulDiskIoError(DeviceObject, Irp); // Simulate Disk I/O Error IOCTL Handler
            MVOL_IOCOMPLETE_REQ(Irp, status, 0);
		}

		case IOCTL_MVOL_SET_LOGLV_MIN:
		{
			status = IOCTL_SetMinimumLogLevel(DeviceObject, Irp); // Set minimum level of logging (system event log, service log)
			MVOL_IOCOMPLETE_REQ(Irp, status, 0);
		}
		case IOCTL_MVOL_GET_DRBD_LOG:
		{
			ULONG size = 0;
			status = IOCTL_GetDrbdLog(DeviceObject, Irp, &size);
			if(status == STATUS_SUCCESS) {
				MVOL_IOCOMPLETE_REQ(Irp, status, size);
			} else {
				MVOL_IOCOMPLETE_REQ(Irp, status, 0);
			}
		}
		case IOCTL_MVOL_SET_HANDLER_USE:
		{
			status = IOCTL_SetHandlerUse(DeviceObject, Irp); // Set handler_use value.
			MVOL_IOCOMPLETE_REQ(Irp, status, 0);
		}
    }

    if (DeviceObject == mvolRootDeviceObject ||
        VolumeExtension->TargetDeviceObject == NULL)
    {
        status = STATUS_UNSUCCESSFUL;
        MVOL_IOCOMPLETE_REQ(Irp, status, 0);
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
}

NTSTATUS
mvolDispatchPnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS		status;
    PIO_STACK_LOCATION	irpSp;

    if (DeviceObject == mvolRootDeviceObject)
    {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    switch (irpSp->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
        {
            status = mvolStartDevice(DeviceObject, Irp);
            break;
        }
		case IRP_MN_SURPRISE_REMOVAL:
        case IRP_MN_REMOVE_DEVICE:
        {
            status = mvolRemoveDevice(DeviceObject, Irp);
            break;
        }
        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        {
            status = mvolDeviceUsage(DeviceObject, Irp);
            break;
        }

        default:
            return mvolSendToNextDriver(DeviceObject, Irp);
    }

    return status;
}

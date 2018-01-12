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
/* Can't include ntifs.h, produces conflicts with wdm.h.
 * #include <ntifs.h> */
USHORT
NTAPI
RtlCaptureStackBackTrace(
    _In_ ULONG FramesToSkip,
    _In_ ULONG FramesToCapture,
    _Out_writes_to_(FramesToCapture, return) PVOID * BackTrace,
    _Out_opt_ PULONG BackTraceHash
    );

#include "drbd_windows.h"
#include "drbd_wingenl.h"	
#include "proto.h"

#include "linux/idr.h"
#include "drbd_int.h"
#include "drbd_wrappers.h"

#include <ntdddisk.h>

#ifdef _WIN32_WPP
#include "sub.tmh" 
#endif

NTSTATUS
mvolIrpCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	PKEVENT Event = (PKEVENT) Context;

	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
mvolRunIrpSynchronous(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS		status;
	KEVENT			event;
	PVOLUME_EXTENSION	VolumeExtension = DeviceObject->DeviceExtension;

	KeInitializeEvent(&event, NotificationEvent, FALSE);
	IoCopyCurrentIrpStackLocationToNext(Irp);
	IoSetCompletionRoutine(Irp, mvolIrpCompletion, &event, TRUE, TRUE, TRUE);
	status = IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, (PLARGE_INTEGER) NULL);
		status = Irp->IoStatus.Status;
	}

	return status;
}

VOID
mvolSyncFilterWithTarget(IN PDEVICE_OBJECT FilterDevice, IN PDEVICE_OBJECT TargetDevice)
{
	ULONG	propFlags;

	//
	// Propogate all useful flags from target to mvol. MountMgr will look
	// at the mvol object capabilities to figure out if the disk is
	// a removable and perhaps other things.
	//
	propFlags = TargetDevice->Flags & FILTER_DEVICE_PROPOGATE_FLAGS;
	FilterDevice->Flags |= propFlags;

	propFlags = TargetDevice->Characteristics & FILTER_DEVICE_PROPOGATE_CHARACTERISTICS;
	FilterDevice->Characteristics |= propFlags;
}

NTSTATUS
mvolStartDevice(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS		status;
	PVOLUME_EXTENSION	VolumeExtension = DeviceObject->DeviceExtension;

	status = mvolRunIrpSynchronous(DeviceObject, Irp);
	mvolSyncFilterWithTarget(DeviceObject, VolumeExtension->TargetDeviceObject);
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

static
enum drbd_disk_state get_disk_state2(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	enum drbd_disk_state disk_state;

	spin_lock_irq(&resource->req_lock);
	disk_state = device->disk_state[NOW];
	spin_unlock_irq(&resource->req_lock);
	return disk_state;
}

NTSTATUS
mvolRemoveDevice(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS		status;
	PVOLUME_EXTENSION	VolumeExtension = DeviceObject->DeviceExtension;

	// we should call acuire removelock before pass down irp.
	// if acuire-removelock fail, we should return fail(STATUS_DELETE_PENDING).
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		status = IoAcquireRemoveLock(&VolumeExtension->RemoveLock, NULL);
		if(!NT_SUCCESS(status)) {
			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = 0;

			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return status;
		}
	}
	
	status = mvolRunIrpSynchronous(DeviceObject, Irp);
	if (!NT_SUCCESS(status))
	{
		WDRBD_ERROR("cannot remove device, status=0x%x\n", status);
	}

	IoReleaseRemoveLockAndWait(&VolumeExtension->RemoveLock, NULL); //wait remove lock
	IoDetachDevice(VolumeExtension->TargetDeviceObject);
	IoDeleteDevice(DeviceObject);

#ifdef MULTI_WRITE_HOOKER_THREADS
	{
		int i = 0;
		for (i = 0; i < 5; i++) 
		{
			if (deviceExtension->WorkThreadInfo[i].Active)
			{
				mvolTerminateThread(&deviceExtension->WorkThreadInfo);
				WDRBD_TRACE("[%ws]: WorkThread Terminate Completely\n",
					deviceExtension->PhysicalDeviceName);
			}
		}
	}
#else
	if (VolumeExtension->WorkThreadInfo.Active)
	{
		mvolTerminateThread(&VolumeExtension->WorkThreadInfo);
		WDRBD_TRACE("[%ws]: WorkThread Terminate Completely\n",	VolumeExtension->PhysicalDeviceName);
	}
#endif

	struct drbd_device *device = get_device_with_vol_ext(VolumeExtension, FALSE);
	if (device)
	{
		if (get_disk_state2(device) >= D_INCONSISTENT)
		{
			drbd_chk_io_error(device, 1, DRBD_FORCE_DETACH);

			long timeo = 3 * HZ;
			wait_event_interruptible_timeout(timeo, device->misc_wait,
						 get_disk_state2(device) != D_FAILED, timeo);
		}			
		kref_put(&device->kref, drbd_destroy_device);
	}
		
		/* TODO: no destroy func? */
	blkdev_put(VolumeExtension->lower_dev, 0);
	blkdev_put(VolumeExtension->upper_dev, 0);

	// DW-1277: check volume type we marked when drbd attaches.
	// for normal volume.
	if (!test_bit(VOLUME_TYPE_REPL, &VolumeExtension->Flag) &&
		!test_bit(VOLUME_TYPE_META, &VolumeExtension->Flag))
	{
		WDRBD_INFO("Volume %wZ was removed\n", &VolumeExtension->MountPoint);
	}
	// for replication volume.
	if (test_and_clear_bit(VOLUME_TYPE_REPL, &VolumeExtension->Flag))
	{
		WDRBD_INFO("Replication volume %wZ was removed\n", &VolumeExtension->MountPoint);
	}
	// for meta volume.
	if (test_and_clear_bit(VOLUME_TYPE_META, &VolumeExtension->Flag))
	{
		WDRBD_INFO("Meta volume %wZ was removed\n", &VolumeExtension->MountPoint);
	}
	
	FreeUnicodeString(&VolumeExtension->MountPoint);
	FreeUnicodeString(&VolumeExtension->VolumeGuid);

	MVOL_LOCK();
	mvolDeleteDeviceList(VolumeExtension);
	MVOL_UNLOCK();
	
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS
mvolDeviceUsage(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS		status;
	PVOLUME_EXTENSION	VolumeExtension = DeviceObject->DeviceExtension;
	PDEVICE_OBJECT		attachedDeviceObject;

	attachedDeviceObject = IoGetAttachedDeviceReference(DeviceObject);
	if (attachedDeviceObject)
	{
		if (attachedDeviceObject == DeviceObject ||
			(attachedDeviceObject->Flags & DO_POWER_PAGABLE))
		{
			DeviceObject->Flags |= DO_POWER_PAGABLE;
		}
		ObDereferenceObject(attachedDeviceObject);
	}

	status = mvolRunIrpSynchronous(DeviceObject, Irp);

	if (!(VolumeExtension->TargetDeviceObject->Flags & DO_POWER_PAGABLE))
	{
		DeviceObject->Flags &= ~DO_POWER_PAGABLE;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

/* TODO: this needed? */
void bio_finished(struct bio * bio, int error) {
   PIRP irp = bio->bi_irp;

   IoCompleteRequest(irp, error ? IO_NO_INCREMENT : IO_DISK_INCREMENT);

   bio_free(bio);
}

#ifdef _WIN32_GetDiskPerf
NTSTATUS
mvolGetDiskPerf(PDEVICE_OBJECT TargetDeviceObject, PDISK_PERFORMANCE pDiskPerf)
{
	NTSTATUS					status;
	KEVENT						event;
	IO_STATUS_BLOCK				ioStatus;
	PIRP						newIrp;

	KeInitializeEvent(&event, NotificationEvent, FALSE);
	newIrp = IoBuildDeviceIoControlRequest(IOCTL_DISK_PERFORMANCE,
											TargetDeviceObject, NULL, 0,
											pDiskPerf, sizeof(DISK_PERFORMANCE),
											FALSE, &event, &ioStatus);
	if (!newIrp)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = IoCallDriver(TargetDeviceObject, newIrp);
	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, (PLARGE_INTEGER) NULL);
		status = ioStatus.Status;
	}
	return status;
}
#endif

VOID
mvolLogError(PDEVICE_OBJECT DeviceObject, ULONG UniqID, NTSTATUS ErrorCode, NTSTATUS Status)
{
	PIO_ERROR_LOG_PACKET		pLogEntry;
	PROOT_EXTENSION			RootExtension = NULL;
	PVOLUME_EXTENSION		VolumeExtension = NULL;
	PWCHAR				wp;
	USHORT				len, deviceNameLength;
	
	if( mvolRootDeviceObject == DeviceObject )
	{
		RootExtension = DeviceObject->DeviceExtension;
		deviceNameLength = RootExtension->PhysicalDeviceNameLength;
	}
	else
	{
		VolumeExtension = DeviceObject->DeviceExtension;
		deviceNameLength = VolumeExtension->PhysicalDeviceNameLength;
	}

	len = sizeof(IO_ERROR_LOG_PACKET) + deviceNameLength + 4;
	pLogEntry = (PIO_ERROR_LOG_PACKET) IoAllocateErrorLogEntry(mvolDriverObject, (UCHAR) len);
	if (pLogEntry == NULL)
	{
		WDRBD_ERROR("cannot alloc Log Entry\n");
		return;
	}
	RtlZeroMemory(pLogEntry, len);

	pLogEntry->ErrorCode = ErrorCode;
	pLogEntry->UniqueErrorValue = UniqID;
	pLogEntry->FinalStatus = Status;
	pLogEntry->DumpDataSize = 0;
	pLogEntry->NumberOfStrings = 1; // -> 1 for %2, 2 for %3...! %1 is driver obkect!
	pLogEntry->StringOffset = sizeof(IO_ERROR_LOG_PACKET) +pLogEntry->DumpDataSize;

	wp = (PWCHAR) ((PCHAR) pLogEntry + pLogEntry->StringOffset);

	if( RootExtension != NULL )
		wcscpy(wp, RootExtension->PhysicalDeviceName);
	else
		wcscpy(wp, VolumeExtension->PhysicalDeviceName);
	wp += deviceNameLength / sizeof(WCHAR);
	*wp = 0;

	IoWriteErrorLogEntry(pLogEntry);
}


#ifdef _WIN32_EVENTLOG

DWORD msgids [] = {
	PRINTK_EMERG,
	PRINTK_ALERT,
	PRINTK_CRIT,
	PRINTK_ERR,
	PRINTK_WARN,
	PRINTK_NOTICE,
	PRINTK_INFO,
	PRINTK_DBG
};

// _WIN32_MULTILINE_LOG
void save_to_system_event(char * buf, int length, int level_index)
{
	int offset = 3;
	char *p = buf + offset;
	int i = 0;

	while (offset < length)
	{
		int line_sz = WriteEventLogEntryData(msgids[level_index], 0, 0, 1, L"%S", p);
		if (line_sz > 0)
		{
			offset = offset + (line_sz / 2);
			p = buf + offset;
		}
		else
		{
			WriteEventLogEntryData(PRINTK_ERR, 0, 0, 1, L"%S", KERN_ERR "LogLink: save_to_system_event: unexpected ret\n");
			break;
		}
	}
}


/* We don't create the syslog UDP socket here, since we cannot start
 * the networking that early (Windows would wait forever for the 
 * network stack to start.
 *
 * Just our spinlock is initialized.
 */

void printk_init(void)
{
	initialize_syslog_printk();
}

void printk_cleanup(void)
{
}

static int _char_to_wchar(wchar_t * dst, size_t buf_size, char * src)
{
    char * p = src;
    wchar_t * t = dst;
    int c = 0;

    for (; *p && c < buf_size; ++c)
    {
        *t++ = (wchar_t)*p++;
    }

    return c;
}

/* TODO: still used? */
int
WriteEventLogEntryData(
	ULONG	pi_ErrorCode,
	ULONG	pi_UniqueErrorCode,
	ULONG	pi_FinalStatus,
	ULONG	pi_nDataItems,
	...
)
/*++

Routine Description:
Writes an event log entry to the event log.

Arguments:

pi_pIoObject......... The IO object ( driver object or device object ).
pi_ErrorCode......... The error code.
pi_UniqueErrorCode... A specific error code.
pi_FinalStatus....... The final status.
pi_nDataItems........ Number of data items (i.e. pairs of data parameters).
.
. data items values
.

Return Value:

None .

Reference : http://git.etherboot.org/scm/mirror/winof/hw/mlx4/kernel/bus/core/l2w_debug.c
--*/
{
	/* Variable argument list */
	va_list					l_Argptr;
	/* Pointer to an error log entry */
	PIO_ERROR_LOG_PACKET	l_pErrorLogEntry;
	/* sizeof insertion string */
	int 	l_Size = 0;
	/* temp buffer */
	UCHAR l_Buf[ERROR_LOG_MAXIMUM_SIZE - 2];
	/* position in buffer */
	UCHAR * l_Ptr = l_Buf;
	/* Data item index */
	USHORT l_nDataItem;
	/* total packet size */
	int l_TotalSize;

	if (mvolRootDeviceObject == NULL) {
		ASSERT(mvolRootDeviceObject != NULL);
		return -2;
	}

	/* Init the variable argument list */
	va_start(l_Argptr, pi_nDataItems);

	/* Create the insertion strings Insert the data items */
	memset(l_Buf, 0, sizeof(l_Buf));
	for (l_nDataItem = 0; l_nDataItem < pi_nDataItems; l_nDataItem++)
	{
		//NTSTATUS status;
		/* Current binary data item */
		int l_CurDataItem;
		/* Current pointer data item */
		void* l_CurPtrDataItem;
		/* format specifier */
		WCHAR* l_FormatStr;
		/* the rest of the buffer */
		int l_BufSize = (int) (l_Buf + sizeof(l_Buf) -l_Ptr);
		/* size of insertion string */
		size_t l_StrSize;

		/* print as much as we can */
		if (l_BufSize < 4)
			break;

		/* Get format specifier */
		l_FormatStr = va_arg(l_Argptr, PWCHAR);

        int ret = 0;
		/* Get next data item */
        if (!wcscmp(l_FormatStr, L"%S")) {
			l_CurPtrDataItem = va_arg(l_Argptr, PCHAR);
            ret = _char_to_wchar((wchar_t*)l_Ptr, l_BufSize >> 1, l_CurPtrDataItem);
		}
		else if (!wcscmp(l_FormatStr, L"%s")) {
			l_CurPtrDataItem = va_arg(l_Argptr, PWCHAR);
			/* convert to string */
			swprintf_s((wchar_t*)l_Ptr, l_BufSize >> 1, l_FormatStr, l_CurPtrDataItem);
            //status = RtlStringCchPrintfW((NTSTRSAFE_PWSTR)l_Ptr, l_BufSize >> 1, l_FormatStr, l_CurPtrDataItem);
		}
		else {
			l_CurDataItem = va_arg(l_Argptr, int);
			/* convert to string */
			swprintf_s((wchar_t*)l_Ptr, l_BufSize >> 1, l_FormatStr, l_CurDataItem);
			//status = RtlStringCchPrintfW((NTSTRSAFE_PWSTR) l_Ptr, l_BufSize >> 1, l_FormatStr, l_CurDataItem);
		}

        if (!ret)
			return -3;

		/* prepare the next loop */
        l_StrSize = wcslen((PWCHAR)l_Ptr) * sizeof(WCHAR);
		//status = RtlStringCbLengthW((NTSTRSAFE_PWSTR) l_Ptr, l_BufSize, &l_StrSize);
		//if (!NT_SUCCESS(status))
		//	return 4;
		*(WCHAR*) &l_Ptr[l_StrSize] = (WCHAR) 0;
		l_StrSize += 2;
		l_Size = l_Size + (int) l_StrSize;
		l_Ptr = l_Buf + l_Size;
		l_BufSize = (int) (l_Buf + sizeof(l_Buf) -l_Ptr);

	} /* Inset a data item */

	/* Term the variable argument list */
	va_end(l_Argptr);

	/* Allocate an error log entry */
	l_TotalSize = sizeof(IO_ERROR_LOG_PACKET) +l_Size;
	if (l_TotalSize >= ERROR_LOG_MAXIMUM_SIZE - 2) {
		l_TotalSize = ERROR_LOG_MAXIMUM_SIZE - 2;
		l_Size = l_TotalSize - sizeof(IO_ERROR_LOG_PACKET);
	}
	l_pErrorLogEntry = (PIO_ERROR_LOG_PACKET) IoAllocateErrorLogEntry(
		mvolRootDeviceObject, (UCHAR) l_TotalSize);

	/* Check allocation */
	if (l_pErrorLogEntry != NULL)
	{ /* OK */

		/* Set the error log entry header */
		l_pErrorLogEntry->ErrorCode = pi_ErrorCode;
		l_pErrorLogEntry->DumpDataSize = 0;
		l_pErrorLogEntry->SequenceNumber = 0;
		l_pErrorLogEntry->MajorFunctionCode = 0;
		l_pErrorLogEntry->IoControlCode = 0;
		l_pErrorLogEntry->RetryCount = 0;
		l_pErrorLogEntry->UniqueErrorValue = pi_UniqueErrorCode;
		l_pErrorLogEntry->FinalStatus = pi_FinalStatus;
		l_pErrorLogEntry->NumberOfStrings = l_nDataItem;
		l_pErrorLogEntry->StringOffset = sizeof(IO_ERROR_LOG_PACKET) +l_pErrorLogEntry->DumpDataSize;
		l_Ptr = (UCHAR*) l_pErrorLogEntry + l_pErrorLogEntry->StringOffset;
		if (l_Size)
			memcpy(l_Ptr, l_Buf, l_Size);

		/* Write the packet */
		IoWriteErrorLogEntry(l_pErrorLogEntry);

		return l_Size;	// _WIN32_MULTILINE_LOG test!

	} /* OK */
    return -4;
} /* WriteEventLogEntry */

NTSTATUS DeleteDriveLetterInRegistry(char letter)
{
    UNICODE_STRING reg_path, valuekey;
    wchar_t wszletter[] = L"A";

    RtlUnicodeStringInit(&reg_path, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\drbd\\volumes");

    wszletter[0] = (WCHAR)letter;
    RtlUnicodeStringInit(&valuekey, wszletter);

    return DeleteRegistryValueKey(&reg_path, &valuekey);
}

/**
* @brief   free VOLUME_EXTENSION's dev object
*/
VOID drbdFreeDev(PVOLUME_EXTENSION VolumeExtension)
{
	if (VolumeExtension == NULL || VolumeExtension->lower_dev == NULL || VolumeExtension->upper_dev == NULL) {
		return;
	}

		/* TODO: request queues? */
	if (VolumeExtension->lower_dev->bd_disk)
		kfree(VolumeExtension->lower_dev->bd_disk->queue);
	kfree(VolumeExtension->lower_dev->bd_disk);
	kfree(VolumeExtension->lower_dev);

	if (VolumeExtension->upper_dev->bd_disk)
		kfree(VolumeExtension->upper_dev->bd_disk->queue);
	kfree(VolumeExtension->upper_dev->bd_disk);
	kfree(VolumeExtension->upper_dev);
}

#ifdef _WIN32_DEBUG_OOS

static USHORT getStackFrames(PVOID *frames, USHORT usFrameCount)
{
	USHORT usCaptured = 0;

	if (NULL == frames ||
		0 == usFrameCount)
	{
		WDRBD_ERROR("Invalid Parameter, frames(%p), usFrameCount(%d)\n", frames, usFrameCount);
		return 0;
	}
	
	usCaptured = RtlCaptureStackBackTrace(2, usFrameCount, frames, NULL);	
	if (0 == usCaptured)
	{
		WDRBD_ERROR("Captured frame count is 0\n");
		return 0;
	}

	return usCaptured;	
}

// DW-1153: Write Out-of-sync trace specific log. it includes stack frame.
VOID WriteOOSTraceLog(int bitmap_index, ULONG_PTR startBit, ULONG_PTR endBit, ULONG_PTR bitsCount, enum update_sync_bits_mode mode)
{
	PVOID* stackFrames = NULL;
	USHORT frameCount = STACK_FRAME_CAPTURE_COUNT;
	CHAR buf[MAX_DRBDLOG_BUF] = { 0, };

	// getting stack frames may overload with frequent bitmap operation, just return if oos trace is disabled.
	if (FALSE == atomic_read(&g_oos_trace))
	{
		return;
	}

	sprintf(buf, "%s["OOS_TRACE_STRING"] %s %Iu bits for bitmap_index(%d), pos(%Iu ~ %Iu), sector(%Iu ~ %Iu)", KERN_DEBUG_OOS, mode == SET_IN_SYNC ? "Clear" : "Set", bitsCount, bitmap_index, startBit, endBit, BM_BIT_TO_SECT(startBit), (BM_BIT_TO_SECT(endBit) | 0x7));

	stackFrames = (PVOID*)ExAllocatePool(NonPagedPool, sizeof(PVOID) * frameCount);

	if (NULL == stackFrames)
	{
		WDRBD_ERROR("Failed to allcate pool for stackFrames\n");
		return;
	}

	frameCount = getStackFrames(stackFrames, frameCount);
		
	for (int i = 0; i < frameCount; i++)
	{
		CHAR temp[20] = { 0, };
		sprintf(temp, FRAME_DELIMITER"%p", stackFrames[i]);
		strcat(buf, temp);
	}

	strcat(buf, "\n");
	
	printk(buf);

	if (NULL != stackFrames)
	{
		ExFreePool(stackFrames);
		stackFrames = NULL;
	}
}
#endif
#endif

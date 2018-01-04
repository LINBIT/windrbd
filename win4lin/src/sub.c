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

void bio_finished(struct bio * bio, blk_status_t error) {
   PIRP irp = bio->pMasterIrp;

   /* TODO handle split-up bios! */
   IoCompleteRequest(irp, error ? IO_NO_INCREMENT : IO_DISK_INCREMENT);

   bio_free(bio);
}


int DoSplitIo(PVOLUME_EXTENSION VolumeExtension, ULONG io, PIRP upper_pirp, struct splitInfo *splitInfo,
    long split_id, long split_total_id, long split_total_length, struct drbd_device *device, PVOID buffer, LARGE_INTEGER offset, ULONG length)
{
	NTSTATUS				status;
	struct bio				*bio;
	unsigned int			nr_pages;

printk("Should not come here.\n");

	nr_pages = (length + PAGE_SIZE - 1) >> PAGE_SHIFT;
	bio = bio_alloc(GFP_NOIO, nr_pages, '75DW');
	if (!bio) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	bio->split_id = split_id;
	bio->split_total_id = split_total_id;
	bio->split_total_length = split_total_length;
	bio->splitInfo = splitInfo;
//	bio->bio_databuf = buffer;
	bio->pMasterIrp = upper_pirp; 

	bio->bi_sector = offset.QuadPart >> 9; 
	bio->bi_bdev = VolumeExtension->upper_dev;
	bio->bi_rw |= (io == IRP_MJ_WRITE) ? WRITE : READ;
	bio->bi_size = length;
	bio->bi_end_io = bio_finished;
	// save original Master Irp's Stack Flags
	bio->MasterIrpStackFlags = ((PIO_STACK_LOCATION)IoGetCurrentIrpStackLocation(upper_pirp))->Flags;
	
	drbd_make_request(device->rq_queue, bio); // drbd local I/O entry point 

	return STATUS_PENDING;
}

NTSTATUS
mvolReadWriteDevice(PVOLUME_EXTENSION VolumeExtension, PIRP Irp, ULONG Io)
{
	NTSTATUS		status = STATUS_INSUFFICIENT_RESOURCES;
	PIO_STACK_LOCATION	irpSp;
	PVOID			buffer;
	LARGE_INTEGER		offset;
	ULONG			length;
	struct drbd_device*	device = NULL;

	irpSp = IoGetCurrentIrpStackLocation(Irp);
	if (Irp->MdlAddress)
	{
		buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		if (buffer == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	else
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (Io == IRP_MJ_WRITE)
	{
		offset.QuadPart = irpSp->Parameters.Write.ByteOffset.QuadPart;
		length = irpSp->Parameters.Write.Length;
	}
	else
	{
		offset.QuadPart = irpSp->Parameters.Read.ByteOffset.QuadPart;
		length = irpSp->Parameters.Read.Length;
	}

	// DW-1300: get device and get reference.
	device = get_device_with_vol_ext(VolumeExtension, TRUE);
	if (device/* && (mdev->state.role == R_PRIMARY)*/) {
		struct splitInfo *splitInfo = 0;
		ULONG io_id = 0;
		ULONG rest, slice, loop;
		ULONG splitted_io_count;

		slice = MAX_SPLIT_BLOCK_SZ; // 1MB fixed
		loop = length / slice;
		rest = length % slice;

		if (loop == 0)
		{
			splitted_io_count = 1;
		}
		else
		{
			if (rest)
			{
				splitted_io_count = loop + 1;
			}
			else
			{
				splitted_io_count = loop;
			}

			splitInfo = kzalloc(sizeof(struct splitInfo), 0, '95DW');
			if (!splitInfo)
			{
				status = STATUS_NO_MEMORY;
				goto fail_put_dev;
			}
			splitInfo->finished = 0;
			splitInfo->LastError = STATUS_SUCCESS; 
		}

		for (io_id = 0; io_id < loop; io_id++)
		{
#ifdef _WIN32_TMP_Win8_BUG_0x1a_61946
			char *newbuf;
			if (Io == IRP_MJ_READ)
			{
				newbuf = kzalloc(slice, 0, 'A5DW');
				if (!newbuf)
				{
					status = STATUS_NO_MEMORY;
					WDRBD_ERROR("HOOKER malloc fail!!!\n");
					goto fail_put_dev;
				}
			}
			else
			{
				newbuf = buffer;
			}

			if ((status = DoSplitIo(VolumeExtension, Io, Irp, splitInfo, io_id, splitted_io_count, length, device, newbuf, offset, slice)) != 0)
#else
			if ((status = DoSplitIo(VolumeExtension, Io, Irp, splitInfo, io_id, splitted_io_count, length, device, buffer, offset, slice)))
#endif
			{
			    if (status != STATUS_PENDING)
				goto fail_put_dev;
			}

			offset.QuadPart = offset.QuadPart + slice;
			buffer = (char *) buffer + slice;
		}

		if (rest)
		{
#ifdef _WIN32_TMP_Win8_BUG_0x1a_61946
			char *newbuf;
			if (Io == IRP_MJ_READ)
			{
				newbuf = kzalloc(rest, 0, 'B5DW');
				if (!newbuf)
				{
					status = STATUS_NO_MEMORY;
					WDRBD_ERROR("HOOKER rest malloc fail!!\n");
					goto fail_put_dev;
				}
			}
			else
			{
				newbuf = buffer;
			}

			if ((status = DoSplitIo(VolumeExtension, Io, Irp, splitInfo, io_id, splitted_io_count, length, device, newbuf, offset, rest)) != 0)
#else
            if ((status = DoSplitIo(VolumeExtension, Io, Irp, splitInfo, io_id, splitted_io_count, length, device, buffer, offset, rest)))
#endif
			{
				goto fail_put_dev;
			}
		}

		return STATUS_SUCCESS;
	}
	else
	{
		status = STATUS_INVALID_DEVICE_REQUEST;
		goto fail;
	}

fail_put_dev:
	// DW-1300: failed to go through drbd engine, the irp will be completed with failed status and complete_master_bio won't be called, put reference here.
	if (device)
		kref_put(&device->kref, drbd_destroy_device);

fail:
	WDRBD_ERROR("failed. status=0x%x\n", status);
	return status;
}

/* TODO: this has moved, not needed any more */
NTSTATUS
mvolGetVolumeSize(PDEVICE_OBJECT TargetDeviceObject, PLARGE_INTEGER pVolumeSize)
{
    NTSTATUS					status;
    KEVENT						event;
    IO_STATUS_BLOCK				ioStatus;
    PIRP						newIrp;
    GET_LENGTH_INFORMATION      li;
    memset(&li, 0, sizeof(li));

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        WDRBD_ERROR("cannot run IoBuildDeviceIoControlRequest becauseof IRP(%d)\n", KeGetCurrentIrql());
    }

    newIrp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_LENGTH_INFO,
        TargetDeviceObject, NULL, 0,
        &li, sizeof(li),
        FALSE, &event, &ioStatus);
    if (!newIrp)
    {
        WDRBD_ERROR("cannot alloc new IRP\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(TargetDeviceObject, newIrp);
    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, (PLARGE_INTEGER)NULL);
        status = ioStatus.Status;
    }

    if (!NT_SUCCESS(status))
    {
        WDRBD_ERROR("cannot get volume information, err=0x%x\n", status);
        return status;
    }

    pVolumeSize->QuadPart = li.Length.QuadPart;

    return status;
}

NTSTATUS
mvolQueryMountPoint(PVOLUME_EXTENSION pvext)
{
	ULONG mplen = pvext->PhysicalDeviceNameLength + sizeof(MOUNTMGR_MOUNT_POINT);
	ULONG mpslen = 4096 * 2;

	PCHAR inbuf = kmalloc(mplen, 0, '56DW');
	PCHAR otbuf = kmalloc(mpslen, 0, '56DW');
	if (!inbuf || !otbuf) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	PMOUNTMGR_MOUNT_POINT	pmp = (PMOUNTMGR_MOUNT_POINT)inbuf;
	PMOUNTMGR_MOUNT_POINTS	pmps = (PMOUNTMGR_MOUNT_POINTS)otbuf;
	
	pmp->DeviceNameLength = pvext->PhysicalDeviceNameLength;
	pmp->DeviceNameOffset = sizeof(MOUNTMGR_MOUNT_POINT);
	RtlCopyMemory(inbuf + pmp->DeviceNameOffset,
		pvext->PhysicalDeviceName,
		pvext->PhysicalDeviceNameLength);
	
	NTSTATUS status = QueryMountPoint(pmp, mplen, pmps, &mpslen);
	if (!NT_SUCCESS(status)) {
		goto cleanup;
	}

	for (int i = 0; i < pmps->NumberOfMountPoints; i++) {

		PMOUNTMGR_MOUNT_POINT p = pmps->MountPoints + i;
		PUNICODE_STRING link = NULL;
		UNICODE_STRING name = {
			.Length = p->SymbolicLinkNameLength,
			.MaximumLength = p->SymbolicLinkNameLength,
			.Buffer = (PWCH)(otbuf + p->SymbolicLinkNameOffset) };
		
		if (MOUNTMGR_IS_DRIVE_LETTER(&name)) {
			name.Length = strlen(" :") * sizeof(WCHAR);
			name.Buffer += strlen("\\DosDevices\\");
			pvext->VolIndex = name.Buffer[0] - 'C';
			link = &pvext->MountPoint;
			FreeUnicodeString(link);
		}
		else if (MOUNTMGR_IS_VOLUME_NAME(&name)) {
			link = &pvext->VolumeGuid;
		}

		link && ucsdup(link, name.Buffer, name.Length);
	}

cleanup:
	kfree(inbuf);
	kfree(otbuf);
	
	return status;
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


/* Replaced by print-to-syslog */
#if 0
void _printk(const char * func, const char * format, ...)
{
    int ret = 0;
    va_list args;
    char* buf = NULL;
    long logcnt = 0;

    ULONG msgid = PRINTK_INFO;
    int level_index = format[1] - '0';
    int printLevel = 0;
    BOOLEAN bEventLog = FALSE;
    BOOLEAN bDbgLog = FALSE;
#ifdef _WIN32_DEBUG_OOS
    BOOLEAN bOosLog = FALSE;
#endif
    LARGE_INTEGER systemTime, localTime;
    TIME_FIELDS timeFields = {0,};
    KIRQL		oldirql;
    LONGLONG	totallogcnt = 0;
    long 		offset = 0;
    ASSERT((level_index >= 0) && (level_index < 8));

    // to write system event log.
    if (level_index <= atomic_read(&g_eventlog_lv_min))
	bEventLog = TRUE;
    // to print through debugger.
    if (level_index <= atomic_read(&g_dbglog_lv_min))
	bDbgLog = TRUE;
#ifdef _WIN32_DEBUG_OOS
    if (TRUE == atomic_read(&g_oos_trace))
	bOosLog = TRUE;
#endif

    // nothing to log.
#ifdef _WIN32_DEBUG_OOS
    if (!bEventLog && !bDbgLog && !bOosLog)
	return 0;
#else
    if (!bEventLog && !bDbgLog)
		return 0;
#endif

    logcnt = InterlockedIncrement(&gLogCnt);
    if(logcnt >= LOGBUF_MAXCNT) {
	gLogCnt = 0;
	logcnt = 0;
    }
    totallogcnt = InterlockedIncrement64(&gTotalLogCnt);

    buf = gLogBuf[logcnt];
    RtlZeroMemory(buf, MAX_DRBDLOG_BUF);
    //#define TOTALCNT_OFFSET	(9)
    //#define TIME_OFFSET		(TOTALCNT_OFFSET+24)	//"00001234 08/02/2016 13:24:13.123 "
    KeQuerySystemTime(&systemTime);
    ExSystemTimeToLocalTime(&systemTime, &localTime);

    RtlTimeToTimeFields(&localTime, &timeFields);

    offset = sprintf(buf , "%08lld %02d/%02d/%04d %02d:%02d:%02d.%03d [%s] ", 
	    totallogcnt,
	    timeFields.Month,
	    timeFields.Day,
	    timeFields.Year,
	    timeFields.Hour,
	    timeFields.Minute,
	    timeFields.Second,
	    timeFields.Milliseconds,
	    func);

#define LEVEL_OFFSET	10

    switch (level_index) {
	case KERN_EMERG_NUM: case KERN_ALERT_NUM: case KERN_CRIT_NUM: 
	    printLevel = DPFLTR_ERROR_LEVEL; memcpy(buf+offset, "WDRBD_FATA", LEVEL_OFFSET); break;
	case KERN_ERR_NUM: 
	    printLevel = DPFLTR_ERROR_LEVEL; memcpy(buf+offset, "WDRBD_ERRO", LEVEL_OFFSET); break;
	case KERN_WARNING_NUM: 
	    printLevel = DPFLTR_WARNING_LEVEL; memcpy(buf+offset, "WDRBD_WARN", LEVEL_OFFSET); break;
	case KERN_NOTICE_NUM: case KERN_INFO_NUM: 
	    printLevel = DPFLTR_INFO_LEVEL; memcpy(buf+offset, "WDRBD_INFO", LEVEL_OFFSET); break;
	case KERN_DEBUG_NUM: 
	    printLevel = DPFLTR_TRACE_LEVEL; memcpy(buf+offset, "WDRBD_TRAC", LEVEL_OFFSET); break;
	default: 
	    printLevel = DPFLTR_TRACE_LEVEL; memcpy(buf+offset, "WDRBD_UNKN", LEVEL_OFFSET); break;
    }

    va_start(args, format);
    ret = vsprintf(buf + offset + LEVEL_OFFSET, format, args); // DRBD_DOC: improve vsnprintf 
    va_end(args);

    int length = strlen(buf);
    if (length > MAX_DRBDLOG_BUF) {
	length = MAX_DRBDLOG_BUF - 1;
	buf[MAX_DRBDLOG_BUF - 1] = 0;
    } else {
	// TODO: chekc min?
    }

#ifdef _WIN32_WPP
    DoTraceMessage(TRCINFO, "%s", buf);
    WriteEventLogEntryData(msgids[level_index], 0, 0, 1, L"%S", buf);
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_INFO_LEVEL, "WDRBD_INFO: [%s] %s", func, buf);
#else

    if (bEventLog) {
	save_to_system_event(buf, length, level_index);
    }

    if (bDbgLog || bOosLog)
	DbgPrintEx(FLTR_COMPONENT, printLevel, buf);

#endif
    return 0;
}
#endif
#endif

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
#if 0
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) // DRBD_DOC: DV: skip api RtlStringCchPrintfW(PASSIVE_LEVEL)
    {
        // DRBD_DOC: you should consider to process EVENTLOG
        WDRBD_WARN("IRQL(%d) too high. Log canceled.\n", KeGetCurrentIrql());
        return 1;
    }
#endif
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


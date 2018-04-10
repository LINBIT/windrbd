/*
	Copyright(C) 2017-2018, Johannes Thoma <johannes@johannesthoma.com>
	Copyright(C) 2017-2018, LINBIT HA-Solutions GmbH  <office@linbit.com>

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

/* This file contains the handler on the windrbd device (matching the
 * /dev/drbd<n> devices in Linux). Requests to a windrbd device (such
 * as called by a CreateFile, WriteFile and the like) are handled first
 * herein and then (if neccessary) forwarded to the corresponding
 * DRBD handlers. For functions related to accessing the DRBD backing
 * devices (the 'physical' devices), see drbd_windows.c
 */

#include <wdm.h>
#include <ntddk.h>
#include <ntdddisk.h>

#include "drbd_windows.h"
#include "windrbd_device.h"
#include "drbd_int.h"
#include "drbd_wrappers.h"

static NTSTATUS windrbd_not_implemented(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	
	printk(KERN_DEBUG "DRBD device request not implemented: MajorFunction: 0x%x\n", s->MajorFunction);
	irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_NOT_IMPLEMENTED;
}

static void fill_drive_geometry(struct _DISK_GEOMETRY *g, struct block_device *dev)
{
	g->BytesPerSector = dev->bd_block_size;
	g->Cylinders.QuadPart = dev->d_size / dev->bd_block_size - WINDRBD_SECTOR_SHIFT;
	g->TracksPerCylinder = 1;
	g->SectorsPerTrack = 1;
	g->MediaType = FixedMedia;
}

static void fill_partition_info(struct _PARTITION_INFORMATION *p, struct block_device *dev)
{
	p->StartingOffset.QuadPart = 0;
	p->PartitionLength.QuadPart = dev->d_size - WINDRBD_SECTOR_SHIFT*512;
	p->HiddenSectors = 0;
	p->PartitionNumber = 1;
	p->PartitionType = PARTITION_ENTRY_UNUSED;
	p->BootIndicator = FALSE;
	p->RecognizedPartition = TRUE;
	p->RewritePartition = FALSE;
}

static void fill_partition_info_ex(struct _PARTITION_INFORMATION_EX *p, struct block_device *dev)
{
	p->PartitionStyle = PARTITION_STYLE_MBR;
	p->StartingOffset.QuadPart = 0;
	p->PartitionLength.QuadPart = dev->d_size - WINDRBD_SECTOR_SHIFT*512;
	p->PartitionNumber = 1;
	p->RewritePartition = FALSE;
	p->Mbr.PartitionType = PARTITION_EXTENDED;
	p->Mbr.BootIndicator = FALSE;
	p->Mbr.RecognizedPartition = TRUE;
	p->Mbr.HiddenSectors = 0;
}

static NTSTATUS windrbd_device_control(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct block_device *dev = device->DeviceExtension;
	if (dev == NULL) {
		printk(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status = STATUS_SUCCESS;

	switch (s->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_DISK_GET_DRIVE_GEOMETRY:
		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _DISK_GEOMETRY)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		fill_drive_geometry((struct _DISK_GEOMETRY*) irp->AssociatedIrp.SystemBuffer, dev);
		irp->IoStatus.Information = sizeof(struct _DISK_GEOMETRY);
		break;

	case IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _DISK_GEOMETRY_EX)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		struct _DISK_GEOMETRY_EX *g = irp->AssociatedIrp.SystemBuffer;
		fill_drive_geometry(&g->Geometry, dev);
		g->DiskSize.QuadPart = dev->d_size - WINDRBD_SECTOR_SHIFT*512;
		g->Data[0] = 0;

		irp->IoStatus.Information = sizeof(struct _DISK_GEOMETRY_EX);
		break;

	case IOCTL_DISK_GET_LENGTH_INFO:
		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _GET_LENGTH_INFORMATION)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		struct _GET_LENGTH_INFORMATION *l = irp->AssociatedIrp.SystemBuffer;
		l->Length.QuadPart = dev->d_size - WINDRBD_SECTOR_SHIFT*512;
		irp->IoStatus.Information = sizeof(struct _GET_LENGTH_INFORMATION);
		break;

	case IOCTL_DISK_MEDIA_REMOVAL:
		if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct _PREVENT_MEDIA_REMOVAL)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		struct _PREVENT_MEDIA_REMOVAL *r = irp->AssociatedIrp.SystemBuffer;
		printk(KERN_INFO "DRBD: Request for %slocking media\n", r->PreventMediaRemoval ? "" : "un");

		dev->mechanically_locked = r->PreventMediaRemoval;

		irp->IoStatus.Information = 0;
		break;

	case IOCTL_DISK_GET_PARTITION_INFO:
		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _PARTITION_INFORMATION)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		struct _PARTITION_INFORMATION *p = irp->AssociatedIrp.SystemBuffer;
		fill_partition_info(p, dev);
		irp->IoStatus.Information = sizeof(struct _PARTITION_INFORMATION);
		break;

	case IOCTL_DISK_GET_PARTITION_INFO_EX:
		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _PARTITION_INFORMATION_EX)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		struct _PARTITION_INFORMATION_EX *pe = irp->AssociatedIrp.SystemBuffer;
		fill_partition_info_ex(pe, dev);
		irp->IoStatus.Information = sizeof(struct _PARTITION_INFORMATION_EX);
		break;

	case IOCTL_DISK_SET_PARTITION_INFO:
		if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct _SET_PARTITION_INFORMATION)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		struct _SET_PARTITION_INFORMATION *pi = irp->AssociatedIrp.SystemBuffer;
		printk(KERN_INFO "Request to set partition type to %x\n", pi->PartitionType);
		irp->IoStatus.Information = 0;
		break;

	case IOCTL_DISK_IS_WRITABLE:
		break;	/* just return without error */

	case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
printk("karin IOCTL_MOUNTDEV_QUERY_DEVICE_NAME\n");
		int length = dev->path_to_device.Length * sizeof(WCHAR);
		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _MOUNTDEV_NAME) + length) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		struct _MOUNTDEV_NAME *name = irp->AssociatedIrp.SystemBuffer;

		name->NameLength = length;
		RtlCopyMemory(name->Name, dev->path_to_device.Buffer, length);

		irp->IoStatus.Information = length + sizeof(struct _MOUNTDEV_NAME);
		break;

	default: 
		printk(KERN_DEBUG "DRBD IoCtl request not implemented: IoControlCode: 0x%x\n", s->Parameters.DeviceIoControl.IoControlCode);
		status = STATUS_NOT_IMPLEMENTED;
	}

	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
}

static NTSTATUS windrbd_create(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct block_device *dev = device->DeviceExtension;
	if (dev == NULL) {
		printk(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	int mode;
	NTSTATUS status;
	int err;

printk(KERN_DEBUG "s->Parameters.Create.SecurityContext->DesiredAccess is %x\n", s->Parameters.Create.SecurityContext->DesiredAccess);

	mode = (s->Parameters.Create.SecurityContext->DesiredAccess &
                (FILE_WRITE_DATA  | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_APPEND_DATA | GENERIC_WRITE)) ? FMODE_WRITE : 0;

	printk(KERN_INFO "DRBD device create request: opening DRBD device %s\n",
		mode == 0 ? "read-only" : "read-write");

	err = drbd_open(dev, mode);
printk(KERN_DEBUG "drbd_open returned %d\n", err);
	if (err == -EMEDIUMTYPE) {
		printk(KERN_DEBUG "-EMEDIUMTYPE error ignored on drbd_open()\n");
		err = 0;
	}
	status = (err < 0) ? STATUS_INVALID_DEVICE_REQUEST : STATUS_SUCCESS;

	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
printk(KERN_DEBUG "status is %x\n", status);
	return status;
}


static NTSTATUS windrbd_close(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct block_device *dev = device->DeviceExtension;
	if (dev == NULL) {
		printk(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	int mode;
	NTSTATUS status;
	int err;

	mode = 0;	/* TODO: remember mode from open () */
/*	mode = (s->Parameters.Create.SecurityContext->DesiredAccess &
                (FILE_WRITE_DATA  | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_APPEND_DATA | GENERIC_WRITE)) ? FMODE_WRITE : 0; */

	printk(KERN_INFO "DRBD device close request: releasing DRBD device %s\n",
		mode == 0 ? "read-only" : "read-write");

	err = dev->bd_disk->fops->release(dev->bd_disk, mode);
printk(KERN_DEBUG "drbd_release returned %d\n", err);
	status = (err < 0) ? STATUS_INVALID_DEVICE_REQUEST : STATUS_SUCCESS;

	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

static NTSTATUS windrbd_cleanup(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct block_device *dev = device->DeviceExtension;
	if (dev == NULL) {
		printk(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	NTSTATUS status = STATUS_SUCCESS;

printk(KERN_INFO "Pretending that cleanup does something.\n");
	/* TODO: call this: */
/*        drbd_cleanup_by_win_shutdown(VolumeExtension); */

	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

static void windrbd_bio_finished(struct bio * bio, int error)
{
	PIRP irp = bio->bi_upper_irp;

	if (error == 0) {
		if (bio->bi_rw == READ) {
			if (bio->bi_upper_irp && bio->bi_upper_irp->MdlAddress) {
				void *user_buffer = MmGetSystemAddressForMdlSafe(bio->bi_upper_irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
				if (user_buffer != NULL)
					RtlCopyMemory(user_buffer, bio->bi_io_vec[0].bv_page->addr, bio->bi_io_vec[0].bv_len);
				else
					printk("MmGetSystemAddressForMdlSafe returned NULL\n");

				kfree(bio->bi_io_vec[0].bv_page->addr);
			}
		}
		irp->IoStatus.Information = bio->bi_size;
		irp->IoStatus.Status = STATUS_SUCCESS;
	} else {
		printk(KERN_ERR "I/O failed with %d\n", error);
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	}
	IoCompleteRequest(irp, error ? IO_NO_INCREMENT : IO_DISK_INCREMENT);

	bio_put(bio);
}

static int irp_to_bio(struct _IRP *irp, struct block_device *dev, struct bio *bio)
{
	/* TODO: use bio_alloc(), bio_add_page and the like */
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	struct _MDL *mdl = irp->MdlAddress;

	if (s == NULL) {
		printk("Stacklocation is NULL.\n");
		return -1;
	}
	if (mdl == NULL) {
		printk("MdlAddress is NULL.\n");
		return -1;
	}

		/* TODO: FLUSH? */
	bio->bi_rw |= (s->MajorFunction == IRP_MJ_WRITE) ? WRITE : READ;
/* TODO: Parameters.Write if IRP_MD_WRITE */
	bio->bi_size = s->Parameters.Read.Length;
	bio->bi_sector = (s->Parameters.Read.ByteOffset.QuadPart) / dev->bd_block_size + WINDRBD_SECTOR_SHIFT;
	bio->bi_bdev = dev;
	bio->bi_max_vecs = 1;
	bio->bi_vcnt = 1;

	/* TODO: later have more than one .. */
	if (mdl->Next != NULL) {
		printk(KERN_ERR "not implemented: have more than one mdl. Dropping additional mdl data.\n");
		return -1;
	}
	bio->bi_io_vec[0].bv_page = kmalloc(sizeof(struct page), 0, 'DRBD');
	if (bio->bi_io_vec[0].bv_page == NULL) {
		printk("Page is NULL.\n");
		return -1;
	}

/* TODO: eventually we want to make READ requests work without the
	 intermediate buffer and the extra copy.
*/
//	MmBuildMdlForNonPagedPool(mdl);
/*
	MmProbeAndLockPages(mdl, UserMode,
		(s->MajorFunction == IRP_MJ_WRITE) ? IoReadAccess : IoWriteAccess);
*/

	bio->bi_io_vec[0].bv_len = MmGetMdlByteCount(mdl);
	if (bio->bi_rw == READ) {
		bio->bi_io_vec[0].bv_page->addr = kmalloc(bio->bi_io_vec[0].bv_len, 0, 'DRBD');
	} else {
		/* This is not page aligned. */
		bio->bi_io_vec[0].bv_page->addr = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
		bio->bi_paged_memory = true;
	}
	if (bio->bi_io_vec[0].bv_page->addr == NULL) {
		printk("MmGetSystemAddressForMdlSafe returned NULL.\n");
		return -1;
			/* TODO: Here we get a blue screen sooner or later */
	}
		/* Address returned by MmGetSystemAddressForMdlSafe
		 * is already offset, not using MmGetMdlByteOffset.
		 */
	bio->bi_io_vec[0].bv_offset = 0;

// printk("bio->bi_io_vec[0].bv_page->addr: %p bio->bi_io_vec[0].bv_len: %d\n", bio->bi_io_vec[0].bv_page->addr, bio->bi_io_vec[0].bv_len);

	bio->bi_end_io = windrbd_bio_finished;
	bio->bi_upper_irp = irp;

/* printk("bio: %p bio->bi_io_vec[0].bv_page->addr: %p bio->bi_io_vec[0].bv_len: %d bio->bi_io_vec[0].bv_offset: %d\n", bio, bio->bi_io_vec[0].bv_page->addr, bio->bi_io_vec[0].bv_len, bio->bi_io_vec[0].bv_offset); */

	return 0;
}

static NTSTATUS windrbd_io(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct block_device *dev = device->DeviceExtension;
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	if (dev == NULL) {
		printk(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		goto exit;
	}
	struct bio *bio;

	if (dev->drbd_device->resource->role[NOW] != R_PRIMARY) {
printk("I/O request while not primary.\n");
		goto exit;
	}
		/* TODO: can serve read requests from peer */
	if (dev->drbd_device->disk_state[NOW] <= D_FAILED) {
printk("I/O request on a failed disk.\n");
		goto exit;
	}

	bio = bio_alloc(GFP_NOIO, 1, 'DBRD');
	if (bio == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto exit;
	}
	if (irp_to_bio(irp, dev, bio) < 0) {
		bio_free(bio);
		goto exit;
	}
        IoMarkIrpPending(irp);
	drbd_make_request(dev->drbd_device->rq_queue, bio);

	return STATUS_PENDING;

exit:
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
}

static NTSTATUS windrbd_shutdown(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	printk("System shutdown, for now, don't clean up, there might be DRBD resources online\nin which case we would crash the system.\n");

	printk("device: %p irp: %p\n", device, irp);
#if 0
	if (device == mvolRootDeviceObject)
		drbd_cleanup();

/* TODO: clean up logging. */
#endif

	irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
}

static NTSTATUS windrbd_flush(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct block_device *dev = device->DeviceExtension;
	struct bio *bio;
	NTSTATUS status;

	bio = bio_alloc(GFP_NOIO, 0, 'DBRD');
	if (bio == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto exit;
	}
	bio->bi_rw = WRITE | DRBD_REQ_PREFLUSH;
	bio->bi_size = 0;
	bio->bi_end_io = windrbd_bio_finished;
	bio->bi_upper_irp = irp;
	bio->bi_bdev = dev;

        IoMarkIrpPending(irp);
	drbd_make_request(dev->drbd_device->rq_queue, bio);
		/* The irp may be already invalid here. */
	return STATUS_PENDING;

exit:
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
}

void windrbd_set_major_functions(struct _DRIVER_OBJECT *obj)
{
	int i;
	NTSTATUS status;

	for (i=0; i<IRP_MJ_MAXIMUM_FUNCTION; i++)
		obj->MajorFunction[i] = windrbd_not_implemented;

	obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = windrbd_device_control;
	obj->MajorFunction[IRP_MJ_READ] = windrbd_io;
	obj->MajorFunction[IRP_MJ_WRITE] = windrbd_io;
	obj->MajorFunction[IRP_MJ_CREATE] = windrbd_create;
	obj->MajorFunction[IRP_MJ_CLOSE] = windrbd_close;
	obj->MajorFunction[IRP_MJ_CLEANUP] = windrbd_cleanup;
	obj->MajorFunction[IRP_MJ_SHUTDOWN] = windrbd_shutdown;
	obj->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = windrbd_flush;

	status = IoRegisterShutdownNotification(mvolRootDeviceObject);
	if (status != STATUS_SUCCESS) {
		printk("Could not register shutdown notification.\n");
	}
}

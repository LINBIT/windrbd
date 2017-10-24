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
	g->Cylinders.QuadPart = dev->d_size / dev->bd_block_size;
	g->TracksPerCylinder = 1;
	g->SectorsPerTrack = 1;
	g->MediaType = FixedMedia;
}

static NTSTATUS windrbd_device_control(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	struct block_device *dev = device->DeviceExtension;
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
		g->DiskSize.QuadPart = dev->d_size;
		g->Data[0] = 0;

		irp->IoStatus.Information = sizeof(struct _DISK_GEOMETRY_EX);
		break;

	case IOCTL_DISK_GET_LENGTH_INFO:
		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _GET_LENGTH_INFORMATION)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		struct _GET_LENGTH_INFORMATION *l = irp->AssociatedIrp.SystemBuffer;
		l->Length.QuadPart = dev->d_size;
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

	default: 
		printk(KERN_DEBUG "DRBD IoCtl request not implemented: IoControlCode: 0x%x\n", s->Parameters.DeviceIoControl.IoControlCode);
		status = STATUS_NOT_IMPLEMENTED;
	}

	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
}

static void windrbd_bio_finished(struct bio * bio, blk_status_t error)
{
	PIRP irp = bio->pMasterIrp;

	printk("1\n");

	IoCompleteRequest(irp, error ? IO_NO_INCREMENT : IO_DISK_INCREMENT);
	printk("2\n");
	complete(&bio->completion);

//	bio_free(bio);
	printk("3\n");
}



static int irp_to_bio(struct _IRP *irp, struct block_device *dev, struct bio *bio)
{
printk("1\n");
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

printk("2\n");
		/* TODO: FLUSH? */
	bio->bi_rw |= (s->MajorFunction == IRP_MJ_WRITE) ? WRITE : READ;
	bio->bi_size = s->Parameters.Read.Length;
	bio->bi_sector = s->Parameters.Read.ByteOffset.QuadPart / dev->bd_block_size;
printk("3\n");
	bio->bi_bdev = dev;
	bio->bi_max_vecs = 1;
	bio->bi_vcnt = 0;  /* just for now .. */

printk("4\n");
	/* TODO: later have more than one .. */
	if (mdl->Next != NULL) {
		printk("not implemented: have more than one mdl\n");
	}
printk("5\n");
	bio->bi_io_vec[0].bv_page = kmalloc(sizeof(struct page), 0, 'DRBD');
	if (bio->bi_io_vec[0].bv_page == NULL) {
		printk("Page is NULL.\n");
		return -1;
	}
	bio->bi_io_vec[0].bv_page->addr = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
printk("a\n");
	bio->bi_io_vec[0].bv_len = MmGetMdlByteCount(mdl);
printk("b\n");
	bio->bi_io_vec[0].bv_offset = MmGetMdlByteOffset(mdl);
printk("c\n");

	bio->bio_databuf = bio->bi_io_vec[0].bv_page->addr;
//	bio->bio_databuf = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
	bio->bi_end_io = windrbd_bio_finished;
	bio->pMasterIrp = irp;
	init_completion(&bio->completion);

printk("6\n");

	return 0;
}

static NTSTATUS windrbd_io(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct block_device *dev = device->DeviceExtension;
	struct bio *bio;
	NTSTATUS status = STATUS_SUCCESS;

printk("1\n");

	bio = bio_alloc(GFP_NOIO, 1, 'DBRD');
printk("2\n");
	if (bio == NULL) {
printk("3\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto exit;
	}
printk("4\n");
	if (irp_to_bio(irp, dev, bio) < 0) {
printk("5\n");
		bio_free(bio);
		status = STATUS_INVALID_DEVICE_REQUEST;
		goto exit;
	}
printk("6\n");
	drbd_make_request(dev->drbd_device->rq_queue, bio);
printk("7\n");
	wait_for_completion(&bio->completion);
printk("x\n");

/*        IoMarkIrpPending(irp);

	return STATUS_PENDING; */
	return STATUS_SUCCESS;

exit:
printk("8\n");
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
printk("9\n");
        return status;
}

void windrbd_set_major_functions(struct _DRIVER_OBJECT *obj)
{
	int i;

	for (i=0; i<IRP_MJ_MAXIMUM_FUNCTION; i++)
		obj->MajorFunction[i] = windrbd_not_implemented;

	obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = windrbd_device_control;
	obj->MajorFunction[IRP_MJ_READ] = windrbd_io;
	obj->MajorFunction[IRP_MJ_WRITE] = windrbd_io;

}

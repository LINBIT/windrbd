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
#include <wdmguid.h>
#include <srb.h>
#include <scsi.h>
#include <ntddscsi.h>
#include <ntddstor.h>

/* Uncomment this if you want more debug output (disable for releases) */
#define DEBUG 1

#include "drbd_windows.h"
#include "windrbd_device.h"
#include "windrbd_ioctl.h"
#include "drbd_int.h"
#include "drbd_wrappers.h"

/* TODO: return STATUS_NO_MEMORY instead of STATUS_INSUFFICIENT_RESOURCES
 * whereever a kmalloc() fails.
 */

static NTSTATUS windrbd_not_implemented(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);

	if (device == mvolRootDeviceObject) {
		dbg(KERN_DEBUG "DRBD root device request not implemented: MajorFunction: 0x%x\n", s->MajorFunction);

		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	dbg(KERN_DEBUG "DRBD device request not implemented: MajorFunction: 0x%x\n", s->MajorFunction);
	irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS wait_for_becoming_primary(struct block_device *bdev)
{
/* TODO: windrbd_bdget/windrbd_bdput */
#if 0
	NTSTATUS status;

printk("waiting for becoming primary...\n");
	status = KeWaitForSingleObject(&bdev->primary_event, Executive, KernelMode, FALSE, NULL);
	if (status != STATUS_SUCCESS)
		printk("KeWaitForSingleObject returned %x\n", status);
	else
		printk("Am Primary now, proceeding with I/O request\n");

	return status;
#else
	printk("NOT waiting for becoming primary.\n");
	return STATUS_SUCCESS;
#endif
}

static void fill_drive_geometry(struct _DISK_GEOMETRY *g, struct block_device *dev)
{
	g->BytesPerSector = dev->bd_block_size;
	g->Cylinders.QuadPart = dev->d_size / dev->bd_block_size;
	g->TracksPerCylinder = 1;
	g->SectorsPerTrack = 1;
	g->MediaType = FixedMedia;
}

static void fill_partition_info(struct _PARTITION_INFORMATION *p, struct block_device *dev)
{
	p->StartingOffset.QuadPart = 0;
	p->PartitionLength.QuadPart = dev->d_size;
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
	p->PartitionLength.QuadPart = dev->d_size;
	p->PartitionNumber = 1;
	p->RewritePartition = FALSE;
	p->Mbr.PartitionType = PARTITION_EXTENDED;
	p->Mbr.BootIndicator = FALSE;
	p->Mbr.RecognizedPartition = TRUE;
	p->Mbr.HiddenSectors = 0;
}

static NTSTATUS put_string(const char *s, struct _IO_STACK_LOCATION *sl, struct _IRP *irp)
{
	size_t len;

	if (s == NULL)
		return STATUS_INTERNAL_ERROR;

	len = strlen(s);
	if (sl->Parameters.DeviceIoControl.OutputBufferLength < len+1)
		return STATUS_BUFFER_TOO_SMALL;

	strcpy(irp->AssociatedIrp.SystemBuffer, s);
	irp->IoStatus.Information = len+1;

	return STATUS_SUCCESS;
}

static NTSTATUS windrbd_root_device_control(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status = STATUS_SUCCESS;

	switch (s->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_WINDRBD_ROOT_IS_WINDRBD_ROOT_DEVICE:
		break;	/* just return success */

	case IOCTL_WINDRBD_ROOT_INJECT_FAULTS:
		if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct windrbd_ioctl_fault_injection)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		struct windrbd_ioctl_fault_injection *inj = irp->AssociatedIrp.SystemBuffer;
		if (windrbd_inject_faults(inj->after, inj->where, NULL) < 0)
			status = STATUS_INVALID_DEVICE_REQUEST;

		irp->IoStatus.Information = 0;
		break;

	case IOCTL_WINDRBD_ROOT_SEND_NL_PACKET:
		size_t in_bytes = s->Parameters.DeviceIoControl.InputBufferLength;

		if (in_bytes > NLMSG_GOODSIZE) {
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		int err = windrbd_process_netlink_packet(irp->AssociatedIrp.SystemBuffer, in_bytes);
		irp->IoStatus.Information = 0;

		if (err != 0) /* TODO: sure? */
			status = STATUS_INVALID_DEVICE_REQUEST;
		else
			status = STATUS_SUCCESS;

		break;

	case IOCTL_WINDRBD_ROOT_RECEIVE_NL_PACKET:
		size_t out_max_bytes = s->Parameters.DeviceIoControl.OutputBufferLength;
		size_t bytes_returned;
		u32 portid;

		if (s->Parameters.DeviceIoControl.InputBufferLength != sizeof(struct windrbd_ioctl_genl_portid)) {
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		portid = ((struct windrbd_ioctl_genl_portid*) irp->AssociatedIrp.SystemBuffer)->portid;

		bytes_returned = windrbd_receive_netlink_packets(irp->AssociatedIrp.SystemBuffer, out_max_bytes, portid);

			/* may be 0, if there is no data */
		irp->IoStatus.Information = bytes_returned;
		status = STATUS_SUCCESS;
		break;

	case IOCTL_WINDRBD_ROOT_JOIN_MC_GROUP:
		if (s->Parameters.DeviceIoControl.InputBufferLength != sizeof(struct windrbd_ioctl_genl_portid_and_multicast_group)) {
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		struct windrbd_ioctl_genl_portid_and_multicast_group *m;
		m = (struct windrbd_ioctl_genl_portid_and_multicast_group*) irp->AssociatedIrp.SystemBuffer;

		if (windrbd_join_multicast_group(m->portid, m->name, s->FileObject) < 0)
			status = STATUS_INSUFFICIENT_RESOURCES;

		irp->IoStatus.Information = 0;
		break;

	case IOCTL_WINDRBD_ROOT_RECEIVE_USERMODE_HELPER:
		size_t bytes_returned2;
		size_t out_max_bytes2 = s->Parameters.DeviceIoControl.OutputBufferLength;
		int ret;

		ret = windrbd_um_get_next_request(irp->AssociatedIrp.SystemBuffer, out_max_bytes2, &bytes_returned2);

		if (ret == -EINVAL)
			status = STATUS_BUFFER_TOO_SMALL;

		irp->IoStatus.Information = bytes_returned2;
		break;

	case IOCTL_WINDRBD_ROOT_SEND_USERMODE_HELPER_RETURN_VALUE:
		if (s->Parameters.DeviceIoControl.InputBufferLength != sizeof(struct windrbd_usermode_helper_return_value)) {
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
			/* TODO: retval? */
		windrbd_um_return_return_value(irp->AssociatedIrp.SystemBuffer);

		irp->IoStatus.Information = 0;
		break;

	case IOCTL_WINDRBD_ROOT_SET_MOUNT_POINT_FOR_MINOR:
		if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct windrbd_minor_mount_point)) {
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		struct windrbd_minor_mount_point *mp =
			(struct windrbd_minor_mount_point*) irp->AssociatedIrp.SystemBuffer;

		switch (windrbd_set_mount_point_for_minor_utf16(mp->minor, mp->mount_point)) {
		case -EBUSY:
			status = STATUS_DEVICE_BUSY;
			break;

		case -ENOMEM:
			status = STATUS_NO_MEMORY;
			break;

		case 0:
			break;

		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
		}

		irp->IoStatus.Information = 0;
		break;

	case IOCTL_WINDRBD_ROOT_GET_DRBD_VERSION:
		status = put_string(REL_VERSION, s, irp);
		break;

	case IOCTL_WINDRBD_ROOT_GET_WINDRBD_VERSION:
		status = put_string(drbd_buildtag(), s, irp);
		break;

	case IOCTL_WINDRBD_ROOT_DUMP_ALLOCATED_MEMORY:
		if (dump_memory_allocations(0) != 0)
			status = STATUS_INVALID_DEVICE_REQUEST;
		break;

	default:
		dbg(KERN_DEBUG "DRBD IoCtl request not implemented: IoControlCode: 0x%x\n", s->Parameters.DeviceIoControl.IoControlCode);
		status = STATUS_INVALID_DEVICE_REQUEST;
	}

	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

static NTSTATUS windrbd_device_control(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
printk("1\n");
	if (device == mvolRootDeviceObject)
		return windrbd_root_device_control(device, irp);

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == (void*) -1 || ref == NULL || ref->bdev == NULL) {
		printk(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
		irp->IoStatus.Information = 0;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_SUCH_DEVICE;
	}

	struct block_device *dev = ref->bdev;
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status = STATUS_SUCCESS;

	status = wait_for_becoming_primary(dev);
	if (status != STATUS_SUCCESS)
		goto out;

printk("ioctl is %x\n", s->Parameters.DeviceIoControl.IoControlCode);

	switch (s->Parameters.DeviceIoControl.IoControlCode) {
		/* custom WINDRBD ioctl's */
	case IOCTL_WINDRBD_IS_WINDRBD_DEVICE:
		break;	/* just return success */

	case IOCTL_WINDRBD_INJECT_FAULTS:
		if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct windrbd_ioctl_fault_injection)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		struct windrbd_ioctl_fault_injection *inj = irp->AssociatedIrp.SystemBuffer;
		if (windrbd_inject_faults(inj->after, inj->where, dev) < 0)
			status = STATUS_DEVICE_DOES_NOT_EXIST;

		irp->IoStatus.Information = 0;
		break;

		/* ioctls defined for block devices (some of them) */
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
		dbg(KERN_INFO "DRBD: Request for %slocking media\n", r->PreventMediaRemoval ? "" : "un");

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
		dbg(KERN_INFO "Request to set partition type to %x\n", pi->PartitionType);
		irp->IoStatus.Information = 0;
		break;

	case IOCTL_DISK_IS_WRITABLE:
		break;	/* just return without error */

#if 0
	case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
	{
		int length = dev->path_to_device.Length;
		struct _MOUNTDEV_NAME *name = irp->AssociatedIrp.SystemBuffer;
		int total_length = sizeof(struct _MOUNTDEV_NAME) - sizeof(name->Name) + length + sizeof(name->Name[0]);

		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _MOUNTDEV_NAME) - sizeof(name->Name)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		name->NameLength = length;
		if (s->Parameters.DeviceIoControl.OutputBufferLength < total_length) {
				/* Fill in only length, so mount manager knows
				 * how much space we need. */
			irp->IoStatus.Information = sizeof(struct _MOUNTDEV_NAME);
			status = STATUS_BUFFER_OVERFLOW;
			break;
		}
		RtlCopyMemory(name->Name, dev->path_to_device.Buffer, length);
		name->Name[length / sizeof(name->Name[0])] = 0;

		irp->IoStatus.Information = total_length;
		break;
	}

	case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
	{
		int length = dev->mount_point.Length;
		struct _MOUNTDEV_SUGGESTED_LINK_NAME *mount_point = irp->AssociatedIrp.SystemBuffer;
		int total_length = sizeof(struct _MOUNTDEV_SUGGESTED_LINK_NAME) - sizeof(mount_point->Name) + length + sizeof(mount_point->Name[0]);

		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _MOUNTDEV_SUGGESTED_LINK_NAME) - sizeof(mount_point->Name)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		mount_point->UseOnlyIfThereAreNoOtherLinks = FALSE;
		mount_point->NameLength = length;
		if (s->Parameters.DeviceIoControl.OutputBufferLength < total_length) {
				/* Fill in only length, so mount manager knows
				 * how much space we need. */
			irp->IoStatus.Information = sizeof(struct _MOUNTDEV_SUGGESTED_LINK_NAME);
			status = STATUS_BUFFER_OVERFLOW;
			break;
		}
		RtlCopyMemory(mount_point->Name, dev->mount_point.Buffer, length);
		mount_point->Name[length / sizeof(mount_point->Name[0])] = 0;

		irp->IoStatus.Information = total_length;
		break;
	}

	case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
	{
		char guid[64];
			/* generated by https://www.guidgen.com */
		status = RtlStringCbPrintfA(guid, sizeof(guid)-1, "b71d%04x-0aac-47f4-b6df-223a1c73eb2e", dev->minor);

		if (status != STATUS_SUCCESS)
			break;

		int length = strlen(guid);
		struct _MOUNTDEV_UNIQUE_ID *id = irp->AssociatedIrp.SystemBuffer;
		int total_length = sizeof(struct _MOUNTDEV_UNIQUE_ID) - sizeof(id->UniqueId) + length + sizeof(id->UniqueId[0]);

		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _MOUNTDEV_UNIQUE_ID) - sizeof(id->UniqueId)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		id->UniqueIdLength = length;
		if (s->Parameters.DeviceIoControl.OutputBufferLength < total_length) {
				/* Fill in only length, so mount manager knows
				 * how much space we need. */
			irp->IoStatus.Information = sizeof(struct _MOUNTDEV_UNIQUE_ID);
			status = STATUS_BUFFER_OVERFLOW;
			break;
		}
		RtlCopyMemory(id->UniqueId, guid, length);
		id->UniqueId[length] = 0;

		irp->IoStatus.Information = total_length;
		break;
	}
#endif

	case IOCTL_STORAGE_GET_HOTPLUG_INFO:
		struct _STORAGE_HOTPLUG_INFO *hotplug_info = 
			irp->AssociatedIrp.SystemBuffer;

		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _STORAGE_HOTPLUG_INFO)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		hotplug_info->Size = sizeof(struct _STORAGE_HOTPLUG_INFO);
			/* TODO: makes no difference for FAT, ... */
		hotplug_info->MediaRemovable = TRUE;
		hotplug_info->MediaHotplug = TRUE;
		hotplug_info->DeviceHotplug = TRUE;
/*		hotplug_info->MediaRemovable = FALSE;
		hotplug_info->MediaHotplug = FALSE;
		hotplug_info->DeviceHotplug = FALSE; */
		hotplug_info->WriteCacheEnableOverride = FALSE;
		
		irp->IoStatus.Information = sizeof(struct _STORAGE_HOTPLUG_INFO);
		status = STATUS_SUCCESS;
		break;

    case IOCTL_STORAGE_QUERY_PROPERTY:
    {
      PSTORAGE_PROPERTY_QUERY StoragePropertyQuery = irp->AssociatedIrp.SystemBuffer;
      status = STATUS_INVALID_PARAMETER;
      size_t CopySize;
      STORAGE_ADAPTER_DESCRIPTOR StorageAdapterDescriptor;
      STORAGE_DEVICE_DESCRIPTOR StorageDeviceDescriptor;

printk("got IOCTL_STORAGE_QUERY_PROPERTY ...\n");

      if (StoragePropertyQuery->PropertyId == StorageAdapterProperty && StoragePropertyQuery->QueryType == PropertyStandardQuery) {
        CopySize = (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(STORAGE_ADAPTER_DESCRIPTOR)?s->Parameters.DeviceIoControl.OutputBufferLength:sizeof(STORAGE_ADAPTER_DESCRIPTOR));
        StorageAdapterDescriptor.Version = sizeof(STORAGE_ADAPTER_DESCRIPTOR);
        StorageAdapterDescriptor.Size = sizeof(STORAGE_ADAPTER_DESCRIPTOR);
        StorageAdapterDescriptor.MaximumTransferLength = 1024*1024; // SECTORSIZE * DeviceExtension->Disk.MaxSectorsPerPacket;
//        StorageAdapterDescriptor.MaximumTransferLength = SECTORSIZE * POOLSIZE;
        StorageAdapterDescriptor.MaximumPhysicalPages = (ULONG)-1;
        StorageAdapterDescriptor.AlignmentMask = 0;
        StorageAdapterDescriptor.AdapterUsesPio = TRUE;
        StorageAdapterDescriptor.AdapterScansDown = FALSE;
        StorageAdapterDescriptor.CommandQueueing = FALSE;
        StorageAdapterDescriptor.AcceleratedTransfer = FALSE;
        StorageAdapterDescriptor.BusType = BusTypeScsi;
        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &StorageAdapterDescriptor, CopySize);
        irp->IoStatus.Information = (ULONG_PTR)CopySize;
        status = STATUS_SUCCESS;
      }
      if (StoragePropertyQuery->PropertyId == StorageDeviceProperty && StoragePropertyQuery->QueryType == PropertyStandardQuery) {
        CopySize = (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(STORAGE_DEVICE_DESCRIPTOR)?s->Parameters.DeviceIoControl.OutputBufferLength:sizeof(STORAGE_DEVICE_DESCRIPTOR));
        StorageDeviceDescriptor.Version = sizeof(STORAGE_DEVICE_DESCRIPTOR);
        StorageDeviceDescriptor.Size = sizeof(STORAGE_DEVICE_DESCRIPTOR);
        StorageDeviceDescriptor.DeviceType = DIRECT_ACCESS_DEVICE;
        StorageDeviceDescriptor.DeviceTypeModifier = 0;
        StorageDeviceDescriptor.RemovableMedia = FALSE;
        StorageDeviceDescriptor.CommandQueueing = FALSE;
        StorageDeviceDescriptor.VendorIdOffset = 0;
        StorageDeviceDescriptor.ProductIdOffset = 0;
        StorageDeviceDescriptor.ProductRevisionOffset = 0;
        StorageDeviceDescriptor.SerialNumberOffset = 0;
        StorageDeviceDescriptor.BusType = BusTypeScsi;
        StorageDeviceDescriptor.RawPropertiesLength = 0;
        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &StorageDeviceDescriptor, CopySize);
        irp->IoStatus.Information = (ULONG_PTR)CopySize;
        status = STATUS_SUCCESS;
      }
      if (status == STATUS_INVALID_PARAMETER) {
printk("Invalid IOCTL_STORAGE_QUERY_PROPERTY (PropertyId: %08x / QueryType: %08x)!!\n", StoragePropertyQuery->PropertyId, StoragePropertyQuery->QueryType);
      }
      break;
   }
   case IOCTL_SCSI_GET_ADDRESS:
   {
      printk("got IOCTL_SCSI_GET_ADDRESS\n");
      size_t CopySize = (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SCSI_ADDRESS)?s->Parameters.DeviceIoControl.OutputBufferLength:sizeof(SCSI_ADDRESS));
      SCSI_ADDRESS ScsiAdress;

      ScsiAdress.Length = sizeof(SCSI_ADDRESS);
      ScsiAdress.PortNumber = 0;
      ScsiAdress.PathId = 0;
      ScsiAdress.TargetId = dev->minor;	/* TODO: only lowest 8 bit */
      ScsiAdress.Lun = 0;
      RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &ScsiAdress, CopySize);
      irp->IoStatus.Information = (ULONG_PTR)CopySize;
      status = STATUS_SUCCESS;
      break;
   }

/*
	case IOCTL_STORAGE_QUERY_PROPERTY:
		struct _STORAGE_PROPERTY_QUERY *query =
			irp->AssociatedIrp.SystemBuffer;

		if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct _STORAGE_PROPERTY_QUERY)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		dbg("IOCTL_STORAGE_QUERY_PROPERTY: PropertyId: %d QueryType: %d\n", query->PropertyId, query->QueryType);
		status = STATUS_NOT_IMPLEMENTED;
		break;
*/

	case IOCTL_DISK_CHECK_VERIFY:
	case IOCTL_STORAGE_CHECK_VERIFY:
	case IOCTL_STORAGE_CHECK_VERIFY2:
		dbg("CHECK_VERIFY (%x)\n", s->Parameters.DeviceIoControl.IoControlCode);
		if (s->Parameters.DeviceIoControl.OutputBufferLength >=
			sizeof(ULONG))
		{
			*(PULONG)irp->AssociatedIrp.SystemBuffer = 0;
			irp->IoStatus.Information = sizeof(ULONG);
		}
		status = STATUS_SUCCESS;
		break;

	case IOCTL_STORAGE_GET_DEVICE_NUMBER:
		struct _STORAGE_DEVICE_NUMBER *dn;
		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _STORAGE_DEVICE_NUMBER)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		dn = (struct _STORAGE_DEVICE_NUMBER*) irp->AssociatedIrp.SystemBuffer;

		dn->DeviceType = FILE_DEVICE_DISK; /* TODO: device->DeviceType? */
		dn->DeviceNumber = dev->minor;
		dn->PartitionNumber = -1;

		irp->IoStatus.Information = sizeof(struct _STORAGE_DEVICE_NUMBER);
		status = STATUS_SUCCESS;
		break;

	case IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES:
		struct _DEVICE_MANAGE_DATA_SET_ATTRIBUTES *attrs =
	            (struct _DEVICE_MANAGE_DATA_SET_ATTRIBUTES*) irp->AssociatedIrp.SystemBuffer;

		if ((s->Parameters.DeviceIoControl.InputBufferLength <
	            sizeof(struct _DEVICE_MANAGE_DATA_SET_ATTRIBUTES)) ||
                   (s->Parameters.DeviceIoControl.InputBufferLength <
                   (attrs->DataSetRangesOffset + attrs->DataSetRangesLength))) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		dbg("attrs->Action is %d\n", attrs->Action);
		if (attrs->Action != DeviceDsmAction_Trim) {
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		int items = attrs->DataSetRangesLength / sizeof(DEVICE_DATA_SET_RANGE);

		dbg("%d items\n", items);

		status = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;
			/* TODO: trim */

		break;

	/* from reactos */

#define IOCTL_VOLUME_BASE                 ((ULONG) 'V')
#define IOCTL_VOLUME_IS_PARTITION \
  CTL_CODE(IOCTL_VOLUME_BASE, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)

	case IOCTL_VOLUME_IS_PARTITION:
		dbg(KERN_DEBUG "IOCTL_VOLUME_IS_PARTITION: s->Parameters.DeviceIoControl.InputBufferLength is %d s->Parameters.DeviceIoControl.OutputBufferLength is %d\n", s->Parameters.DeviceIoControl.InputBufferLength, s->Parameters.DeviceIoControl.OutputBufferLength);

		status = STATUS_SUCCESS;
		break;

	case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
		struct _DRIVE_LAYOUT_INFORMATION_EX *dli;

		dbg(KERN_DEBUG "IOCTL_DISK_GET_DRIVE_LAYOUT_EX: s->Parameters.DeviceIoControl.InputBufferLength is %d s->Parameters.DeviceIoControl.OutputBufferLength is %d\n", s->Parameters.DeviceIoControl.InputBufferLength, s->Parameters.DeviceIoControl.OutputBufferLength);

		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _DRIVE_LAYOUT_INFORMATION_EX)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		dli = (struct _DRIVE_LAYOUT_INFORMATION_EX*) irp->AssociatedIrp.SystemBuffer;

		dli->PartitionStyle = 0;	/* MBR */
		dli->PartitionCount = 1;
		dli->Mbr.Signature = 0x12345678;
//		dli->Mbr.Checksum = 0;

		fill_partition_info_ex(&dli->PartitionEntry[0], dev);
		irp->IoStatus.Information = sizeof(struct _DRIVE_LAYOUT_INFORMATION_EX);

		status = STATUS_SUCCESS;
		break;
	default: 
		dbg(KERN_DEBUG "DRBD IoCtl request not implemented: IoControlCode: 0x%x\n", s->Parameters.DeviceIoControl.IoControlCode);

		status = STATUS_INVALID_PARAMETER;
	}

out:
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
}

static NTSTATUS windrbd_create(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
printk("1\n");
	if (device == mvolRootDeviceObject) {
		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}
printk("2\n");

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == (void*) -1 || ref == NULL || ref->bdev == NULL) {
		printk(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
		irp->IoStatus.Information = 0;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_SUCH_DEVICE;
	}
	struct block_device *dev = ref->bdev;
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	int mode;
	NTSTATUS status;
	int err;

	if (dev->drbd_device != NULL) {
		status = wait_for_becoming_primary(dev->drbd_device->this_bdev);
		if (status != STATUS_SUCCESS)
			goto exit;

		dbg(KERN_DEBUG "s->Parameters.Create.SecurityContext->DesiredAccess is %x\n", s->Parameters.Create.SecurityContext->DesiredAccess);

		mode = (s->Parameters.Create.SecurityContext->DesiredAccess &
       	               (FILE_WRITE_DATA  | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_APPEND_DATA | GENERIC_WRITE)) ? FMODE_WRITE : 0;

		dbg(KERN_INFO "DRBD device create request: opening DRBD device %s\n",
			mode == 0 ? "read-only" : "read-write");

		err = drbd_open(dev, mode);
		dbg(KERN_DEBUG "drbd_open returned %d\n", err);
		status = (err < 0) ? STATUS_INVALID_DEVICE_REQUEST : STATUS_SUCCESS;
	} else {
			/* If we are currently mounting we most likely got
			 * this IRP from the mount manager. Do not open the
			 * device in drbd, this will fail at this early stage.
			 */

		dbg("Create request while device isn't set up yet.\n");
		status = STATUS_SUCCESS;
	}

exit:
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	dbg(KERN_DEBUG "status is %x\n", status);
	return status;
}


static NTSTATUS windrbd_close(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
printk("1\n");
	if (device == mvolRootDeviceObject) {
		struct _IO_STACK_LOCATION *s2 = IoGetCurrentIrpStackLocation(irp);
		windrbd_delete_multicast_groups_for_file(s2->FileObject);

		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == (void*) -1 || ref == NULL || ref->bdev == NULL) {
		printk(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
		irp->IoStatus.Information = 0;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_SUCH_DEVICE;
	}
	struct block_device *dev = ref->bdev;
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	int mode;
	NTSTATUS status;
	int err;

	if (dev->drbd_device != NULL) {
		mode = 0;	/* TODO: remember mode from open () */
/*	mode = (s->Parameters.Create.SecurityContext->DesiredAccess &
                (FILE_WRITE_DATA  | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_APPEND_DATA | GENERIC_WRITE)) ? FMODE_WRITE : 0; */

/*
		dbg(KERN_INFO "DRBD device close request: releasing DRBD device %s\n",
			mode == 0 ? "read-only" : "read-write");
*/

		err = dev->bd_disk->fops->release(dev->bd_disk, mode);
		dbg(KERN_DEBUG "drbd_release returned %d\n", err);
		status = (err < 0) ? STATUS_INVALID_DEVICE_REQUEST : STATUS_SUCCESS;
	} else {
		dbg("Close request while device isn't set up yet.\n");
			/* See comment in windrbd_create() */
		status = STATUS_SUCCESS;
	}

	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

static NTSTATUS windrbd_cleanup(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
printk("1\n");
	if (device == mvolRootDeviceObject) {
		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == (void*) -1 || ref == NULL || ref->bdev == NULL) {
		printk(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
		irp->IoStatus.Information = 0;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_SUCH_DEVICE;
	}
	struct block_device *dev = ref->bdev;
	NTSTATUS status = STATUS_SUCCESS;

	dbg(KERN_INFO "Pretending that cleanup does something.\n");
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

/* Limit imposed by DRBD over the wire protocol. This will not change
 * in the next 5+ years, most likely never.
 */

#define MAX_BIO_SIZE (1024*1024)

static void windrbd_bio_finished(struct bio * bio, int error)
{
	PIRP irp = bio->bi_upper_irp;
	int i;
	NTSTATUS status;

	status = STATUS_SUCCESS;

	if (error == 0) {
		if (bio->bi_rw == READ) {
			if (!bio->bi_common_data->bc_device_failed && bio->bi_upper_irp && bio->bi_upper_irp->MdlAddress) {
				char *user_buffer = bio->bi_upper_irp_buffer;
				if (user_buffer != NULL) {
					int offset;

					offset = bio->bi_mdl_offset;
					for (i=0;i<bio->bi_vcnt;i++) {

dbg("RtlCopyMemory(%p, %p, %d)\n", user_buffer+offset, ((char*)bio->bi_io_vec[i].bv_page->addr)+bio->bi_io_vec[i].bv_offset, bio->bi_io_vec[i].bv_len);
dbg("i is %d offset is %d user_buffer is %p bio->bi_io_vec[i].bv_page->addr is %p bio->bi_io_vec[i].bv_offset is %d bio->bi_io_vec[i].bv_len is %d\n", i, offset, user_buffer, bio->bi_io_vec[i].bv_page->addr, bio->bi_io_vec[i].bv_offset, bio->bi_io_vec[i].bv_len);

						RtlCopyMemory(user_buffer+offset, ((char*)bio->bi_io_vec[i].bv_page->addr)+bio->bi_io_vec[i].bv_offset, bio->bi_io_vec[i].bv_len);
{ int j; for (j=0;j<10;j++) { printk("data[%d] is %x\n", j, ((unsigned char*)user_buffer+offset)[j]); } }
						offset += bio->bi_io_vec[i].bv_len;
					}
				} else {
					printk(KERN_WARNING "MmGetSystemAddressForMdlSafe returned NULL\n");
					status = STATUS_INVALID_PARAMETER;
				}
			}
		}
	} else {
		printk(KERN_ERR "I/O failed with %d\n", error);

			/* This translates to error 55
			 * (ERROR_DEV_NOT_EXIST: The specified network
			 * resource or device is no longer available.
			 * which is quite close to what we mean. Also
			 * under Windows 10 / Server 2016?
			 */

		status = STATUS_DEVICE_DOES_NOT_EXIST;
	}
	if (bio->bi_rw == READ)
		for (i=0;i<bio->bi_vcnt;i++)
			kfree(bio->bi_io_vec[i].bv_page->addr);

        unsigned long flags;

		/* TODO: later when we patch out the extra copy
		 * on read, this also can be done much easier.
		 */

	int total_num_completed = bio->bi_common_data->bc_num_requests;
	size_t total_size = bio->bi_common_data->bc_total_size;

        spin_lock_irqsave(&bio->bi_common_data->bc_device_failed_lock, flags);
        int num_completed = atomic_inc_return(&bio->bi_common_data->bc_num_completed);
        int device_failed = bio->bi_common_data->bc_device_failed;
        if (status != STATUS_SUCCESS)
                bio->bi_common_data->bc_device_failed = 1;
        spin_unlock_irqrestore(&bio->bi_common_data->bc_device_failed_lock, flags);

		/* Do not access bio->bi_common_data here as it might be
		 * already freed.
		 */

	if (num_completed == total_num_completed) {
		if (status == STATUS_SUCCESS)
			irp->IoStatus.Information = total_size;
		else
				/* Windows documentation states that this
				 * should be set to 0 if non-success error
				 * code is returned (even if we already
				 * successfully read/wrote data).
				 */
			irp->IoStatus.Information = 0;

		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, status != STATUS_SUCCESS ? IO_NO_INCREMENT : IO_DISK_INCREMENT);
		kfree(bio->bi_common_data);
	}
	for (i=0;i<bio->bi_vcnt;i++)
		kfree(bio->bi_io_vec[i].bv_page);

	bio_put(bio);
}

static NTSTATUS windrbd_make_drbd_requests(struct _IRP *irp, struct block_device *dev, char *buffer, unsigned int total_size, sector_t sector, unsigned long rw)
{
	struct bio *bio;

	int b;
	struct bio_collection *common_data;

printk("transfer buffer is %p\n", buffer);

	if (sector * dev->bd_block_size >= dev->d_size) {
		dbg("Attempt to read past the end of the device\n");
		return STATUS_INVALID_PARAMETER;
	}
	if (sector * dev->bd_block_size + total_size > dev->d_size) {
		dbg("Attempt to read past the end of the device, request shortened\n");
		total_size = dev->d_size - sector * dev->bd_block_size; 
	}
	if (total_size == 0) {
		printk("I/O request of size 0.\n");
		return STATUS_INVALID_PARAMETER;
	}
	if (buffer == NULL) {
		printk("I/O buffer (from MmGetSystemAddressForMdlSafe()) is NULL\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

// dbg("%s sector: %d this_bio_size: %d\n", s->MajorFunction == IRP_MJ_WRITE ? "WRITE" : "READ", sector, this_bio_size);
	int bio_count = (total_size-1) / MAX_BIO_SIZE + 1;
	int this_bio_size;
	int last_bio_size = total_size % MAX_BIO_SIZE;
	if (last_bio_size == 0)
		last_bio_size = MAX_BIO_SIZE;

	common_data = kzalloc(sizeof(*common_data), 0, 'DRBD');
	if (common_data == NULL) {
		printk("Cannot allocate common data.\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	atomic_set(&common_data->bc_num_completed, 0);
	common_data->bc_total_size = total_size;
	common_data->bc_num_requests = bio_count;
	common_data->bc_device_failed = 0;
	spin_lock_init(&common_data->bc_device_failed_lock);

	/* Do this before windrbd_bio_finished might be called, else
	 * this could produce a blue screen.
	 */

        IoMarkIrpPending(irp);

	for (b=0; b<bio_count; b++) {
		this_bio_size = (b==bio_count-1) ? last_bio_size : MAX_BIO_SIZE;

		bio = bio_alloc(GFP_NOIO, 1, 'DBRD');
		if (bio == NULL) {
			printk("Couldn't allocate bio.\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		bio->bi_rw = rw;
		bio->bi_bdev = dev;
		bio->bi_max_vecs = 1;
		bio->bi_vcnt = 1;
		bio->bi_paged_memory = bio->bi_rw == WRITE;
		bio->bi_size = this_bio_size;
		bio->bi_sector = sector + b*MAX_BIO_SIZE/dev->bd_block_size;
		bio->bi_upper_irp_buffer = buffer;
		bio->bi_mdl_offset = b*MAX_BIO_SIZE;
		bio->bi_common_data = common_data;

dbg("%s sector: %d total_size: %d\n", rw == WRITE ? "WRITE" : "READ", sector, total_size);

		bio->bi_io_vec[0].bv_page = kzalloc(sizeof(struct page), 0, 'DRBD');
		if (bio->bi_io_vec[0].bv_page == NULL) {
			printk("Couldn't allocate page.\n");
			return STATUS_INSUFFICIENT_RESOURCES; /* TODO: cleanup */
		}

		bio->bi_io_vec[0].bv_len = this_bio_size;
		bio->bi_io_vec[0].bv_page->size = this_bio_size;
		kref_init(&bio->bi_io_vec[0].bv_page->kref);


/*
 * TODO: eventually we want to make READ requests work without the
 *	 intermediate buffer and the extra copy.
 */

		if (bio->bi_rw == READ)
			bio->bi_io_vec[0].bv_page->addr = kmalloc(this_bio_size, 0, 'DRBD');
		else
			bio->bi_io_vec[0].bv_page->addr = buffer+bio->bi_mdl_offset;

				/* TODO: fault inject here. */
		if (bio->bi_io_vec[0].bv_page->addr == NULL) {
			printk("Couldn't allocate temp buffer for read.\n");
			return STATUS_INSUFFICIENT_RESOURCES; /* TODO: cleanup */
		}

		bio->bi_io_vec[0].bv_offset = 0;
		bio->bi_end_io = windrbd_bio_finished;
		bio->bi_upper_irp = irp;

// dbg("bio: %p bio->bi_io_vec[0].bv_page->addr: %p bio->bi_io_vec[0].bv_len: %d bio->bi_io_vec[0].bv_offset: %d\n", bio, bio->bi_io_vec[0].bv_page->addr, bio->bi_io_vec[0].bv_len, bio->bi_io_vec[0].bv_offset);
// dbg("bio->bi_size: %d bio->bi_sector: %d bio->bi_mdl_offset: %d\n", bio->bi_size, bio->bi_sector, bio->bi_mdl_offset);

		drbd_make_request(dev->drbd_device->rq_queue, bio);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS make_drbd_requests_from_irp(struct _IRP *irp, struct block_device *dev)
{
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	struct _MDL *mdl = irp->MdlAddress;

	unsigned int total_size;
	sector_t sector;
	char *buffer;
	unsigned long rw;

	if (s == NULL) {
		printk("Stacklocation is NULL.\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	if (mdl == NULL) {
			/* TODO: this sometimes happens with windrbd-test.
			 * Find out why.
			 */
		dbg("MdlAddress is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	/* later have more than one .. */

	/* Update: I tried to generate this test case using ReadFileGather/
	 * WriteFileScatter but this is more like a mmap replacement (has
	 * one MDL element with page table entries created for each vector
	 * element). I don't know currently how to test this. Plus we
	 * found a Windows block device that blue screens (!) if there
	 * is more than one MDL element in the request (Windows 10 USB
	 * storage driver). For now, it should be sufficient to support
	 * one MDL element, we will implement this if someone complains.
	 */

	if (mdl->Next != NULL) {
		printk(KERN_ERR "not implemented: have more than one mdl. Dropping additional mdl data.\n");
		return STATUS_NOT_IMPLEMENTED;
	}

	if (s->MajorFunction == IRP_MJ_WRITE) {
		total_size = s->Parameters.Write.Length;
		sector = (s->Parameters.Write.ByteOffset.QuadPart) / dev->bd_block_size;
	} else if (s->MajorFunction == IRP_MJ_READ) {
		total_size = s->Parameters.Read.Length;
		sector = (s->Parameters.Read.ByteOffset.QuadPart) / dev->bd_block_size;
	} else {
		printk("s->MajorFunction neither read nor write.\n");
		return STATUS_INVALID_PARAMETER;
	}

		/* Address returned by MmGetSystemAddressForMdlSafe
		 * is already offset, not using MmGetMdlByteOffset.
		 */

	buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
	if (buffer == NULL) {
		printk("I/O buffer from MmGetSystemAddressForMdlSafe() is NULL\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	rw = s->MajorFunction == IRP_MJ_WRITE ? WRITE : READ;

	return windrbd_make_drbd_requests(irp, dev, buffer, total_size, sector, rw);
}

static NTSTATUS windrbd_io(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
printk("1\n");
	if (device == mvolRootDeviceObject) {
		dbg(KERN_WARNING "I/O on root device not supported.\n");

		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == (void*) -1 || ref == NULL || ref->bdev == NULL) {
		printk(KERN_WARNING "I/O request: Device %p accessed after it was deleted.\n", device);
		irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
		irp->IoStatus.Information = 0;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_SUCH_DEVICE;
	}
	struct block_device *dev = ref->bdev;
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

		/* Happens when mounting fails and we try to umount
		 * the device.
		 */

	if (dev->drbd_device == NULL) {
		dbg("I/O request while device isn't set up yet.\n");
		goto exit;
	}

	if (dev->drbd_device->resource->role[NOW] != R_PRIMARY) {
		dbg("I/O request while not primary, waiting for primary.\n");

		status = wait_for_becoming_primary(dev->drbd_device->this_bdev);
		if (status != STATUS_SUCCESS)
			goto exit;
	}

		/* allow I/O when the local disk failed, usually there
		 * are peers which can handle the I/O. If not, DRBD will
		 * report an I/O error which we will get in our completion
		 * routine later and can report to the application.
		 */

	status = make_drbd_requests_from_irp(irp, dev);
	if (status != STATUS_SUCCESS)
		goto exit;

	return STATUS_PENDING;

exit:
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
}

static NTSTATUS windrbd_shutdown(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	if (device == mvolRootDeviceObject) {
		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

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

static void windrbd_bio_flush_finished(struct bio * bio, int error)
{
	PIRP irp = bio->bi_upper_irp;

	if (error == 0) {
		irp->IoStatus.Information = bio->bi_size;
		irp->IoStatus.Status = STATUS_SUCCESS;
	} else {
		printk(KERN_ERR "Flush failed with %d\n", error);
		irp->IoStatus.Information = 0;

			/* TODO: On Windows 7, this error seems not
			 * to reach userspace. On Windows 10, returning
			 * STATUS_UNSUCCESSFUL translates to a
			 * Permission denied error.
			 */
		// irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
		irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	}
	IoCompleteRequest(irp, error ? IO_NO_INCREMENT : IO_DISK_INCREMENT);

	bio_put(bio);
}

static NTSTATUS windrbd_flush(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	if (device == mvolRootDeviceObject) {
		dbg(KERN_WARNING "Flush on root device not supported.\n");

		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == (void*) -1 || ref == NULL || ref->bdev == NULL) {
		printk(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
		irp->IoStatus.Information = 0;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_SUCH_DEVICE;
	}
	struct block_device *dev = ref->bdev;
	struct bio *bio;
	NTSTATUS status;

	bio = bio_alloc(GFP_NOIO, 0, 'DBRD');
	if (bio == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto exit;
	}
	bio->bi_rw = WRITE | DRBD_REQ_PREFLUSH;
	bio->bi_size = 0;
	bio->bi_end_io = windrbd_bio_flush_finished;
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

static NTSTATUS start_completed(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PKEVENT event) {
	KeSetEvent(event, 0, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

static int get_all_drbd_device_objects(struct _DEVICE_OBJECT **array, int max)
{
        struct drbd_resource *resource;
	struct drbd_device *drbd_device;
	int vnr;
	int count = 0;

	for_each_resource(resource, &drbd_resources) {
		idr_for_each_entry(struct drbd_device *, &resource->devices, drbd_device, vnr) {
			if (drbd_device && drbd_device->this_bdev && drbd_device->this_bdev->windows_device) {
				if (count < max && array != NULL) {
					array[count] = drbd_device->this_bdev->windows_device;
					ObReferenceObject(drbd_device->this_bdev->windows_device);
				}
printk("windows device at %p\n", drbd_device->this_bdev->windows_device);
				count++;
			}
		}
	}
printk("%d drbd windows devices found\n", count);
	return count;
}

extern void windrbd_bus_is_ready(void);

static NTSTATUS windrbd_pnp_bus_object(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	struct _BUS_EXTENSION *bus_ext = (struct _BUS_EXTENSION*) device->DeviceExtension;
	NTSTATUS status;
	KEVENT start_completed_event;

	switch (s->MinorFunction) {
	case IRP_MN_START_DEVICE:
		dbg("got IRP_MN_START_DEVICE\n");

		KeInitializeEvent(&start_completed_event, NotificationEvent, FALSE);
		IoCopyCurrentIrpStackLocationToNext(irp);
		IoSetCompletionRoutine(irp, (PIO_COMPLETION_ROUTINE)start_completed, (PVOID)&start_completed_event, TRUE, TRUE, TRUE);

printk("starting lower device object\n");
		status = IoCallDriver(bus_ext->lower_device, irp);
		if (status == STATUS_PENDING) {
printk("Pening ...\n");
			KeWaitForSingleObject(&start_completed_event, Executive, KernelMode, FALSE, NULL);
printk("Completed.\n");
		}
		status = irp->IoStatus.Status;
		if (status != STATUS_SUCCESS)
			printk("Warning: lower device start returned %x\n", status);

printk("starting device object status is %x\n", status);

		status = STATUS_SUCCESS;
		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, IO_NO_INCREMENT);

printk("completed IRP\n");

		windrbd_bus_is_ready();
printk("Set bus ready\n");

		return status;

	case IRP_MN_QUERY_PNP_DEVICE_STATE:
		dbg("got IRP_MN_QUERY_PNP_DEVICE_STATE\n");
		irp->IoStatus.Information = 0;
		status = STATUS_SUCCESS;
		break;

	case IRP_MN_QUERY_REMOVE_DEVICE:
		dbg("got IRP_MN_QUERY_REMOVE_DEVICE\n");
		// status = STATUS_SUCCESS;
		status = STATUS_NOT_IMPLEMENTED; /* so we don't get removed. */
		break;

	case IRP_MN_CANCEL_REMOVE_DEVICE:
		dbg("got IRP_MN_CANCEL_REMOVE_DEVICE\n");
		status = STATUS_SUCCESS;
		break;

	case IRP_MN_SURPRISE_REMOVAL:
		dbg("got IRP_MN_SURPRISE_REMOVAL\n");
		status = STATUS_SUCCESS;
		break;

	case IRP_MN_REMOVE_DEVICE:
		dbg("got IRP_MN_REMOVE_DEVICE\n");

		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoSkipCurrentIrpStackLocation(irp);

printk("removing lower device object\n");
		status = IoCallDriver(bus_ext->lower_device, irp);

printk("IoCallDriver returned %x\n", status);

			/* TODO: delete all DRBD devices */

printk("detaching device object\n");
		IoDetachDevice(bus_ext->lower_device);
printk("deleting device object\n");
		IoDeleteDevice(device);
printk("device object deleted.\n");
printk("NOT completing IRP\n");
		drbd_bus_device = NULL;
		return STATUS_SUCCESS; /* must not do IoCompleteRequest */

	case IRP_MN_QUERY_DEVICE_RELATIONS:
		dbg("got IRP_MN_QUERY_DEVICE_RELATIONS\n");

		int type = s->Parameters.QueryDeviceRelations.Type;
dbg("Pnp: Is a IRP_MN_QUERY_DEVICE_RELATIONS: s->Parameters.QueryDeviceRelations.Type is %x (bus relations is %x)\n", s->Parameters.QueryDeviceRelations.Type, BusRelations);
		if (s->Parameters.QueryDeviceRelations.Type == BusRelations) {
printk("about to report DRBD devices ...\n");
			int num_devices = get_all_drbd_device_objects(NULL, 0);
			struct _DEVICE_RELATIONS *device_relations;
			int n;

			size_t siz = sizeof(*device_relations)+num_devices*sizeof(device_relations->Objects[0]);
printk("size of device relations is %d\n", siz);
		/* must be PagedPool else PnP manager complains */
			device_relations = ExAllocatePoolWithTag(PagedPool, siz, 'DRBD');
			if (device_relations == NULL) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			n = get_all_drbd_device_objects(&device_relations->Objects[0], num_devices);
			if (n != num_devices)
				printk("Warning: number of DRBD devices changed: old %d != new %d\n", num_devices, n);
			device_relations->Count = num_devices;
			irp->IoStatus.Information = (ULONG_PTR)device_relations;
			irp->IoStatus.Status = STATUS_SUCCESS;

			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
		} else {
			status = STATUS_NOT_IMPLEMENTED;
		}
		break;

	default:
		dbg("got unimplemented minor %x\n", s->MinorFunction);

		status = irp->IoStatus.Status;
		printk("status is %x\n", status);
	}

	if (status != STATUS_SUCCESS && status != STATUS_NOT_SUPPORTED && status != STATUS_NOT_IMPLEMENTED) {
printk("minor %x failed with status %x, not forwarding to lower driver...\n", s->MinorFunction, status);
		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	} else {
		irp->IoStatus.Status = status;
		IoSkipCurrentIrpStackLocation(irp);
printk("forwarding minor %x to lower driver...\n", s->MinorFunction);
		status = IoCallDriver(bus_ext->lower_device, irp);
		if (status != STATUS_SUCCESS)
			printk("Warning: lower device returned status %x\n", status);
	}

	return status;
}

static NTSTATUS windrbd_pnp(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	NTSTATUS status;

	if (device == mvolRootDeviceObject) {
		dbg(KERN_WARNING "PNP requests on root device not supported.\n");

		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}
	status = STATUS_NOT_IMPLEMENTED;

	dbg("Pnp: device: %p irp: %p\n", device, irp);

	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);

	dbg(KERN_DEBUG "got PnP device request: MajorFunction: 0x%x, MinorFunction: %x\n", s->MajorFunction, s->MinorFunction);
	if (device == drbd_bus_device) {
printk("bus object\n");
			/* Some minors (REMOVE_DEVICE) might delete the
			 * device object in which case we must not
			 * call IoCompleteRequest(). For the minors
			 * that don't IoCompleteRequest or IoCallDevice
			 * is done in this function:
			 */
		return windrbd_pnp_bus_object(device, irp);
	} else {
		struct block_device_reference *ref = device->DeviceExtension;
		struct block_device *bdev = NULL;
		struct drbd_device *drbd_device = NULL;
		int minor = -1;
printk("1\n");
		if (ref != (void*) -1 && ref != NULL) {
printk("2\n");
			bdev = ref->bdev;
			if (bdev) {
printk("3\n");
				drbd_device = bdev->drbd_device;
				if (drbd_device) {
printk("4\n");
					minor = drbd_device->minor;
				}
			}
		}

#if 0
		if (bdev != NULL)
			wait_for_becoming_primary(bdev);
		else
			printk("bdev is NULL on start device, this should not happen (minor is %x)\n", s->MinorFunction);
#endif

printk("5\n");
		switch (s->MinorFunction) {
		case IRP_MN_START_DEVICE:
		{
			int x;

printk("starting device\n");
printk("NOT waiting for becoming Primary\n");

/*
			x = ObReferenceObject(device);
printk("ObReferenceObject returned %d\n", x);
*/

			status = STATUS_SUCCESS;
			break;
		}

		case IRP_MN_QUERY_PNP_DEVICE_STATE:
printk("got IRP_MN_QUERY_PNP_DEVICE_STATE\n");
			irp->IoStatus.Information = 0;
			status = STATUS_SUCCESS;
			break;

		case IRP_MN_QUERY_ID:
		{
			wchar_t *string;
			dbg("Pnp: Is IRP_MN_QUERY_ID, type is %d\n", s->Parameters.QueryId.IdType);
printk("minor is %d\n", minor);
			if (minor < 0) {
				status = STATUS_INVALID_DEVICE_REQUEST;
				break;
			}
#define MAX_ID_LEN 512
			string = ExAllocatePoolWithTag(PagedPool, MAX_ID_LEN*sizeof(wchar_t), 'DRBD');
printk("6\n");
			if (string == NULL) {
				status = STATUS_INSUFFICIENT_RESOURCES;
			} else {
				memset(string, 0, MAX_ID_LEN*sizeof(wchar_t));
printk("7\n");
				switch (s->Parameters.QueryId.IdType) {
				case BusQueryDeviceID:
					swprintf(string, L"WinDRBD\\Disk%d", minor);
printk("8\n");
					status = STATUS_SUCCESS;
					break;
				case BusQueryInstanceID:
					swprintf(string, L"WinDRBD%d", minor);
printk("9\n");
					status = STATUS_SUCCESS;
					break;
				case BusQueryHardwareIDs:
printk("a\n");
					size_t len;
					len = swprintf(string, L"WinDRBDDisk");
					swprintf(&string[len+1], L"GenDisk");
printk("b\n");
					status = STATUS_SUCCESS;
					break;
				case BusQueryCompatibleIDs:
					len = swprintf(string, L"WinDRBDDisk");
					swprintf(&string[len+1], L"GenDisk");
//					len = swprintf(string, L"GenDisk");
printk("c\n");
					status = STATUS_SUCCESS;
					break;
				default:
printk("d\n");
					status = STATUS_NOT_IMPLEMENTED;
				}
			}
printk("e\n");
			if (status == STATUS_SUCCESS) {
dbg("Returned string is %S\n", string);
printk("f\n");
				irp->IoStatus.Information = (ULONG_PTR) string;
			} else {
printk("g\n");
				ExFreePool(string);
			}
printk("h\n");
			break;
		}

		case IRP_MN_QUERY_DEVICE_RELATIONS:
			dbg("Pnp: Is a IRP_MN_QUERY_DEVICE_RELATIONS: s->Parameters.QueryDeviceRelations.Type is %x\n", s->Parameters.QueryDeviceRelations.Type);

			switch (s->Parameters.QueryDeviceRelations.Type) {
			case TargetDeviceRelation:
			{
				struct _DEVICE_RELATIONS *device_relations;
				size_t siz = sizeof(*device_relations)+sizeof(device_relations->Objects[0]);
				printk("size of device relations is %d\n", siz);
		/* must be PagedPool else PnP manager complains */
				device_relations = ExAllocatePoolWithTag(PagedPool, siz, 'DRBD');
				if (device_relations == NULL) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
				device_relations->Count = 1;
				device_relations->Objects[0] = bdev->windows_device;
				ObReferenceObject(bdev->windows_device);

				irp->IoStatus.Information = (ULONG_PTR)device_relations;
				status = STATUS_SUCCESS;
				break;
			}

			case BusRelations:
			{
				struct _DEVICE_RELATIONS *device_relations;
				size_t siz = sizeof(*device_relations);

		/* must be PagedPool else PnP manager complains */
				device_relations = ExAllocatePoolWithTag(PagedPool, siz, 'DRBD');
				if (device_relations == NULL) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
				device_relations->Count = 0;
				irp->IoStatus.Information = (ULONG_PTR)device_relations;
				status = STATUS_SUCCESS;
				break;
			}

			default:
				printk("Type %d is not implemented\n");
				status = STATUS_NOT_IMPLEMENTED;
			}
			break;

/*
		case IRP_MN_QUERY_INTERFACE:
			IoSkipCurrentStackLocation(irp);
*/

		case IRP_MN_QUERY_DEVICE_TEXT:
		{
			wchar_t *string = NULL;
			size_t string_length;

			if ((string = (PWCHAR)ExAllocatePool(NonPagedPool, (512 * sizeof(WCHAR)))) == NULL) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(string, (512 * sizeof(WCHAR)));
			switch (s->Parameters.QueryDeviceText.DeviceTextType ) {
			case DeviceTextDescription:
				string_length = swprintf(string, L"DRBD Disk") + 1;
				irp->IoStatus.Information = (ULONG_PTR)ExAllocatePool(PagedPool, string_length * sizeof(WCHAR));
				if (irp->IoStatus.Information == 0) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
				RtlCopyMemory((PWCHAR)irp->IoStatus.Information, string, string_length * sizeof(WCHAR));
				status = STATUS_SUCCESS;
				break;

			case DeviceTextLocationInformation:
				string_length = swprintf(string, L"WinDRBD e%d", minor) + 1;

				irp->IoStatus.Information = (ULONG_PTR)ExAllocatePool(PagedPool, string_length * sizeof(WCHAR));
				if (irp->IoStatus.Information == 0) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
				RtlCopyMemory((PWCHAR)irp->IoStatus.Information, string, string_length * sizeof(WCHAR));
				status = STATUS_SUCCESS;
				break;
			default:
				irp->IoStatus.Information = 0;
				status = STATUS_NOT_SUPPORTED;
			}
			ExFreePool(string);
			break;
		}

		case IRP_MN_DEVICE_ENUMERATED:
			status = STATUS_SUCCESS;
			break;

/* TODO: set PNP_DEVICE_NOT_DISABLEABLE on IRP_MN_QUERY_PNP_DEVICE_STATE */

		case IRP_MN_QUERY_BUS_INFORMATION:
		{
			struct _PNP_BUS_INFORMATION *bus_info;

			bus_info = ExAllocatePool(PagedPool, sizeof(*bus_info));
			if (bus_info  == NULL) {
			        printk("DiskDispatchPnP ExAllocatePool IRP_MN_QUERY_BUS_INFORMATION failed\n");
			        status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			bus_info->BusTypeGuid = GUID_BUS_TYPE_INTERNAL;
			bus_info->LegacyBusType = PNPBus;
			bus_info->BusNumber = 0;
			irp->IoStatus.Information = (ULONG_PTR)bus_info;
			status = STATUS_SUCCESS;
			break;
		}

		case IRP_MN_QUERY_CAPABILITIES:
		{
			struct _DEVICE_CAPABILITIES *DeviceCapabilities;
			DeviceCapabilities = s->Parameters.DeviceCapabilities.Capabilities;
printk("got IRP_MN_QUERY_CAPABILITIES\n");
			if (DeviceCapabilities->Version != 1 || DeviceCapabilities->Size < sizeof(DEVICE_CAPABILITIES)) {
printk("wrong version of DeviceCapabilities\n");
				status = STATUS_UNSUCCESSFUL;
				break;
			}
			DeviceCapabilities->DeviceState[PowerSystemWorking] = PowerDeviceD0;
			if (DeviceCapabilities->DeviceState[PowerSystemSleeping1] != PowerDeviceD0) DeviceCapabilities->DeviceState[PowerSystemSleeping1] = PowerDeviceD1;
			if (DeviceCapabilities->DeviceState[PowerSystemSleeping2] != PowerDeviceD0) DeviceCapabilities->DeviceState[PowerSystemSleeping2] = PowerDeviceD3;
//      if (DeviceCapabilities->DeviceState[PowerSystemSleeping3] != PowerDeviceD0) DeviceCapabilities->DeviceState[PowerSystemSleeping3] = PowerDeviceD3;
			DeviceCapabilities->DeviceWake = PowerDeviceD1;
			DeviceCapabilities->DeviceD1 = TRUE;
			DeviceCapabilities->DeviceD2 = FALSE;
			DeviceCapabilities->WakeFromD0 = FALSE;
			DeviceCapabilities->WakeFromD1 = FALSE;
			DeviceCapabilities->WakeFromD2 = FALSE;
			DeviceCapabilities->WakeFromD3 = FALSE;
			DeviceCapabilities->D1Latency = 0;
			DeviceCapabilities->D2Latency = 0;
			DeviceCapabilities->D3Latency = 0;
			DeviceCapabilities->EjectSupported = FALSE;
			DeviceCapabilities->HardwareDisabled = FALSE;
			DeviceCapabilities->Removable = FALSE;
			DeviceCapabilities->SurpriseRemovalOK = FALSE;
			DeviceCapabilities->UniqueID = FALSE;
			DeviceCapabilities->SilentInstall = FALSE;

			status = STATUS_SUCCESS;
			break;
		}
		case IRP_MN_DEVICE_USAGE_NOTIFICATION:
printk("got IRP_MN_DEVICE_USAGE_NOTIFICATION\n");
			irp->IoStatus.Information = 0;
			status = STATUS_SUCCESS;
			break;

		case IRP_MN_QUERY_REMOVE_DEVICE:
			dbg("got IRP_MN_QUERY_REMOVE_DEVICE\n");
			// status = STATUS_SUCCESS;
			status = STATUS_NOT_IMPLEMENTED; /* so we don't get removed. */
			break;

		case IRP_MN_CANCEL_REMOVE_DEVICE:
			dbg("got IRP_MN_CANCEL_REMOVE_DEVICE\n");
			status = STATUS_SUCCESS;
			break;

		case IRP_MN_SURPRISE_REMOVAL:
			dbg("got IRP_MN_SURPRISE_REMOVAL\n");
			status = STATUS_SUCCESS;
			break;

		case IRP_MN_REMOVE_DEVICE:
			dbg("got IRP_MN_REMOVE_DEVICE\n");

			if (ref != (void*) -1) {
				device->DeviceExtension = (void*) -1;
				dbg("about to delete device object %p\n", device);
				IoDeleteDevice(device);
				dbg("device object deleted\n");
			} else {
				dbg("Warning: got IRP_MN_REMOVE_DEVICE twice for the same device object, not doing anything.\n");
			}

			return STATUS_SUCCESS;

		default:
			printk("got unimplemented minor %x for disk object\n", s->MinorFunction);
			if (drbd_bus_device != NULL) {
printk("irp status is %x\n", irp->IoStatus.Status);
				IoSkipCurrentIrpStackLocation(irp);
				status = IoCallDriver(drbd_bus_device, irp);
				printk("bus object returned %x\n", status);
				return status;
			}
			else
				printk("no bus object, cannot forward irp\n");

//			status = irp->IoStatus.Status;
//			status = STATUS_NOT_IMPLEMENTED;
		}
	}

	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

static NTSTATUS windrbd_power(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status;

	dbg(KERN_DEBUG "got Power device request: MajorFunction: 0x%x, MinorFunction: %x\n", s->MajorFunction, s->MinorFunction);

	if (device == mvolRootDeviceObject) {
		dbg(KERN_WARNING "Power requests on root device not supported.\n");

		irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NOT_SUPPORTED;
	}
	dbg("Power: device: %p irp: %p\n", device, irp);

	PoStartNextPowerIrp(irp);
	if (device == drbd_bus_device) {
		struct _BUS_EXTENSION *bus_ext = (struct _BUS_EXTENSION*) device->DeviceExtension;
		IoSkipCurrentIrpStackLocation(irp);
printk("Calling PoCallDriver ...\n");
		status = PoCallDriver(bus_ext->lower_device, irp);
printk("PoCallDriver returned %x\n", status);
	} else {
		irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		status = STATUS_NOT_SUPPORTED;
	}

printk("status is %x\n", status);
	return status;
}

	/* When installing WinDRBD as PnP Disk driver, the disk.sys driver
	 * is stacked over us and will send us SCSI requests. Some of them
	 * are implemented here (like read/write), others like TRIM
	 * or WRITESAME are not supported yet.
	 */

#define REVERSE_BYTES_QUAD(Destination, Source) { \
  PEIGHT_BYTE d = (PEIGHT_BYTE)(Destination);     \
  PEIGHT_BYTE s = (PEIGHT_BYTE)(Source);          \
  d->Byte7 = s->Byte0;                            \
  d->Byte6 = s->Byte1;                            \
  d->Byte5 = s->Byte2;                            \
  d->Byte4 = s->Byte3;                            \
  d->Byte3 = s->Byte4;                            \
  d->Byte2 = s->Byte5;                            \
  d->Byte1 = s->Byte6;                            \
  d->Byte0 = s->Byte7;                            \
}

static long long wait_for_size(struct _DEVICE_OBJECT *device)
{
	struct block_device_reference *ref;
	struct block_device *bdev = NULL;
	NTSTATUS status;
	long long d_size = -1;

	ref = device->DeviceExtension;
	if (ref != (void*) -1 && ref != NULL) {
		bdev = ref->bdev;

		if (bdev != NULL) {
			windrbd_bdget(bdev);

			dbg("waiting for block device size to become valid.\n");
			status = KeWaitForSingleObject(&bdev->capacity_event, Executive, KernelMode, FALSE, NULL);
			if (status == STATUS_SUCCESS) {
				dbg("Got size now, proceeding with I/O request\n");

				if (bdev->d_size > 0) {
					dbg("block device size is %lld\n", bdev->d_size);
					d_size = bdev->d_size;
				} else {
					dbg("Warning: block device size still not known yet.\n");
				}
			}
			else {
				dbg("KeWaitForSingleObject returned %x\n", status);
			}
			windrbd_bdput(bdev);
		}
	} else {
		dbg("ref is NULL!\n");
	}
	return d_size;
}

static NTSTATUS windrbd_scsi(struct _DEVICE_OBJECT *device, struct _IRP *irp) {
	NTSTATUS status;
	struct _SCSI_REQUEST_BLOCK *srb;
	struct _CDB16 *cdb16;
	union _CDB *cdb;
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	LONGLONG StartSector;
	ULONG SectorCount, Temp;
	LONGLONG d_size, LargeTemp;
	struct block_device *bdev;

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == (void*) -1 || ref == NULL || ref->bdev == NULL) {
		printk(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
		irp->IoStatus.Information = 0;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_SUCH_DEVICE;
	}
	bdev = ref->bdev;

	status = STATUS_INVALID_DEVICE_REQUEST;

printk("SCSI request for device %p\n", device);

	srb = s->Parameters.Scsi.Srb;
	if (srb == NULL) {
		goto out;
	}
	cdb = (union _CDB*) srb->Cdb;
	cdb16 = (struct _CDB16*) srb->Cdb;

	srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
	srb->ScsiStatus = SCSISTAT_GOOD;
	irp->IoStatus.Information = 0;
	if (srb->Lun != 0) {
		dbg("LUN of SCSI device request is %d (should be 0)\n", srb->Lun);
		goto out; // STATUS_SUCCESS?
	}
	status = STATUS_SUCCESS;	/* optimistic */

printk("got SCSI function %x\n", srb->Function);

	switch (srb->Function) {
	case SRB_FUNCTION_EXECUTE_SCSI:
printk("got SRB_FUNCTION_EXECUTE_SCSI SCSI function is %x\n", cdb->AsByte[0]);
		switch (cdb->AsByte[0]) {
		case SCSIOP_TEST_UNIT_READY:
			srb->SrbStatus = SRB_STATUS_SUCCESS;
			break;

			/* I/O. Route through DRBD via 
			 * windrbd_make_drbd_requests() and mark
			 * IRP pending.
			 */

		case SCSIOP_READ:
		case SCSIOP_READ16:
		case SCSIOP_WRITE:
		case SCSIOP_WRITE16:
		{
			long long start_sector;
			unsigned long long sector_count, total_size;
			int rw;

			rw = (cdb->AsByte[0] == SCSIOP_READ16 || cdb->AsByte[0] == SCSIOP_READ) ? READ : WRITE;

			if (cdb->AsByte[0] == SCSIOP_READ16 ||
			    cdb->AsByte[0] == SCSIOP_WRITE16) {
				REVERSE_BYTES_QUAD(&start_sector, &(cdb16->LogicalBlock[0]));
				REVERSE_BYTES(&sector_count, &(cdb16->TransferLength[0]));
			} else {
				start_sector = (cdb->CDB10.LogicalBlockByte0 << 24) + (cdb->CDB10.LogicalBlockByte1 << 16) + (cdb->CDB10.LogicalBlockByte2 << 8) + cdb->CDB10.LogicalBlockByte3;
				sector_count = (cdb->CDB10.TransferBlocksMsb << 8) + cdb->CDB10.TransferBlocksLsb;
			}

			if ((((PUCHAR)srb->DataBuffer - (PUCHAR)MmGetMdlVirtualAddress(irp->MdlAddress)) + (PUCHAR)MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority)) == NULL) {
				printk("cannot map transfer buffer\n");
				status = STATUS_INSUFFICIENT_RESOURCES;
				irp->IoStatus.Information = 0;
				break;
			}


printk("SCSI I/O: sector %lld, %d sectors to %p\n", start_sector, sector_count, srb->DataBuffer);

			status = windrbd_make_drbd_requests(irp, bdev, ((char*)srb->DataBuffer - (char*)MmGetMdlVirtualAddress(irp->MdlAddress)) + (char*)MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority), sector_count*512, start_sector, rw);
			if (status == STATUS_SUCCESS) {
				irp->IoStatus.Information = 0;
				irp->IoStatus.Status = STATUS_PENDING;
				return STATUS_PENDING;
			}

			break;
		}

		case SCSIOP_READ_CAPACITY:
			d_size = wait_for_size(device);

			Temp = 512;   /* TODO: later from struct */
			REVERSE_BYTES(&(((PREAD_CAPACITY_DATA)srb->DataBuffer)->BytesPerBlock), &Temp);
			if (d_size > 0) {
				if ((d_size % 512) != 0)
					printk("Warning: device size (%lld) not a multiple of 512\n", d_size);
				LargeTemp = (d_size / 512) - 1;

				if (LargeTemp > 0xffffffff) {
					((PREAD_CAPACITY_DATA)srb->DataBuffer)->LogicalBlockAddress = -1;
				} else {
					Temp = (ULONG) LargeTemp;
printk("SCSI: Reporting %lld bytes as capacity ...\n", d_size);
					REVERSE_BYTES(&(((PREAD_CAPACITY_DATA)srb->DataBuffer)->LogicalBlockAddress), &Temp);
				}
				irp->IoStatus.Information = sizeof(READ_CAPACITY_DATA);
				srb->SrbStatus = SRB_STATUS_SUCCESS;
				status = STATUS_SUCCESS;
			} else {
				srb->SrbStatus = SRB_STATUS_NO_DEVICE;
				status = STATUS_NO_SUCH_DEVICE;
			}
			break;

		case SCSIOP_READ_CAPACITY16:
			d_size = wait_for_size(device);

			Temp = 512;
			REVERSE_BYTES(&(((PREAD_CAPACITY_DATA_EX)srb->DataBuffer)->BytesPerBlock), &Temp);
			if (d_size > 0) {
				if ((d_size % 512) != 0)
					printk("Warning: device size (%lld) not a multiple of 512\n", d_size);
				LargeTemp = (d_size / 512) - 1;
				REVERSE_BYTES_QUAD(&(((PREAD_CAPACITY_DATA_EX)srb->DataBuffer)->LogicalBlockAddress.QuadPart), &LargeTemp);
printk("SCSI: Reporting %lld bytes as capacity16 ...\n", d_size);
				irp->IoStatus.Information = sizeof(READ_CAPACITY_DATA_EX);
				srb->SrbStatus = SRB_STATUS_SUCCESS;
				status = STATUS_SUCCESS;
			} else {
				srb->SrbStatus = SRB_STATUS_NO_DEVICE;
				status = STATUS_NO_SUCH_DEVICE;
			}
			break;

		case SCSIOP_MODE_SENSE:
		{
			PMODE_PARAMETER_HEADER ModeParameterHeader;

			if (srb->DataTransferLength < sizeof(MODE_PARAMETER_HEADER)) {
				srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
				break;
			}
			ModeParameterHeader = (PMODE_PARAMETER_HEADER)srb->DataBuffer;
			RtlZeroMemory(ModeParameterHeader, srb->DataTransferLength);
			ModeParameterHeader->ModeDataLength = sizeof(MODE_PARAMETER_HEADER);
			ModeParameterHeader->MediumType = FixedMedia;
			ModeParameterHeader->BlockDescriptorLength = 0;
			srb->DataTransferLength = sizeof(MODE_PARAMETER_HEADER);
			irp->IoStatus.Information = sizeof(MODE_PARAMETER_HEADER);
			srb->SrbStatus = SRB_STATUS_SUCCESS;
			status = STATUS_SUCCESS; /* TODO: ?? */
			break;
		}

		default:
printk("SCSI OP %x not supported\n", cdb->AsByte[0]);
			status = STATUS_NOT_IMPLEMENTED;
		}
		break;

	case SRB_FUNCTION_IO_CONTROL:
		srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
		break;

	case SRB_FUNCTION_CLAIM_DEVICE:
printk("got SRB_FUNCTION_CLAIM_DEVICE\n");
		srb->DataBuffer = device;
		srb->SrbStatus = SRB_STATUS_SUCCESS;
		break;

	case SRB_FUNCTION_RELEASE_DEVICE:
//		ObDereferenceObject(device);
		srb->SrbStatus = SRB_STATUS_SUCCESS;
		break;

	case SRB_FUNCTION_SHUTDOWN:
	case SRB_FUNCTION_FLUSH:
		srb->SrbStatus = SRB_STATUS_SUCCESS;
		break;

	default:
printk("got unimplemented SCSI function %x\n", srb->Function);
		status = STATUS_NOT_IMPLEMENTED;
	}

out:
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
	obj->MajorFunction[IRP_MJ_PNP] = windrbd_pnp;
	obj->MajorFunction[IRP_MJ_SHUTDOWN] = windrbd_shutdown;
	obj->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = windrbd_flush;
	obj->MajorFunction[IRP_MJ_SCSI] = windrbd_scsi;
	obj->MajorFunction[IRP_MJ_POWER] = windrbd_power;

	status = IoRegisterShutdownNotification(mvolRootDeviceObject);
	if (status != STATUS_SUCCESS) {
		printk("Could not register shutdown notification.\n");
	}
}

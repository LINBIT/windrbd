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

/* Uncomment this if you want more debug output (disable for releases) */

/*
#define DEBUG 1
*/

/* less verbose, used to debug bus device being deleted
 * right after creation.
 */
/*
#define DEBUG_BUS 1
*/

#ifdef RELEASE
#ifdef DEBUG
#undef DEBUG
#endif
#endif

#include <linux/types.h>
#include <ntdddisk.h>
#include <wdmguid.h>
#include <srb.h>
#include <scsi.h>
#include <ntddscsi.h>
#include <ntddstor.h>
#include <linux/module.h>
// #include <strsafe.h>	/* for StringCbPrintfW() - but it does not return length */

#include "windrbd_config.h"
#include <windrbd_internal.h>
#include "windrbd/windrbd_ioctl.h"
#include "drbd_int.h"
#include "drbd_wrappers.h"
#include "partition_table_template.h"

#include <linux/delay.h>

static PDRIVER_DISPATCH windrbd_dispatch_table[IRP_MJ_MAXIMUM_FUNCTION + 1];
static char *thread_names[IRP_MJ_MAXIMUM_FUNCTION + 1] = {
"create",		/* IRP_MJ_CREATE                     0x00 */
"createpipe",		/* IRP_MJ_CREATE_NAMED_PIPE          0x01 */
"close",		/* IRP_MJ_CLOSE                      0x02 */
"read",			/* IRP_MJ_READ                       0x03 */
"write",		/* IRP_MJ_WRITE                      0x04 */
"queryinfo",		/* IRP_MJ_QUERY_INFORMATION          0x05 */
"setinfo",		/* IRP_MJ_SET_INFORMATION            0x06 */
"queryea",		/* IRP_MJ_QUERY_EA                   0x07 */
"setea",		/* IRP_MJ_SET_EA                     0x08 */
"flush",		/* IRP_MJ_FLUSH_BUFFERS              0x09 */
"queryvol",		/* IRP_MJ_QUERY_VOLUME_INFORMATION   0x0a */
"setvol",		/* IRP_MJ_SET_VOLUME_INFORMATION     0x0b */
"dircontrol",		/* IRP_MJ_DIRECTORY_CONTROL          0x0c */
"fscontrol",		/* IRP_MJ_FILE_SYSTEM_CONTROL        0x0d */
"devicecontrol",	/* IRP_MJ_DEVICE_CONTROL             0x0e */
"scsi",			/* IRP_MJ_SCSI                       0x0f */
"shutdown",		/* IRP_MJ_SHUTDOWN                   0x10 */
"lockcontrol",		/* IRP_MJ_LOCK_CONTROL               0x11 */
"cleanup",		/* IRP_MJ_CLEANUP                    0x12 */
"createmslot",		/* IRP_MJ_CREATE_MAILSLOT            0x13 */
"querysec",		/* IRP_MJ_QUERY_SECURITY             0x14 */
"setsec",		/* IRP_MJ_SET_SECURITY               0x15 */
"power",		/* IRP_MJ_POWER                      0x16 */
"syscontrol",		/* IRP_MJ_SYSTEM_CONTROL             0x17 */
"devchange",		/* IRP_MJ_DEVICE_CHANGE              0x18 */
"queryquota",		/* IRP_MJ_QUERY_QUOTA                0x19 */
"setquota",		/* IRP_MJ_SET_QUOTA                  0x1a */
"pnp",			/* IRP_MJ_PNP                        0x1b */
};

static int shutting_down;	/* Windows machine is about to shut down */
static int about_to_unload_driver;	/* Driver will soon unload so
					 * we can upgrade it
					 */

/* TODO: return STATUS_NO_MEMORY instead of STATUS_INSUFFICIENT_RESOURCES
 * whereever a kmalloc() fails.
 */

static NTSTATUS __attribute__((stdcall)) windrbd_not_implemented(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
#ifdef DEBUG
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
#endif

	if (device == mvolRootDeviceObject || device == user_device_object || device == drbd_bus_device) {
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

	/* Better not do any printk's in here, we are in the I/O
	 * path.
	 */

/* 3 hours */
// #define LONG_TIMEOUT 10000
#define LONG_TIMEOUT 50

#define wait_for_becoming_primary(bdev) wait_for_becoming_primary_debug(bdev, __FILE__, __LINE__, __func__)

	/* See drbd_main.c: must patch this to non-static */
extern int try_to_promote(struct drbd_device *device, long timeout, bool ndelay);

static NTSTATUS wait_for_becoming_primary_debug(struct block_device *bdev, const char *file, int line, const char *func)
{
	NTSTATUS status;
	struct drbd_device *drbd_device;
	struct drbd_resource *resource;
	int rv;
	LONG_PTR timeout = LONG_TIMEOUT * HZ / 10;

	drbd_device = bdev->drbd_device;
	if (drbd_device != NULL) {
		resource = drbd_device->resource;
		if (resource == NULL)
			return STATUS_INVALID_PARAMETER;
	} else
		return STATUS_INVALID_PARAMETER;

	/* TODO: should we keep the auto-promote support code here.
	   It works pretty well, just need to export try_to_promote in
	   DRBD ...
	 */
	if ((bdev->is_bootdevice || bdev->my_auto_promote) && !bdev->powering_down && !shutting_down) {
		drbd_device = bdev->drbd_device;
		if (drbd_device != NULL) {
			resource = drbd_device->resource;
			if (resource != NULL) {
				while (resource->role[NOW] == R_SECONDARY) {
					dbg("Am secondary, trying to promote (called from %s:%d (%s())...\n", file, line, func);
					rv = try_to_promote(drbd_device, timeout, 0);

		/* no uptodate disk: we are not yet connected, wait a bit
		 * until we are.
		 */
					if (rv < SS_SUCCESS && rv != SS_NO_UP_TO_DATE_DISK) {
						drbd_info(resource, "Auto-promote failed: %s\n", drbd_set_st_err_str(rv));
						break;
					}
					if (rv == SS_SUCCESS) {
						if (windrbd_rescan_bus() < 0) {
							printk("Warning: could not rescan bus on becoming primary.\n");
						}
						break;
					}

					if (bdev->powering_down || bdev->delete_pending || shutting_down)
						break;

					msleep(100);
					if (bdev->powering_down || bdev->delete_pending || shutting_down)
						break;
				}
			}
		}
	} else {
		if (!bdev->powering_down && !shutting_down) {
			dbg("Waiting for becoming primary (called from %s:%d (%s())...\n", file, line, func);

			status = KeWaitForSingleObject(&bdev->primary_event, Executive, KernelMode, FALSE, NULL);
			if (status != STATUS_SUCCESS)
				dbg("KeWaitForSingleObject returned %x\n", status);
			else
				dbg("Am primary now, proceeding with request\n");
		} else {
			dbg("bdev->powering_down is %d, shutting_down is %d, system shutdown, not waiting for becoming Primary\n", bdev->powering_down, shutting_down);
		}
	}

	if (bdev->delete_pending) {
		dbg("device already deleted, cancelling request\n");
		return STATUS_NO_SUCH_DEVICE;
	}

	return (resource->role[NOW] == R_PRIMARY ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
}

static void fill_drive_geometry(struct _DISK_GEOMETRY *g, struct block_device *dev)
{
	g->BytesPerSector = dev->bd_block_size;
	g->Cylinders.QuadPart = dev->bd_inode->i_size / dev->bd_block_size / 255 / 63;
	g->TracksPerCylinder = 255;
	g->SectorsPerTrack = 63;
	g->MediaType = FixedMedia;
}

static void fill_partition_info(struct _PARTITION_INFORMATION *p, struct block_device *dev)
{
	p->StartingOffset.QuadPart = 0;
	p->PartitionLength.QuadPart = dev->bd_inode->i_size;
	p->HiddenSectors = 0;
	p->PartitionNumber = 1;
	p->PartitionType = PARTITION_ENTRY_UNUSED;
	p->BootIndicator = TRUE;
	p->RecognizedPartition = TRUE;
	p->RewritePartition = FALSE;
}

static void fill_partition_info_ex(struct _PARTITION_INFORMATION_EX *p, struct block_device *dev)
{
	p->PartitionStyle = PARTITION_STYLE_MBR;
	p->StartingOffset.QuadPart = 0;
	p->PartitionLength.QuadPart = dev->bd_inode->i_size;
	p->PartitionNumber = 1;
	p->RewritePartition = FALSE;
	p->Mbr.PartitionType = PARTITION_EXTENDED;
	p->Mbr.BootIndicator = TRUE;
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

int windrbd_application_io_suspended(struct block_device *bdev)
{
	return !KeReadStateEvent(&bdev->io_not_suspended);
}

void windrbd_suspend_application_io(struct block_device *bdev, const char *message)
{
	KIRQL flags;

	spin_lock_irqsave(&bdev->suspend_lock, flags);
	if (!windrbd_application_io_suspended(bdev)) {
		if (message != NULL)
			printk("%s", message);

		KeClearEvent(&bdev->io_not_suspended);
	}
	spin_unlock_irqrestore(&bdev->suspend_lock, flags);
}

void windrbd_resume_application_io(struct block_device *bdev, const char *message)
{
	KIRQL flags;

	spin_lock_irqsave(&bdev->suspend_lock, flags);
	if (windrbd_application_io_suspended(bdev)) {
		if (message != NULL)
			printk("%s", message);

		KeSetEvent(&bdev->io_not_suspended, 0, FALSE);
	}
	spin_unlock_irqrestore(&bdev->suspend_lock, flags);
}

static NTSTATUS __attribute__((stdcall)) windrbd_root_device_control(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status = STATUS_SUCCESS;

// printk("root ioctl is 0x%08x object is %p\n", s->Parameters.DeviceIoControl.IoControlCode, device);

	if (!current->is_root) {
		switch (s->Parameters.DeviceIoControl.IoControlCode) {

	/* Allowed ioctl's for user device (open for everybody)
	 * (there is an extra check in the netlink layer)
	 */

		case IOCTL_WINDRBD_ROOT_IS_WINDRBD_ROOT_DEVICE:
		case IOCTL_WINDRBD_ROOT_SEND_NL_PACKET:
		case IOCTL_WINDRBD_ROOT_RECEIVE_NL_PACKET:
		case IOCTL_WINDRBD_ROOT_ARE_THERE_NL_PACKETS:
		case IOCTL_WINDRBD_ROOT_JOIN_MC_GROUP:
		case IOCTL_WINDRBD_ROOT_GET_DRBD_VERSION:
		case IOCTL_WINDRBD_ROOT_GET_WINDRBD_VERSION:
			break;

		default:
			status = STATUS_ACCESS_DENIED;

			irp->IoStatus.Status = status;
		        IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}
	}

	if (about_to_unload_driver) {
		switch (s->Parameters.DeviceIoControl.IoControlCode) {

			/* Terminate all running drbdsetup commands */
		case IOCTL_WINDRBD_ROOT_SEND_NL_PACKET:
		case IOCTL_WINDRBD_ROOT_RECEIVE_NL_PACKET:
		case IOCTL_WINDRBD_ROOT_ARE_THERE_NL_PACKETS:
		case IOCTL_WINDRBD_ROOT_JOIN_MC_GROUP:
			status = STATUS_NO_MORE_ENTRIES;

			irp->IoStatus.Status = status;
		        IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}
	}

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
	{
		size_t in_bytes = s->Parameters.DeviceIoControl.InputBufferLength;

		if (in_bytes > NLMSG_GOODSIZE) {
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		int err = windrbd_process_netlink_packet(irp->AssociatedIrp.SystemBuffer, in_bytes);
		irp->IoStatus.Information = 0;

		if (err != 0) {
			if (err == -EPERM)
				status = STATUS_ACCESS_DENIED;
			else
				status = STATUS_INVALID_DEVICE_REQUEST;
		}
		else
			status = STATUS_SUCCESS;

		break;
	}
	case IOCTL_WINDRBD_ROOT_RECEIVE_NL_PACKET:
	{
		size_t out_max_bytes = s->Parameters.DeviceIoControl.OutputBufferLength;
		size_t bytes_returned;
		u32 portid;

		if (s->Parameters.DeviceIoControl.InputBufferLength != sizeof(struct windrbd_ioctl_genl_portid)) {
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		portid = ((struct windrbd_ioctl_genl_portid*)irp->AssociatedIrp.SystemBuffer)->portid;

		bytes_returned = windrbd_receive_netlink_packets(irp->AssociatedIrp.SystemBuffer, out_max_bytes, portid);

		/* may be 0, if there is no data */
		irp->IoStatus.Information = bytes_returned;
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_WINDRBD_ROOT_ARE_THERE_NL_PACKETS:
	{
		int *there_are_nl_packets = irp->AssociatedIrp.SystemBuffer;
		u32 portid;

		if (s->Parameters.DeviceIoControl.OutputBufferLength != sizeof(int)) {
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		if (s->Parameters.DeviceIoControl.InputBufferLength != sizeof(struct windrbd_ioctl_genl_portid)) {
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		portid = ((struct windrbd_ioctl_genl_portid*)irp->AssociatedIrp.SystemBuffer)->portid;
		*there_are_nl_packets = (int)windrbd_are_there_netlink_packets(portid);

		irp->IoStatus.Information = sizeof(int);
		break;
	}

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
	{
		size_t bytes_returned2;
		size_t out_max_bytes2 = s->Parameters.DeviceIoControl.OutputBufferLength;
		int ret;

		ret = windrbd_um_get_next_request(irp->AssociatedIrp.SystemBuffer, out_max_bytes2, &bytes_returned2);

		if (ret == -EINVAL)
			status = STATUS_BUFFER_TOO_SMALL;

		irp->IoStatus.Information = bytes_returned2;
		break;
	}

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
		status = STATUS_INVALID_DEVICE_REQUEST;
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

	case IOCTL_WINDRBD_ROOT_RUN_TEST:
	{
		const char* test_args = irp->AssociatedIrp.SystemBuffer;
		if (test_args == NULL)
			status = STATUS_INVALID_DEVICE_REQUEST;
		else
			test_main(test_args);

		break;
	}

	case IOCTL_WINDRBD_ROOT_SET_SYSLOG_IP:
	{
		const char* syslog_ip = irp->AssociatedIrp.SystemBuffer;

		if (syslog_ip == NULL)
			status = STATUS_INVALID_DEVICE_REQUEST;
		else
			set_syslog_ip(syslog_ip);

		break;
	}

	case IOCTL_WINDRBD_ROOT_CREATE_RESOURCE_FROM_URL:
	{
		const char* drbd_url = irp->AssociatedIrp.SystemBuffer;

		if (drbd_url == NULL)
			status = STATUS_INVALID_DEVICE_REQUEST;
		else
			create_drbd_resource_from_url(drbd_url);

		break;
	}

	case IOCTL_WINDRBD_ROOT_SET_CONFIG_KEY:
	{
		const char* the_config_key = irp->AssociatedIrp.SystemBuffer;

		if (the_config_key == NULL)
			status = STATUS_INVALID_DEVICE_REQUEST;
		else {
			if (lock_interface(the_config_key) < 0)
				status = STATUS_ACCESS_DENIED;
		}

		break;
	}

	case IOCTL_WINDRBD_ROOT_GET_LOCK_DOWN_STATE:
	{
		int* is_locked_p = irp->AssociatedIrp.SystemBuffer;
		if (s->Parameters.DeviceIoControl.OutputBufferLength != sizeof(int)) {
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		*is_locked_p = windrbd_is_locked();

		irp->IoStatus.Information = sizeof(int);
		break;
	}

	case IOCTL_WINDRBD_ROOT_SET_EVENT_LOG_LEVEL:
	{
		int *the_level = irp->AssociatedIrp.SystemBuffer;

		if (the_level == NULL)
			status = STATUS_INVALID_DEVICE_REQUEST;
		else
			set_event_log_threshold(*the_level);

		break;
	}

	case IOCTL_WINDRBD_ROOT_SET_SHUTDOWN_FLAG:
	{
		int *the_flag = irp->AssociatedIrp.SystemBuffer;

		if (the_flag == NULL)
			status = STATUS_INVALID_DEVICE_REQUEST;
		else {

/* If flag is cleared, assign AddDevice so we get the correct
   bus device in case driver wasn't unloaded and the installer
   was run. This helps making drbdadm primary working again,
   but something else is still missing (device manager shows
   must reboot). Maybe this is not fixable at all ...
 */

			if (about_to_unload_driver && !*the_flag) {
				printk("Assuming we were upgraded and unloading failed, enabling AddDevice again ...\n");
				mvolDriverObject->DriverExtension->AddDevice = mvolAddDevice;
			}
			about_to_unload_driver = (*the_flag);
		}

		break;
	}

	case IOCTL_WINDRBD_ROOT_SET_DRIVER_LOCKED:
	{
		int *the_flag = irp->AssociatedIrp.SystemBuffer;

		if (the_flag == NULL) {
			status = STATUS_INVALID_DEVICE_REQUEST;
		} else {
			if (set_driver_locked_state(*the_flag) != 0) {
				status = STATUS_DEVICE_BUSY;
			}
		}

		break;
	}

	case IOCTL_WINDRBD_ROOT_SET_IO_SUSPENDED_FOR_MINOR:
	{
		int *the_minor = irp->AssociatedIrp.SystemBuffer;

		if (the_minor == NULL) {
			status = STATUS_INVALID_DEVICE_REQUEST;
		} else {
			struct drbd_device *drbd_dev;
			drbd_dev = minor_to_device(*the_minor);
			if (drbd_dev == NULL || drbd_dev->vdisk == NULL || drbd_dev->vdisk->part0) {
				printk("No such DRBD minor: %d\n", *the_minor);
				status = STATUS_INVALID_PARAMETER;
			} else {
				/* reverse logic ... */
				KeClearEvent(&drbd_dev->vdisk->part0->io_not_suspended);
			}
		}
		break;
	}

	case IOCTL_WINDRBD_ROOT_CLEAR_IO_SUSPENDED_FOR_MINOR:
	{
		int *the_minor = irp->AssociatedIrp.SystemBuffer;

		if (the_minor == NULL) {
			status = STATUS_INVALID_DEVICE_REQUEST;
		} else {
			struct drbd_device *drbd_dev;
			drbd_dev = minor_to_device(*the_minor);
			if (drbd_dev == NULL || drbd_dev->vdisk->part0 == NULL) {
				printk("No such DRBD minor: %d\n", *the_minor);
				status = STATUS_INVALID_PARAMETER;
			} else {
					/* reverse logic ... */
				KeSetEvent(&drbd_dev->vdisk->part0->io_not_suspended, 0, FALSE);
			}
		}
		break;
	}

	default:
		dbg(KERN_DEBUG "DRBD IoCtl request not implemented: IoControlCode: 0x%x\n", s->Parameters.DeviceIoControl.IoControlCode);
		status = STATUS_INVALID_DEVICE_REQUEST;
	}

	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

static NTSTATUS __attribute__((stdcall)) windrbd_device_control(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	if (device == drbd_bus_device) {
		irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		irp->IoStatus.Information = 0;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	if (device == mvolRootDeviceObject || device == user_device_object)
		return windrbd_root_device_control(device, irp);

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == NULL || ref->bdev == NULL || ref->bdev->delete_pending) {
		dbg(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
		irp->IoStatus.Information = 0;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_SUCH_DEVICE;
	}

	struct block_device *dev = ref->bdev;
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status = STATUS_SUCCESS;

// printk("ioctl is 0x%08x\n", s->Parameters.DeviceIoControl.IoControlCode);
	if (dev->is_bootdevice) {
		status = wait_for_becoming_primary(dev);
		if (status != STATUS_SUCCESS)
			goto out;
	}

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
		g->DiskSize.QuadPart = dev->bd_inode->i_size;
		g->Data[0] = 0;

		irp->IoStatus.Information = sizeof(struct _DISK_GEOMETRY_EX);
		break;

	case IOCTL_DISK_GET_LENGTH_INFO:
		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _GET_LENGTH_INFORMATION)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		struct _GET_LENGTH_INFORMATION *l = irp->AssociatedIrp.SystemBuffer;
		l->Length.QuadPart = dev->bd_inode->i_size;
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
// printk("got IOCTL_DISK_GET_PARTITION_INFO\n");
		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _PARTITION_INFORMATION)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		struct _PARTITION_INFORMATION *p = irp->AssociatedIrp.SystemBuffer;
// printk("IOCTL_DISK_GET_PARTITION_INFO bootable TRUE\n");
		fill_partition_info(p, dev);
		irp->IoStatus.Information = sizeof(struct _PARTITION_INFORMATION);
		break;

	case IOCTL_DISK_GET_PARTITION_INFO_EX:
// printk("got IOCTL_DISK_GET_PARTITION_INFO_EX\n");
		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _PARTITION_INFORMATION_EX)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		struct _PARTITION_INFORMATION_EX *pe = irp->AssociatedIrp.SystemBuffer;
// printk("IOCTL_DISK_GET_PARTITION_INFO_EX bootable TRUE\n");
		fill_partition_info_ex(pe, dev);
		irp->IoStatus.Information = sizeof(struct _PARTITION_INFORMATION_EX);
		break;

	case IOCTL_DISK_SET_PARTITION_INFO:
		if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct _SET_PARTITION_INFORMATION)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
	/* TODO: this ioctl still needed? */
//		struct _SET_PARTITION_INFORMATION *pi = irp->AssociatedIrp.SystemBuffer;
//		dbg(KERN_INFO "Request to set partition type to %x\n", pi->PartitionType);
		irp->IoStatus.Information = 0;
		break;

	case IOCTL_DISK_IS_WRITABLE:
		break;	/* just return without error */

	case IOCTL_STORAGE_GET_HOTPLUG_INFO:
	{
		struct _STORAGE_HOTPLUG_INFO* hotplug_info =
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
	}

	case IOCTL_STORAGE_QUERY_PROPERTY:
	{
		PSTORAGE_PROPERTY_QUERY StoragePropertyQuery = irp->AssociatedIrp.SystemBuffer;
		// status = STATUS_INVALID_PARAMETER;
		// status = irp->IoStatus.Status;
// printk("irp->IoStatus.Status is %x (STATUS_NOT_SUPPORTED is %x)\n", irp->IoStatus.Status, STATUS_NOT_SUPPORTED);
		status = STATUS_NOT_SUPPORTED;

		size_t CopySize;
		STORAGE_ADAPTER_DESCRIPTOR StorageAdapterDescriptor;
		STORAGE_DEVICE_DESCRIPTOR StorageDeviceDescriptor;

// printk("IOCTL_STORAGE_QUERY_PROPERTY (PropertyId: %08x / QueryType: %08x )!!\n", StoragePropertyQuery->PropertyId, StoragePropertyQuery->QueryType);

		switch (StoragePropertyQuery->QueryType) {
		case PropertyExistsQuery:
			switch (StoragePropertyQuery->PropertyId) {
			case StorageAdapterProperty:
			case StorageDeviceProperty:
			case StorageDeviceAttributesProperty:
			case StorageAccessAlignmentProperty:
			case StorageDeviceSeekPenaltyProperty:
			case StorageDeviceTrimProperty:
//			case StorageDeviceResiliencyProperty:
				status = STATUS_SUCCESS;
				break;
			default:
			}
			break;

		case PropertyStandardQuery:
			switch (StoragePropertyQuery->PropertyId) {
			case StorageAdapterProperty:
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
				/* This is important. SCSI interface does not
				 * work without this.
				 */
				StorageAdapterDescriptor.BusType = BusTypeScsi;
				RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &StorageAdapterDescriptor, CopySize);
				irp->IoStatus.Information = (ULONG_PTR)CopySize;
				status = STATUS_SUCCESS;

				break;
			case StorageDeviceProperty:
				char serial_number[100] = "fdfe98eb-9901-472f-a9bf-f3a6562c578a";
				int serial_number_length;

				CopySize = (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(STORAGE_DEVICE_DESCRIPTOR)?s->Parameters.DeviceIoControl.OutputBufferLength:sizeof(STORAGE_DEVICE_DESCRIPTOR));
				StorageDeviceDescriptor.Version = sizeof(STORAGE_DEVICE_DESCRIPTOR);
				StorageDeviceDescriptor.Size = sizeof(STORAGE_DEVICE_DESCRIPTOR);
				StorageDeviceDescriptor.DeviceType = DIRECT_ACCESS_DEVICE;
				StorageDeviceDescriptor.DeviceTypeModifier = 0;
				StorageDeviceDescriptor.RemovableMedia = FALSE;	/* TODO: TRUE? */
				StorageDeviceDescriptor.CommandQueueing = FALSE;
				StorageDeviceDescriptor.VendorIdOffset = 0;
				StorageDeviceDescriptor.ProductIdOffset = 0;
				StorageDeviceDescriptor.ProductRevisionOffset = 0;
				StorageDeviceDescriptor.SerialNumberOffset = 0;
				StorageDeviceDescriptor.BusType = BusTypeScsi;
				StorageDeviceDescriptor.RawPropertiesLength = 0;

				if (s->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(STORAGE_ADAPTER_DESCRIPTOR) + sizeof(serial_number)) {
					RtlCopyMemory(((char*) irp->AssociatedIrp.SystemBuffer)+sizeof(STORAGE_ADAPTER_DESCRIPTOR), serial_number, sizeof(serial_number));
					StorageDeviceDescriptor.SerialNumberOffset = sizeof(STORAGE_ADAPTER_DESCRIPTOR);
					serial_number_length = sizeof(serial_number);
				} else {
					serial_number_length = 0;
				}
				RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &StorageDeviceDescriptor, CopySize);
				irp->IoStatus.Information = (ULONG_PTR)CopySize+serial_number_length;
				status = STATUS_SUCCESS;

				break;
			case StorageDeviceAttributesProperty:
					/* seems to be undocumented ... */
// printk("StorageDeviceAttributesProperty ...\n");
				irp->IoStatus.Information = 0;
				status = STATUS_SUCCESS;
				break;

			case StorageAccessAlignmentProperty:
			{
				struct _STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR a;

				CopySize = (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(a)?s->Parameters.DeviceIoControl.OutputBufferLength:sizeof(a));
// printk("StorageAccessAlignmentProperty ...\n");
				a.Version = sizeof(a);
				a.Size = sizeof(a);
				a.BytesPerCacheLine = 16;
				a.BytesOffsetForCacheAlignment = 0;
				a.BytesPerLogicalSector = 512;
				a.BytesPerPhysicalSector = 512;
				a.BytesOffsetForSectorAlignment = 0;
				RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &a, CopySize);
				irp->IoStatus.Information = (ULONG_PTR)CopySize;
				status = STATUS_SUCCESS;
				break;
			}

			case StorageDeviceSeekPenaltyProperty:
			{
				struct _DEVICE_SEEK_PENALTY_DESCRIPTOR sp;

				CopySize = (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(sp)?s->Parameters.DeviceIoControl.OutputBufferLength:sizeof(sp));
// printk("StorageDeviceSeekPenaltyProperty ...\n");
				sp.Version = sizeof(sp);
				sp.Size = sizeof(sp);
					/* actually this depends on underlying
					 * storage.
					 */
				sp.IncursSeekPenalty = TRUE;

				RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &sp, CopySize);
				irp->IoStatus.Information = (ULONG_PTR)CopySize;
				status = STATUS_SUCCESS;
				break;
			}

			case StorageDeviceTrimProperty:
			{
				struct _DEVICE_TRIM_DESCRIPTOR trim;

				CopySize = (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(trim)?s->Parameters.DeviceIoControl.OutputBufferLength:sizeof(trim));
// printk("StorageDeviceTrimProperty ...\n");
				trim.Version = sizeof(trim);
				trim.Size = sizeof(trim);
					/* TRIM not implemented till now. TODO: 
					 * Change this value once TRIM is
					 * supported.
					 */
				trim.TrimEnabled = FALSE;

				RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &trim, CopySize);
				irp->IoStatus.Information = (ULONG_PTR)CopySize;
				status = STATUS_SUCCESS;
				break;
			default:
			}

#if 0
	/* This is "reserved for system use". ReFS calls this
         * to check if there is redundancy at device level.
	 * Well ... there is ..  but correctly filling out the
         * struct (https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ne-winioctl-storage_property_id).
         * depends on if we are currently connected to a
         * remote with up to date data and many other things.
         * I think best for now is just to say we do not support
         * it (if we return an invalid struct the device cannot be
         * formatted with ReFS).
	 */

			case StorageDeviceResiliencyProperty:
// printk("StorageDeviceResiliencyProperty ...\n");
				irp->IoStatus.Information = 0;
				status = STATUS_SUCCESS;
				break;
#endif
			}	/* switch PropertyId */
			break;
		default:
		}
		if (status != STATUS_SUCCESS) {
// printk("Invalid IOCTL_STORAGE_QUERY_PROPERTY (PropertyId: %08x / QueryType: %08x)!!\n", StoragePropertyQuery->PropertyId, StoragePropertyQuery->QueryType);
		}
		break;
   	}
	case IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER:
	{
		printk("IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER");
		status = STATUS_NO_SUCH_DEVICE;
		break;
	}

	case IOCTL_SCSI_GET_ADDRESS:
	{
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
	{
		struct _STORAGE_DEVICE_NUMBER* dn;
		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _STORAGE_DEVICE_NUMBER)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		dn = (struct _STORAGE_DEVICE_NUMBER*)irp->AssociatedIrp.SystemBuffer;

		dn->DeviceType = FILE_DEVICE_DISK; /* TODO: device->DeviceType? */
		dn->DeviceNumber = dev->minor;
		dn->PartitionNumber = -1;

		irp->IoStatus.Information = sizeof(struct _STORAGE_DEVICE_NUMBER);
		status = STATUS_SUCCESS;
		break;
	}

	case IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES:
	{
// printk("IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES\n");
		struct _DEVICE_MANAGE_DATA_SET_ATTRIBUTES* attrs =
			(struct _DEVICE_MANAGE_DATA_SET_ATTRIBUTES*)irp->AssociatedIrp.SystemBuffer;

		if ((s->Parameters.DeviceIoControl.InputBufferLength <
			sizeof(struct _DEVICE_MANAGE_DATA_SET_ATTRIBUTES)) ||
			(s->Parameters.DeviceIoControl.InputBufferLength <
				(attrs->DataSetRangesOffset + attrs->DataSetRangesLength))) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
// printk("attrs->Action is %d flag is %d\n", attrs->Action, attrs->Flags);
		if (attrs->Action != DeviceDsmAction_Trim) {
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
//		int items = attrs->DataSetRangesLength / sizeof(DEVICE_DATA_SET_RANGE);

// printk("%d items\n", items);

		// status = STATUS_SUCCESS;
		status = STATUS_NOT_SUPPORTED;
		irp->IoStatus.Information = 0;
		/* TODO: trim */

		break;
	}

	/* from reactos */

#define IOCTL_VOLUME_BASE                 ((ULONG) 'V')
#define IOCTL_VOLUME_IS_PARTITION \
  CTL_CODE(IOCTL_VOLUME_BASE, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)

	case IOCTL_VOLUME_IS_PARTITION:
		dbg(KERN_DEBUG "IOCTL_VOLUME_IS_PARTITION: s->Parameters.DeviceIoControl.InputBufferLength is %d s->Parameters.DeviceIoControl.OutputBufferLength is %d\n", s->Parameters.DeviceIoControl.InputBufferLength, s->Parameters.DeviceIoControl.OutputBufferLength);

		status = STATUS_SUCCESS;
		break;

	case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
	{
		struct _DRIVE_LAYOUT_INFORMATION_EX* dli;

// printk(KERN_DEBUG "IOCTL_DISK_GET_DRIVE_LAYOUT_EX: s->Parameters.DeviceIoControl.InputBufferLength is %d s->Parameters.DeviceIoControl.OutputBufferLength is %d\n", s->Parameters.DeviceIoControl.InputBufferLength, s->Parameters.DeviceIoControl.OutputBufferLength);

		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct _DRIVE_LAYOUT_INFORMATION_EX)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		dli = (struct _DRIVE_LAYOUT_INFORMATION_EX*)irp->AssociatedIrp.SystemBuffer;

		dli->PartitionStyle = 0;	/* MBR */
		dli->PartitionCount = 1;
		dli->Mbr.Signature = 0x12345678;
		//		dli->Mbr.Checksum = 0;

		fill_partition_info_ex(&dli->PartitionEntry[0], dev);
		irp->IoStatus.Information = sizeof(struct _DRIVE_LAYOUT_INFORMATION_EX);

		status = STATUS_SUCCESS;
		break;
	}

/*
	case IOCTL_VOLUME_GET_GPT_ATTRIBUTES:
	{
		struct _VOLUME_GET_GPT_ATTRIBUTES_INFORMATION *gpt_attrs;


		if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(*gpt_attrs)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		gpt_attrs = (struct _VOLUME_GET_GPT_ATTRIBUTES_INFORMATION*) irp->AssociatedIrp.SystemBuffer;

		gpt_attrs->GptAttributes = GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER;
		irp->IoStatus.Information = sizeof(*gpt_attrs);

		status = STATUS_SUCCESS;
		break;
	}
*/

	default:
// printk(KERN_DEBUG "DRBD IoCtl request not implemented: IoControlCode: 0x%x\n", s->Parameters.DeviceIoControl.IoControlCode);

		status = STATUS_INVALID_PARAMETER;
	}

out:
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
}

static NTSTATUS __attribute__((stdcall)) windrbd_create(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	if (device == mvolRootDeviceObject || device == user_device_object || device == drbd_bus_device) {
		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == NULL || ref->bdev == NULL || ref->bdev->delete_pending) {
		dbg(KERN_WARNING "Device %p accessed after it was deleted.\n", device);

dbg("ref is %p\n", ref);
if (ref != NULL)
dbg("ref->bdev is %p, delete_pending is %d\n", ref->bdev, ref->bdev->delete_pending);

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
		dbg(KERN_DEBUG "s->Parameters.Create.SecurityContext->DesiredAccess is %x\n", s->Parameters.Create.SecurityContext->DesiredAccess);
		dbg(KERN_DEBUG "s->Parameters.Create.FileAttributes is %x\n", s->Parameters.Create.FileAttributes);
		dbg(KERN_DEBUG "s->Parameters.Create.Options is %x\n", s->Parameters.Create.Options);
		dbg(KERN_DEBUG "FILE_WRITE_DATA is %x\n", FILE_WRITE_DATA);
		if (s->FileObject != NULL) {
			dbg(KERN_DEBUG "file object is %p write access is %d\n", s->FileObject, s->FileObject->WriteAccess);
		} else {
			dbg(KERN_DEBUG "file object is NULL\n");
		}

		if (dev->is_bootdevice) {
dbg("into wait_for_becoming_primary\n");
			status = wait_for_becoming_primary(dev->drbd_device->vdisk->part0);
dbg("out of wait_for_becoming_primary, status is %x\n", status);
			if (status != STATUS_SUCCESS)
				goto exit;
		}

		mode = (s->Parameters.Create.SecurityContext->DesiredAccess &
       	               (FILE_WRITE_DATA  | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_APPEND_DATA | GENERIC_WRITE)) ? FMODE_WRITE : 0;

		dbg(KERN_INFO "DRBD device  request: opening DRBD device %s\n",
			mode == 0 ? "read-only" : "read-write");

#ifdef DRBD_9_1
		err = dev->bd_disk->fops->open(dev->bd_disk, mode);
#else
		err = dev->bd_disk->fops->open(dev, mode);
#endif
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
	if (status == STATUS_SUCCESS && dev != NULL) {
		dev->num_openers++;
		dbg("num_openers of device %p is now %d\n", dev, dev->num_openers);
	}
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	dbg(KERN_DEBUG "status is %x\n", status);
	return status;
}


static NTSTATUS __attribute__((stdcall)) windrbd_close(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	if (device == mvolRootDeviceObject || device == user_device_object || device == drbd_bus_device) {
		struct _IO_STACK_LOCATION *s2 = IoGetCurrentIrpStackLocation(irp);
		windrbd_delete_multicast_groups_for_file(s2->FileObject);

		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	struct block_device_reference *ref = device->DeviceExtension;
	NTSTATUS status;

	if (ref == NULL || ref->bdev == NULL || ref->bdev->delete_pending) {
		dbg(KERN_WARNING "Device %p accessed after it was deleted.\n", device);

		if (ref == NULL || ref->bdev == NULL)
			status = STATUS_NO_SUCH_DEVICE;
		else
			status = STATUS_SUCCESS;

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = 0;

	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}
	struct block_device *dev = ref->bdev;

	if (dev->drbd_device != NULL) {
/*	mode = (s->Parameters.Create.SecurityContext->DesiredAccess &
                (FILE_WRITE_DATA  | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_APPEND_DATA | GENERIC_WRITE)) ? FMODE_WRITE : 0; */

/*
		dbg(KERN_INFO "DRBD device close request: releasing DRBD device %s\n",
			mode == 0 ? "read-only" : "read-write");
*/

		if (dev->num_openers > 0)
#ifdef DRBD_9_1
			dev->bd_disk->fops->release(dev->bd_disk);
#else
			dev->bd_disk->fops->release(dev->bd_disk, 0);
#endif
		else
			printk("Warning: close called when there are no disk devices open.\n");

		status = STATUS_SUCCESS;
	} else {
		dbg("Close request while device isn't set up yet.\n");
			/* See comment in windrbd_create() */
		status = STATUS_SUCCESS;
	}

	if (status == STATUS_SUCCESS && dev != NULL) {
		if (dev->num_openers > 0)
			dev->num_openers--;

		dbg("num_openers of device %p is now %d\n", dev, dev->num_openers);
	}
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

static NTSTATUS __attribute__((stdcall)) windrbd_cleanup(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	if (device == mvolRootDeviceObject || device == user_device_object || device == drbd_bus_device) {
		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == NULL || ref->bdev == NULL || ref->bdev->delete_pending) {
		dbg(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
		irp->IoStatus.Information = 0;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_SUCH_DEVICE;
	}
	NTSTATUS status = STATUS_SUCCESS;

	dbg(KERN_INFO "Pretending that cleanup does something.\n");
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

/* TODO: this was for some testing? */
#if 0
static void dump_data(const char *tag, char *data, size_t len, size_t offset_on_disk)
{
	size_t i;

	for (i=0;i<len;i++) {
		printk("%s: %x %x\n", tag, offset_on_disk+i, (unsigned char) (data[i]));
	}
}

static int io_complete_thread(void *irp_p)
{
	uint64_t started, elapsed;
	struct _IRP *irp = (struct _IRP*) irp_p;

	started = jiffies;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	elapsed = jiffies - started;
	if (elapsed > 1000)
		printk("IoCompleteRequest %p took %lld ms.\n", irp, elapsed);

	return 0;
}
#endif

/* Limit imposed by DRBD over the wire protocol. This will not change
 * in the next 5+ years, most likely never.
 */

#define MAX_BIO_SIZE (1024*1024)

static void windrbd_bio_finished(struct bio * bio)
{
	PIRP irp = bio->bi_upper_irp;
	int i;
	NTSTATUS status;
	int error = blk_status_to_errno(bio->bi_status);

	if (irp == NULL) {
		printk("Internal error: irp is NULL in bio_finished, this should not happen.");
		return;
	}
// printk("1 error is %d bio is %p\n", error, bio);
// printk("bio->bi_vcnt is %d\n", bio->bi_vcnt);
	status = STATUS_SUCCESS;

	if (error == 0) {
		if (bio_data_dir(bio) == READ) {
			if (!bio->bi_common_data->bc_device_failed && bio->bi_upper_irp && bio->bi_upper_irp->MdlAddress) {
				char *user_buffer = bio->bi_upper_irp_buffer;
				if (user_buffer != NULL) {
					int offset;

					offset = bio->bi_mdl_offset;
					for (i=0;i<bio->bi_vcnt;i++) {
						RtlCopyMemory(user_buffer+offset, ((char*)bio->bi_io_vec[i].bv_page->addr)+bio->bi_io_vec[i].bv_offset, bio->bi_io_vec[i].bv_len);
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
// printk("2\n");
	if (bio_data_dir(bio) == READ) {
// printk("free page contents %p ...\n", bio);
		for (i=0;i<bio->bi_vcnt;i++) {
// printk("free page contents bio->bi_io_vec[i].bv_page->addr is %p i is %d ...\n", bio->bi_io_vec[i].bv_page->addr, i);
			put_page(bio->bi_io_vec[i].bv_page);
//			kfree(bio->bi_io_vec[i].bv_page->addr);
		}
	}

#if 0
		/* Set addr to NULL so that a free_page() later on
		 * (on put_page() at the end of this function) will
		 * not free the page again (or free an invalid address).
		 */

	for (i=0;i<bio->bi_vcnt;i++) {
		bio->bi_io_vec[i].bv_page->addr = NULL;
	}
#endif

	KIRQL flags;

		/* TODO: later when we patch out the extra copy
		 * on read, this also can be done much easier.
		 */

	int total_num_completed = bio->bi_common_data->bc_num_requests;
	size_t total_size = bio->bi_common_data->bc_total_size;

        spin_lock_irqsave(&bio->bi_common_data->bc_device_failed_lock, flags);
        int num_completed = atomic_inc_return(&bio->bi_common_data->bc_num_completed);
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

#if 0
			/* do not complete? */
		if (about_to_remove_irp(irp, bio->bi_bdev) != 0)
			printk("XXX IRP %p not registered, let's see what happens\n", irp);

//		spin_lock_irqsave(&bio->bi_bdev->complete_request_spinlock, flags);
#endif
//		kthread_run(io_complete_thread, irp, "complete-irp");

		if (bio_data_dir(bio) == WRITE)
				/* Signal free_mdl thread that it should
				 * complete the IRP.
				 */
			bio->delayed_io_completion = true;
		else
			IoCompleteRequest(irp, status != STATUS_SUCCESS ? IO_NO_INCREMENT : IO_DISK_INCREMENT);
#if 0
		if (!irp_already_completed(irp))
			IoCompleteRequest(irp, IO_NO_INCREMENT);

		if (really_remove_irp(irp, bio->bi_bdev) != 0)
			printk("XXX IRP %p not registered, let's see what happens\n", irp);

// printk("out of IoCompleteRequest irp is %p\n", irp);
//		spin_unlock_irqrestore(&bio->bi_bdev->complete_request_spinlock, flags);
	printk("XXX out of IoCompleteRequest irp is %p sector is %lld\n", irp, bio->bi_iter.bi_sector);
#endif

		kfree(bio->bi_common_data);
	}
	IoReleaseRemoveLock(&bio->bi_bdev->ref->w_remove_lock, NULL);

		/* TODO: solves memory leak? */
		/* Where is the get_page for this? */
	if (bio_data_dir(bio) == WRITE) {
		for (i=0;i<bio->bi_vcnt;i++)
			put_page(bio->bi_io_vec[i].bv_page);
	}
	bio_put(bio);
}

static void windrbd_internal_io_finished(struct bio * bio)
{
/*	IoReleaseRemoveLock(&bio->bi_bdev->ref->w_remove_lock, NULL); */
	KeSetEvent(bio->bi_io_finished_event, 0, FALSE);
}

struct io_request {
	struct work_struct w;
	struct drbd_device *drbd_device;
	struct bio *bio;
};

static void drbd_make_request_work(struct work_struct *w)
{
	struct io_request *ioreq = container_of(w, struct io_request, w);

// printk("1\n");
	atomic_inc(&ioreq->bio->bi_bdev->num_bios_pending);
	ioreq->bio->bi_bdev->bd_disk->fops->submit_bio(ioreq->bio);
// printk("2\n");
	kfree(ioreq);
}

	/* Create a bio from the parameters and submit I/O request to
	 * DRBD engine. If irp is NULL, wait for completion else use
         * windrbd_bio_finished to complete the IRP.
	 */

static NTSTATUS windrbd_make_drbd_requests(struct _IRP *irp, struct block_device *dev, char *buffer, unsigned int total_size, sector_t sector,
					   ULONG_PTR rw)
{
	struct bio *bio;

	int b;
	struct windrbd_bio_collection *common_data;
	struct _KEVENT event;
	NTSTATUS status;

	if (rw == WRITE && dev->drbd_device->resource->role[NOW] != R_PRIMARY) {
		printk("Attempt to write when not Primary\n");
		return STATUS_INVALID_PARAMETER;
	}
	if (sector * dev->bd_block_size >= dev->bd_inode->i_size) {
		dbg("Attempt to read past the end of the device: dev->bd_block_size is %d sector is %lld (%llu) byte offset is %lld (%llu) dev->bd_inode->i_size is %lld rw is %s\n", dev->bd_block_size, sector, sector, sector * dev->bd_block_size, sector * dev->bd_block_size, dev->bd_inode->i_size, rw == WRITE ? "WRITE" : "READ");
		return STATUS_INVALID_PARAMETER;
	}
	if (sector * dev->bd_block_size + total_size > dev->bd_inode->i_size) {
		dbg("Attempt to read past the end of the device, request shortened\n");
		total_size = dev->bd_inode->i_size - sector * dev->bd_block_size; 
	}
	if (total_size == 0) {
		printk("I/O request of size 0.\n");
		return STATUS_INVALID_PARAMETER;
	}
	if (buffer == NULL) {
		printk("I/O buffer (from MmGetSystemAddressForMdlSafe()) is NULL\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
			/* If suspended wait until not suspended. */
		status = KeWaitForSingleObject(&dev->io_not_suspended, Executive, KernelMode, FALSE, NULL);
		if (status != STATUS_SUCCESS) {
			printk("Error waiting for io_not_suspended event (%08x)\n", status);
			return status;
		}
	}	/* else we may not sleep - process the request */

	int bio_count = (total_size-1) / MAX_BIO_SIZE + 1;
	int this_bio_size;
	int last_bio_size = total_size % MAX_BIO_SIZE;
	if (last_bio_size == 0)
		last_bio_size = MAX_BIO_SIZE;

	common_data = kzalloc(sizeof(*common_data), GFP_KERNEL);
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

	if (irp != NULL) {
	        IoMarkIrpPending(irp);
	}

	int nr_io_vec_elm, i;
	size_t last_elm_size, this_elm_size;

	for (b=0; b<bio_count; b++) {
		this_bio_size = (b==bio_count-1) ? last_bio_size : MAX_BIO_SIZE;

		nr_io_vec_elm = DIV_ROUND_UP(this_bio_size, PAGE_SIZE);
		last_elm_size = this_bio_size % PAGE_SIZE;
		if (last_elm_size == 0)
			last_elm_size = PAGE_SIZE;

		bio = bio_alloc_old(GFP_NOIO, nr_io_vec_elm);
		if (bio == NULL) {
			printk("Couldn't allocate bio.\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		bio->bi_opf = (rw == WRITE ? REQ_OP_WRITE : REQ_OP_READ);
		bio->bi_bdev = dev;
		bio->bi_max_vecs = nr_io_vec_elm;
		bio->bi_vcnt = nr_io_vec_elm;
		bio->bi_paged_memory = (bio_data_dir(bio) == WRITE);
//		bio->force_mdl_unlock = 1;	/* TODO: ?? */
		bio->bi_iter.bi_size = this_bio_size;
		bio->bi_iter.bi_sector = sector + b*MAX_BIO_SIZE/dev->bd_block_size;
		bio->bi_upper_irp_buffer = buffer;
		bio->bi_mdl_offset = (unsigned long long)b*MAX_BIO_SIZE;
		bio->bi_common_data = common_data;
		bio->is_user_request = true;

cond_printk("%s sector: %d total_size: %d\n", rw == WRITE ? "WRITE" : "READ", sector, total_size);

		this_elm_size = PAGE_SIZE;
		for (i = 0; i < nr_io_vec_elm; i++) {
			if (i == nr_io_vec_elm - 1)
				this_elm_size = last_elm_size;

			bio->bi_io_vec[i].bv_page = kzalloc(sizeof(struct page), GFP_KERNEL);
			if (bio->bi_io_vec[i].bv_page == NULL) {
				printk("Couldn't allocate page.\n");
				return STATUS_INSUFFICIENT_RESOURCES; /* TODO: cleanup */
			}

			bio->bi_io_vec[i].bv_len = this_elm_size;
			kref_init(&bio->bi_io_vec[i].bv_page->kref);

			/* Corresponding put_page in the free-mdl
			 * thread (free_bios_thread_fn())
			 */
			get_page(bio->bi_io_vec[i].bv_page);


/*
 * TODO: eventually we want to make READ requests work without the
 *	 intermediate buffer and the extra copy.
 */


			if (irp != NULL && bio_data_dir(bio) == READ) {
				bio->bi_io_vec[i].bv_page->addr = kmalloc(this_elm_size, GFP_KERNEL);
			} else {
				bio->bi_io_vec[i].bv_page->addr = buffer+bio->bi_mdl_offset;
				bio->bi_io_vec[i].bv_page->is_system_buffer = 1;
			}

				/* TODO: fault inject here. */
			if (bio->bi_io_vec[i].bv_page->addr == NULL) {
				printk("Couldn't allocate temp buffer for read.\n");
				return STATUS_INSUFFICIENT_RESOURCES; /* TODO: cleanup */
			}

			bio->bi_io_vec[i].bv_offset = 0;
		}

		if (irp != NULL) {
			bio->bi_end_io = windrbd_bio_finished;
			bio->bi_upper_irp = irp;
		} else {
			bio->bi_end_io = windrbd_internal_io_finished;
			KeInitializeEvent(&event, NotificationEvent, FALSE);
			bio->bi_io_finished_event = &event;
		}

		if (dev->io_workqueue == NULL) {
			printk("Warning: dev->io_workqueue is NULL on I/O handler.\n");
			return -EINVAL;	/* TODO: cleanup */
		}
		part_stat_add(dev, sectors[bio_data_dir(bio) == READ ? STAT_READ : STAT_WRITE], this_bio_size / 512);
		/* drbd_make_request(dev->drbd_device->rq_queue, bio); */
		struct io_request *ioreq;

		ioreq = kzalloc(sizeof(*ioreq), GFP_KERNEL);
		if (ioreq == NULL) {
			return -ENOMEM;	/* TODO: cleanup */
		}
		INIT_WORK(&ioreq->w, drbd_make_request_work);

			/* No need for refcount. workqueue is flushed
			 * and destroyed when becoming secondary, so
			 * no in-flight requests on drbdadm down.
			 */
		ioreq->drbd_device = dev->drbd_device;
		ioreq->bio = bio;

		queue_work(dev->io_workqueue, &ioreq->w);

		if (irp == NULL) {
			NTSTATUS status;

			do {
		                status = KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
				if (status != STATUS_SUCCESS) {
					printk("Ouhh KeWaitForSingleObject returned status %x, don't really know what to do.\n", status);
					msleep(1000);
				}
			} while (status != STATUS_SUCCESS);

				/* And clean up */
			for (i = 0; i < nr_io_vec_elm; i++)
				put_page(bio->bi_io_vec[i].bv_page);

			kfree(bio->bi_common_data);
			bio_put(bio);
		}
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
	ULONG_PTR rw;

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

	buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | WinDRBDMdlMappingNoExecute);

	if (buffer == NULL) {
		printk("I/O buffer from MmGetSystemAddressForMdlSafe() is NULL\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	rw = s->MajorFunction == IRP_MJ_WRITE ? WRITE : READ;

	return windrbd_make_drbd_requests(irp, dev, buffer, total_size, sector, rw);
}

static NTSTATUS __attribute__((stdcall)) windrbd_io(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	if (device == mvolRootDeviceObject || device == user_device_object || device == drbd_bus_device) {
		dbg(KERN_WARNING "I/O on root device not supported.\n");

		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == NULL || ref->bdev == NULL || ref->bdev->delete_pending || ref->bdev->about_to_delete || ref->bdev->ref == NULL) {
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
	status = STATUS_INVALID_DEVICE_REQUEST;

	IoAcquireRemoveLock(&ref->w_remove_lock, NULL);
	if (dev->about_to_delete)
		goto exit_remove_lock;

	if (dev->is_bootdevice && dev->drbd_device->resource->role[NOW] != R_PRIMARY) {
		dbg("I/O request while not primary, waiting for primary.\n");

		status = wait_for_becoming_primary(dev->drbd_device->vdisk->part0);
		if (status != STATUS_SUCCESS)
			goto exit_remove_lock;
	}

		/* allow I/O when the local disk failed, usually there
		 * are peers which can handle the I/O. If not, DRBD will
		 * report an I/O error which we will get in our completion
		 * routine later and can report to the application.
		 */

	status = make_drbd_requests_from_irp(irp, dev);
	if (status != STATUS_SUCCESS)
		goto exit_remove_lock;

	return STATUS_PENDING;

exit_remove_lock:
	IoReleaseRemoveLock(&ref->w_remove_lock, NULL);

exit:
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
}

static NTSTATUS __attribute__((stdcall)) windrbd_shutdown(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	printk("Got SHUTDOWN request, assuming system is about to shut down\n");
	shutting_down = 1;

	if (device == mvolRootDeviceObject || device == user_device_object || device == drbd_bus_device) {
		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	printk("System shutdown, for now, don't clean up, there might be DRBD resources online\nin which case we would crash the system.\n");

	printk("device: %p irp: %p\n", device, irp);

/* TODO: signal the devices waiting for primary that it should stop
 * waiting now.
 */
#if 0
	if (device == mvolRootDeviceObject)
		drbd_cleanup();

/* TODO: clean up logging. */
#endif

	irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
}

static void windrbd_bio_flush_finished(struct bio * bio)
{
	PIRP irp = bio->bi_upper_irp;
	int error = blk_status_to_errno(bio->bi_status);

	if (error == 0) {
		irp->IoStatus.Information = bio->bi_iter.bi_size;
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

static NTSTATUS __attribute__((stdcall)) windrbd_flush(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	if (device == mvolRootDeviceObject || device == user_device_object || device == drbd_bus_device) {
		dbg(KERN_WARNING "Flush on root device not supported.\n");

		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == NULL || ref->bdev == NULL || ref->bdev->delete_pending) {
		dbg(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
		irp->IoStatus.Information = 0;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_SUCH_DEVICE;
	}
	struct block_device *dev = ref->bdev;
	struct bio *bio;
	NTSTATUS status;

	bio = bio_alloc_old(GFP_NOIO, 0);
	if (bio == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto exit;
	}
	bio->bi_opf = REQ_OP_WRITE | REQ_PREFLUSH;
	bio->bi_iter.bi_size = 0;
	bio->bi_end_io = windrbd_bio_flush_finished;
	bio->bi_upper_irp = irp;
	bio->bi_bdev = dev;

        IoMarkIrpPending(irp);
	drbd_submit_bio(bio);
		/* The irp may be already invalid here. */
	return STATUS_PENDING;

exit:
	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
}

static NTSTATUS __attribute__((stdcall)) start_completed(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID event_param)
{
	PKEVENT event = event_param;

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
		idr_for_each_entry(&resource->devices, drbd_device, vnr) {
			if (drbd_device && drbd_device->vdisk && drbd_device->vdisk->part0 && !drbd_device->vdisk->part0->delete_pending && drbd_device->vdisk->part0->windows_device != NULL) {
				if (count < max && array != NULL) {
					array[count] = drbd_device->vdisk->part0->windows_device;
					ObReferenceObject(drbd_device->vdisk->part0->windows_device);
				}
				dbg("windows device at %p\n", drbd_device->vdisk->part0->windows_device);
				count++;
			}
		}
	}
	dbg("%d drbd windows devices found\n", count);
	return count;
}

extern void windrbd_bus_is_ready(void);

static NTSTATUS __attribute__((stdcall)) windrbd_pnp_bus_device(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	int minor_function = s->MinorFunction;
	struct _BUS_EXTENSION *bus_ext = (struct _BUS_EXTENSION*) device->DeviceExtension;
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	KEVENT start_completed_event;

	switch (minor_function) {
	case IRP_MN_START_DEVICE:
		KeInitializeEvent(&start_completed_event, NotificationEvent, FALSE);
		IoCopyCurrentIrpStackLocationToNext(irp);
		IoSetCompletionRoutine(irp, start_completed, (PVOID)&start_completed_event, TRUE, TRUE, TRUE);

		status = IoCallDriver(bus_ext->lower_device, irp);
		if (status == STATUS_PENDING)
			KeWaitForSingleObject(&start_completed_event, Executive, KernelMode, FALSE, NULL);

		status = irp->IoStatus.Status;
		if (status != STATUS_SUCCESS)
			printk("Warning: lower device start returned %x\n", status);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		windrbd_bus_is_ready();
		return status;

	case IRP_MN_REMOVE_DEVICE:
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoSkipCurrentIrpStackLocation(irp);

		status = IoCallDriver(bus_ext->lower_device, irp);

		IoDetachDevice(bus_ext->lower_device);
		IoDeleteDevice(device);

			/* This should allow unload of the driver
			 * once there are also no primary DRBD resources
			 */

		module_put(&windrbd_module);

		drbd_bus_device = NULL;
		/* Also nullify drbd_physical_bus_device else
		 * BSOD on windrbd_rescan_bus later.
		 */
		drbd_physical_bus_device = NULL;

		return status; /* must not do IoCompleteRequest */
			/* This is done (?) in IoCallDriver */

	case IRP_MN_QUERY_DEVICE_RELATIONS:
		if (s->Parameters.QueryDeviceRelations.Type == BusRelations) {
			int num_devices;
			struct _DEVICE_RELATIONS *device_relations;
			int n;
			size_t siz;

				/* In rare cases, when devices are being removed
				 * number of devices may differ between the
				 * first call and the second call. In that
				 * case do it all over again. This should fix
				 * a BSOD on secondary we observed.
				 */
			do {
				num_devices = get_all_drbd_device_objects(NULL, 0);
				siz = sizeof(*device_relations)+num_devices*sizeof(device_relations->Objects[0]);
		/* must be PagedPool else PnP manager complains */
				device_relations = ExAllocatePoolWithTag(PagedPool, siz, DRBD_TAG);
				if (device_relations == NULL) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit;
				}
				RtlZeroMemory(device_relations, siz);
				n = get_all_drbd_device_objects(&device_relations->Objects[0], num_devices);
				if (n != num_devices) {
					printk("Warning: number of DRBD devices changed: old %d != new %d\n", num_devices, n);
					ExFreePool(device_relations);
				}
			} while (n != num_devices);

			device_relations->Count = num_devices;
			irp->IoStatus.Information = (ULONG_PTR)device_relations;
			irp->IoStatus.Status = STATUS_SUCCESS;

			IoCopyCurrentIrpStackLocationToNext(irp);
			status = IoCallDriver(bus_ext->lower_device, irp);
			if (status != STATUS_SUCCESS)
				printk("Warning: lower device returned status %x\n", status);
			return status;
		}
		break;
	}

exit:
	if (!NT_SUCCESS(status)) {
		IoSkipCurrentIrpStackLocation(irp);
		status = IoCallDriver(bus_ext->lower_device, irp);
	/* Keep in mind that irp and s are invalid from here on */
		if (status != STATUS_SUCCESS && status != STATUS_NOT_SUPPORTED)
			printk("Warning: lower device returned status %x for minor function 0x%02x\n", status, minor_function);
	} else {
		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}
	return status;
}

static NTSTATUS __attribute__((stdcall)) windrbd_pnp(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	NTSTATUS status;

		/* TODO: mux */
	if (device == mvolRootDeviceObject || device == user_device_object) {
		dbg(KERN_WARNING "PNP requests on root device not supported.\n");

		status = STATUS_NOT_SUPPORTED;
		goto out;
	}
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);

		/* TODO: can this ever happen? */
	if (s == NULL) {
		printk("Warning: IoGetCurrentIrpStackLocation(%p) is NULL\n", irp);
		status = STATUS_INVALID_DEVICE_REQUEST;
		goto out;
	}

		/* TODO: have a device MUX mechanism ... */
	if (device == drbd_bus_device)
		return windrbd_pnp_bus_device(device, irp);

	struct block_device_reference *ref = device->DeviceExtension;
	struct block_device *bdev = NULL;
	struct drbd_device *drbd_device = NULL;
	int minor = -1;

	if (ref != NULL) {
		bdev = ref->bdev;
		if (bdev != NULL) {
			drbd_device = bdev->drbd_device;
			if (drbd_device != NULL)
				minor = drbd_device->minor;
		}
	}
	if (minor == -1) {
		printk("Warning: got a PnP request when there is no DRBD minor associated\n");
		status = STATUS_INVALID_DEVICE_REQUEST;
		goto out;
	}

	switch (s->MinorFunction) {
	case IRP_MN_START_DEVICE:
		KeSetEvent(&bdev->device_started_event, 0, FALSE);

		status = STATUS_SUCCESS;
		break;

	case IRP_MN_QUERY_PNP_DEVICE_STATE:
		irp->IoStatus.Information = 0;
		status = STATUS_SUCCESS;
		break;

	case IRP_MN_QUERY_ID:
	{
		wchar_t *string;
		int len;

/* TODO: how do we know: ? */
#define MAX_ID_LEN 512

/* Do not use kmalloc(GFP_USER, ...) here .. this is passed to user level
 * who will use something like ExFreePool() and not kfree().
 */
		string = ExAllocatePoolWithTag(PagedPool, MAX_ID_LEN*sizeof(wchar_t), DRBD_TAG);
		if (string == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		memset(string, 0, MAX_ID_LEN*sizeof(wchar_t));
		switch (s->Parameters.QueryId.IdType) {
		case BusQueryDeviceID:
			/* SCSI\\t\*v(8)p(16)r(4) */
			_snwprintf(string, MAX_ID_LEN, L"SCSI\\DiskVENLINBITWINDRBDDISK_____0000");
			status = STATUS_SUCCESS;
			break;
		case BusQueryInstanceID:
			_snwprintf(string, MAX_ID_LEN, L"WinDRBD%d", minor);
			status = STATUS_SUCCESS;
			break;
		case BusQueryHardwareIDs:
			len = _snwprintf(string, MAX_ID_LEN, L"SCSI\\DiskLinbit____________WinDRBD0001");
			len += _snwprintf(&string[len+1], MAX_ID_LEN-len-1, L"SCSI\\DiskLinbit____________WinDRBD")+1;
			len += _snwprintf(&string[len+1], MAX_ID_LEN-len-1, L"SCSI\\DiskLinbit__")+1;
			len += _snwprintf(&string[len+1], MAX_ID_LEN-len-1, L"SCSI\\Linbit____________WinDRBD0")+1;
			len += _snwprintf(&string[len+1], MAX_ID_LEN-len-1, L"Linbit____________WinDRBD0")+1;
			_snwprintf(&string[len+1], MAX_ID_LEN-len-1, L"GenDisk");
			status = STATUS_SUCCESS;
			break;
		case BusQueryCompatibleIDs:
			len = _snwprintf(string, MAX_ID_LEN, L"WinDRBDDisk");
			_snwprintf(&string[len+1], MAX_ID_LEN-len-1, L"GenDisk");
			status = STATUS_SUCCESS;
			break;
		case BusQueryDeviceSerialNumber:
			_snwprintf(string, MAX_ID_LEN, L"%d", minor);
			status = STATUS_SUCCESS;
			break;
		case 5:	/* TODO: really? */
			_snwprintf(string, MAX_ID_LEN, L"%d", minor);
			status = STATUS_SUCCESS;
			break;
		default: /* -1, ... */
			status = irp->IoStatus.Status;
			ExFreePoolWithTag(string, DRBD_TAG);
			goto out_dont_change_status;
		}
		if (status == STATUS_SUCCESS)
			irp->IoStatus.Information = (ULONG_PTR) string;

		break;
	}

	case IRP_MN_QUERY_DEVICE_RELATIONS:
		switch (s->Parameters.QueryDeviceRelations.Type) {
		case TargetDeviceRelation:
		{
			struct _DEVICE_RELATIONS *device_relations;
			size_t siz = sizeof(*device_relations)+sizeof(device_relations->Objects[0]);
		/* must be PagedPool else PnP manager complains */
			device_relations = ExAllocatePoolWithTag(PagedPool, siz, DRBD_TAG);
			if (device_relations == NULL) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(device_relations, siz);
			device_relations->Count = 1;
			device_relations->Objects[0] = device;
			ObReferenceObject(device);

			irp->IoStatus.Information = (ULONG_PTR)device_relations;
			status = STATUS_SUCCESS;
			break;
		}

		case BusRelations:
		case RemovalRelations:
		case EjectionRelations:
		{
			struct _DEVICE_RELATIONS *device_relations;
			size_t siz = sizeof(*device_relations);

		/* must be PagedPool else PnP manager complains */
			device_relations = ExAllocatePoolWithTag(PagedPool, siz, DRBD_TAG);
			if (device_relations == NULL) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(device_relations, siz);
			device_relations->Count = 0;
			irp->IoStatus.Information = (ULONG_PTR)device_relations;
			status = STATUS_SUCCESS;
			break;
		}
		default:
			status = irp->IoStatus.Status;

			goto out_dont_change_status;
		}
		break;

	case IRP_MN_QUERY_DEVICE_TEXT:
	{
		wchar_t *string = NULL;

		if ((string = (PWCHAR)ExAllocatePoolWithTag(PagedPool, (MAX_ID_LEN * sizeof(WCHAR)), DRBD_TAG)) == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		RtlZeroMemory(string, (MAX_ID_LEN * sizeof(WCHAR)));
		switch (s->Parameters.QueryDeviceText.DeviceTextType ) {
		case DeviceTextDescription:
			_snwprintf(string, MAX_ID_LEN, L"WinDRBD Disk");
			irp->IoStatus.Information = (ULONG_PTR)string;
			status = STATUS_SUCCESS;
			break;

		case DeviceTextLocationInformation:
			_snwprintf(string, MAX_ID_LEN, L"WinDRBD Minor %d", minor);
			irp->IoStatus.Information = (ULONG_PTR)string;
			status = STATUS_SUCCESS;
			break;

		default:
			status = irp->IoStatus.Status;

			ExFreePoolWithTag(string, DRBD_TAG);
			irp->IoStatus.Information = 0;
			goto out_dont_change_status;
		}
		break;
	}
	case IRP_MN_QUERY_BUS_INFORMATION:
	{
		struct _PNP_BUS_INFORMATION *bus_info;

		bus_info = ExAllocatePoolWithTag(PagedPool, sizeof(*bus_info), DRBD_TAG);
		if (bus_info  == NULL) {
		        status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		RtlZeroMemory(bus_info, sizeof(*bus_info));

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
		if (DeviceCapabilities->Version != 1 || DeviceCapabilities->Size < sizeof(DEVICE_CAPABILITIES)) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		DeviceCapabilities->DeviceState[PowerSystemWorking] = PowerDeviceD0;
		if (DeviceCapabilities->DeviceState[PowerSystemSleeping1] != PowerDeviceD0)
			DeviceCapabilities->DeviceState[PowerSystemSleeping1] = PowerDeviceD1;
		if (DeviceCapabilities->DeviceState[PowerSystemSleeping2] != PowerDeviceD0)
			DeviceCapabilities->DeviceState[PowerSystemSleeping2] = PowerDeviceD3;
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
		DeviceCapabilities->Removable = TRUE;
		DeviceCapabilities->SurpriseRemovalOK = TRUE;
			/* WinDRBD minors are unique on the system */
		DeviceCapabilities->UniqueID = TRUE;
		DeviceCapabilities->SilentInstall = FALSE;

		status = STATUS_SUCCESS;
		break;
	}

	case IRP_MN_QUERY_REMOVE_DEVICE:
		if (bdev->delete_pending) {
			status = STATUS_SUCCESS;
		} else {
			printk("Someone has requested to remove this device (for example via disabling in device manager).\n");
			printk("Always use drbdadm to remove a WinDRBD disk device (drbdadm secondary or drbdadm down)\n");
			status = STATUS_NOT_SUPPORTED;
		}
		break;

	case IRP_MN_SURPRISE_REMOVAL:		/* ReactOS requires this */
		status = STATUS_SUCCESS;
		break;

	case IRP_MN_REMOVE_DEVICE:
		if (!bdev->delete_pending) {
			printk("Someone has requested to remove this device (for example via disabling in device manager).\n");
			printk("Always use drbdadm to remove a WinDRBD disk device (drbdadm secondary or drbdadm down)\n");
			status = STATUS_NOT_SUPPORTED;
			break;
		}
		bdev->about_to_delete = 1; /* meaning no more I/O on that device */

			/* see https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-remove-locks */
		IoAcquireRemoveLock(&bdev->ref->w_remove_lock, NULL);
			/* TODO: there is a ReactOS bug in that function: ? */
		IoReleaseRemoveLockAndWait(&bdev->ref->w_remove_lock, NULL);

		printk(KERN_DEBUG "About to delete device object %p\n", device);

				/* Avoid anything more happening to that
				 * device. Reason is that there is a reference
				 * count on the device, so it might still
				 * exist for a short period.
				 */
		bdev->ref = NULL;
		IoDeleteDevice(device);
		KeSetEvent(&bdev->device_removed_event, 0, FALSE);

		status = STATUS_SUCCESS;
		break;

	default:
		status = irp->IoStatus.Status;
		goto out_dont_change_status;
	}
out:
	irp->IoStatus.Status = status;
out_dont_change_status:
        IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

static NTSTATUS __attribute__((stdcall)) windrbd_power(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status;

printk(KERN_DEBUG "got Power device request: MajorFunction: 0x%x, MinorFunction: %x\n", s->MajorFunction, s->MinorFunction);

	if (device == mvolRootDeviceObject || device == user_device_object) {
printk(KERN_WARNING "Power requests on root device not supported. Returning SUCCESS to fix a BSOD on shutdown on Windows 2003 Server\n");

		status = STATUS_SUCCESS;
		irp->IoStatus.Status = status;
//		status = irp->IoStatus.Status;

	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}
printk("Power: device: %p irp: %p\n", device, irp);

	if (s->MinorFunction == IRP_MN_QUERY_POWER) {
		dbg("is IRP_MN_QUERY_POWER for %d\n", s->Parameters.Power.Type);
	}
	if (s->MinorFunction == IRP_MN_SET_POWER) {
		dbg("is IRP_MN_SET_POWER for %d\n", s->Parameters.Power.Type);
	}

	PoStartNextPowerIrp(irp);
	if (device == drbd_bus_device) {
		struct _BUS_EXTENSION *bus_ext = (struct _BUS_EXTENSION*) device->DeviceExtension;
//		IoSkipCurrentIrpStackLocation(irp);
printk("Calling PoCallDriver ...\n");
		status = PoCallDriver(bus_ext->lower_device, irp);
printk("PoCallDriver returned %x\n", status);
//		status = STATUS_SUCCESS;
	} else {
			/* TODO: if powering up after sleep / hibernate
			 * unset this flag again.
			 */

		if (s->MinorFunction == IRP_MN_QUERY_POWER &&
		    s->Parameters.Power.Type == SystemPowerState) {
			struct block_device_reference *ref = device->DeviceExtension;
			struct block_device *bdev;

			if (ref != NULL) {
				bdev = ref->bdev;
				if (bdev) {
					printk("About to power down device %p, not trying to become primary any more.\n", device);
					bdev->powering_down = 1;
						/* Wake up those waiting for us */
					KeSetEvent(&bdev->primary_event, 0, FALSE);
					KeSetEvent(&bdev->capacity_event, 0, FALSE);
				}
			}
		}

		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		status = STATUS_SUCCESS;
	}

printk("status is %x\n", status);
	return status;
}

/* This is for Windows management interface which we do not support.
 * Must forward requests to next lower driver.
 */

static NTSTATUS __attribute__((stdcall)) windrbd_sysctl(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (device == mvolRootDeviceObject || device == user_device_object) {
		dbg(KERN_WARNING "Sysctl requests on root device not supported.\n");

		irp->IoStatus.Status = STATUS_SUCCESS;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	if (device == drbd_bus_device) {
		struct _BUS_EXTENSION *bus_ext = (struct _BUS_EXTENSION*) device->DeviceExtension;

		IoSkipCurrentIrpStackLocation(irp);
		status = IoCallDriver(bus_ext->lower_device, irp);
		dbg("sysctl lower object returned %x\n", status);
	} else  {
			/* a disk */
	/* most likely we need to forward that to the lower (=bus) device */
		if (drbd_bus_device != NULL) {
			IoSkipCurrentIrpStackLocation(irp);
			dbg("calling sysctl bus device\n", status);
			status = IoCallDriver(drbd_bus_device, irp);
			dbg("sysctl lower object returned %x\n", status);
		} else {
				/* verifier would complain about this */
			irp->IoStatus.Status = STATUS_SUCCESS;
		        IoCompleteRequest(irp, IO_NO_INCREMENT);
			return irp->IoStatus.Status;
		}
	}
	return status;
}
	/* When installing WinDRBD as PnP Disk driver, the disk.sys driver
	 * is stacked over us and will send us SCSI requests. Some of them
	 * are implemented here (like read/write), others like TRIM
	 * or WRITESAME are not supported yet.
	 */

static long long wait_for_size(struct _DEVICE_OBJECT *device)
{
	struct block_device_reference *ref;
	struct block_device *bdev = NULL;
	NTSTATUS status;
	long long d_size = -1;

	ref = device->DeviceExtension;
	if (ref != NULL) {
		bdev = ref->bdev;

		if (bdev != NULL && !bdev->delete_pending && !bdev->powering_down && !shutting_down) {

		/* This is racy: if refcount is 0 here, it is incremented
		 * again and the destroy function is called twice for
		 * the same object (later in windrbd_bdput(). We now have
		 * RemoveLocks around the I/O paths and will wait in
		 * REMOVE_DEVICE for completion of all I/O including
		 * this one.
		 */
//			windrbd_bdget(bdev);

			dbg("waiting for block device size to become valid.\n");
		/* Windows 10: it BSODs with a DRIVER_PNP_WATCHDOG if
		 * it cannot complete within 5-6 minutes. Report an
		 * error in getting size. TODO: trigger the watchdog.
		 */

			status = KeWaitForSingleObject(&bdev->capacity_event, Executive, KernelMode, FALSE, NULL);
			if (status == STATUS_SUCCESS) {
				dbg("Got size now, proceeding with I/O request\n");

				if (!bdev->powering_down && !bdev->delete_pending && !shutting_down)  {
					if (bdev->bd_inode->i_size > 0) {
						dbg("block device size is %lld\n", bdev->bd_inode->i_size);
						d_size = bdev->bd_inode->i_size;
					} else {
						dbg("Warning: block device size still not known yet.\n");
					}
				} else {
					dbg("Warning: device object about to be deleted\n");
				}
			}
			else {
				dbg("KeWaitForSingleObject returned %x\n", status);
			}
//			windrbd_bdput(bdev);
		}
	} else {
		dbg("ref is NULL!\n");
	}
	return d_size;
}

static void fake_partition_table(struct block_device *bdev)
{
	char *partition_table, *backup_partition_table;
	void *old_partition_table, *old_backup_partition_table;
	char my_disk_guid[16];
	char my_partition_guid[16];
	uint64_t old_partition_size = 0;

		/* Do not change size of a partition here. Windows
		 * would then reenumerate the mount points causing
		 * running services to crash.
		 */

	if (bdev->disk_prolog != NULL) {
		old_partition_size = *(uint64_t*)(bdev->disk_prolog+0x428);
		printk("Found old partition size to be %llu bytes, not going to change it.\n", old_partition_size);
	}
	if (bdev->has_guids) {
		memcpy(my_disk_guid, bdev->disk_guid, 16);
		memcpy(my_partition_guid, bdev->partition_guid, 16);
	} else {
			/* Non - NTFS file systems. They also have a VSN somewhere ... */
		get_random_bytes(my_disk_guid, sizeof(my_disk_guid));
		get_random_bytes(my_partition_guid, sizeof(my_partition_guid));
	}

	/* GPT header (at 0x200):
		0x10 CRC32 of header (offset +0 to +0x5b) in little endian, with this field zeroed during calculation
		0x20 Backup LBA (location of the other header copy)
		0x30 Last usable LBA (secondary partition table first LBA − 1)
		0x38 Disk GUID in mixed endian (random for now?)
		0x58 CRC32 of partition entries array in little endian

	   partition table entry (at 0x400):
		0x10 Unique partition GUID (mixed endian)
		0x28 Last LBA (inclusive, usually odd)
	*/
	partition_table = kzalloc(bdev->data_shift*512, GFP_KERNEL);
	if (partition_table == NULL) {
		printk("Warning: Not enough memory for partition table.\n");
		return;
	}
	backup_partition_table = kzalloc(bdev->appended_sectors*512, GFP_KERNEL);
	if (backup_partition_table == NULL) {
		kfree(partition_table);
		printk("Warning: Not enough memory for partition table.\n");
		return;
	}
	memcpy(partition_table, partition_table_template, partition_table_template_size);

		/* Boot sector. MBR style - present disk as one big partition */
	*(uint32_t*)(partition_table+0x1ca) = (bdev->bd_inode->i_size/512)+bdev->data_shift+bdev->appended_sectors-1;
		/* TODO: we assume that CPU is little endian here ... */
	*(uint64_t*)(partition_table+0x220) = (bdev->bd_inode->i_size/512)+bdev->data_shift+bdev->appended_sectors-1;
	*(uint64_t*)(partition_table+0x230) = (bdev->bd_inode->i_size/512)+bdev->data_shift-1;
	if (old_partition_size != 0) {
		*(uint64_t*)(partition_table+0x428) = old_partition_size;
	} else {
		*(uint64_t*)(partition_table+0x428) = (bdev->bd_inode->i_size/512)+bdev->data_shift-1;
	}

	memcpy(partition_table+0x238, my_disk_guid, 16);
	memcpy(partition_table+0x410, my_partition_guid, 16);

	*(uint32_t*)(partition_table+0x258) = crc32(partition_table+0x400, 0x80 * 0x80);
	*(uint32_t*)(partition_table+0x210) = 0;
	*(uint32_t*)(partition_table+0x210) = crc32(partition_table+0x200, 0x5c);

	memcpy(backup_partition_table+((bdev->appended_sectors-1)*512), partition_table+0x200, 512);
	memcpy(backup_partition_table, partition_table+(512*2), 512);

	uint64_t swap;
	swap = *(uint64_t*)(backup_partition_table+((bdev->appended_sectors-1)*512)+0x20);
	*(uint64_t*)(backup_partition_table+((bdev->appended_sectors-1)*512)+0x20) =
		*(uint64_t*)(backup_partition_table+((bdev->appended_sectors-1)*512)+0x18);
	*(uint64_t*)(backup_partition_table+((bdev->appended_sectors-1)*512)+0x18) = swap;

//	*(uint32_t*)(backup_partition_table+((bdev->appended_sectors-1)*512)+0x58) = crc32(partition_table+0x400, 0x80 * 0x80);
	*(uint32_t*)(backup_partition_table+((bdev->appended_sectors-1)*512)+0x10) = 0;
	*(uint32_t*)(backup_partition_table+((bdev->appended_sectors-1)*512)+0x10) =
		crc32(backup_partition_table+((bdev->appended_sectors-1)*512), 0x5c);

	old_partition_table = bdev->disk_prolog;
	old_backup_partition_table = bdev->disk_epilog;

	bdev->disk_prolog = partition_table;
	bdev->disk_epilog = backup_partition_table;

	if (old_backup_partition_table != NULL) {
		kfree(old_backup_partition_table);
	}
	if (old_partition_table != NULL) {
		kfree(old_partition_table);
	}
}

static int read_boot_sector_from_drbd(struct block_device *bdev, char *bootsect)
{
	return windrbd_make_drbd_requests(NULL, bdev, bootsect, 512, 0, READ);
}

extern int is_filesystem(char *buf);

int windrbd_check_for_filesystem_and_maybe_start_faking_partition_table(struct block_device *bdev)
{
	int err;
	KIRQL flags;

		/* Are we primary? If not, do nothing. */
	if (bdev->drbd_device == NULL ||
            bdev->drbd_device->resource == NULL ||
            bdev->drbd_device->resource->role[NOW] != R_PRIMARY)
		return 0;

		/* Also if we don't exist yet, do nothing */
	if (bdev->bd_inode->i_size <= 0)
		return 0;

	if (!bdev->have_read_bootsector) {
		if ((err = read_boot_sector_from_drbd(bdev, bdev->boot_sector)) != 0) {
			printk("Warning: could not read boot sector from DRBD, errno is %d.\n", err);
			return err;
		}
		bdev->have_read_bootsector = true;
	}
	spin_lock_irqsave(&bdev->virtual_partition_table_lock, flags);

	bdev->data_shift = 0;
	bdev->appended_sectors = 0;

	if (is_filesystem(bdev->boot_sector)) {
		printk("Found a file system on DRBD device, faking partition table around it.\n");
/* Store 32-bit little endian volume serial number at offset 0x48 */
		if (strncmp(bdev->boot_sector+3, "NTFS", 4) == 0) {
			char my_disk_guid[16] = { 0x81, 0x60, 0x9e, 0x40, 0x4e, 0x01, 0x08, 0x45, 0xac, 0x5c, 0x0f, 0xb5, 0x55, 0x05, 0x7c, 0xe6 };
			char my_partition_guid[16] = { 0xab, 0x68, 0x13, 0xa8, 0x7f, 0x9b, 0xcc, 0x12, 0x38, 0x0d, 0x87, 0xfe, 0x28, 0x09, 0x7b, 0xa7 };
			printk("NTFS detected, generating GUIDs from Volume Serial Number (VSN)\n");
			bdev->has_guids = true;
			memcpy(bdev->disk_guid, bdev->boot_sector+0x48, 8);
			memcpy(bdev->disk_guid+8, my_disk_guid+8, 8);
			memcpy(bdev->partition_guid, bdev->boot_sector+0x48, 8);
			memcpy(bdev->partition_guid+8, my_partition_guid+8, 8);
		}
/* Store 8 bytes ReFS serial number at offset 0x38 */
		if (strncmp(bdev->boot_sector+3, "ReFS", 4) == 0) {
			char my_disk_guid[16] = { 0x81, 0x60, 0x9e, 0x40, 0x4e, 0x01, 0x08, 0x45, 0xac, 0x5c, 0x0f, 0xb5, 0x55, 0x05, 0x7c, 0xe6 };
			char my_partition_guid[16] = { 0xab, 0x68, 0x13, 0xa8, 0x7f, 0x9b, 0xcc, 0x12, 0x38, 0x0d, 0x87, 0xfe, 0x28, 0x09, 0x7b, 0xa7 };
			printk("ReFS detected, generating GUIDs from ReFS Serial Number\n");
			bdev->has_guids = true;
			memcpy(bdev->disk_guid, bdev->boot_sector+0x38, 8);
			memcpy(bdev->disk_guid+8, my_disk_guid+8, 8);
			memcpy(bdev->partition_guid, bdev->boot_sector+0x38, 8);
			memcpy(bdev->partition_guid+8, my_partition_guid+8, 8);
		}
		bdev->data_shift = 128;
		bdev->appended_sectors = 128;

		fake_partition_table(bdev);
	} else {
		printk("Did not find a file system on DRBD device, it should contain a partition table already\n");
	}
	spin_unlock_irqrestore(&bdev->virtual_partition_table_lock, flags);

	return 0;
}

void windrbd_device_size_change(struct block_device *bdev)
{
        if (bdev->bd_inode->i_size > 0) {
                printk("got a valid size, unblocking SCSI capacity requests.\n");
                KeSetEvent(&bdev->capacity_event, 0, FALSE);

		if (windrbd_check_for_filesystem_and_maybe_start_faking_partition_table(bdev) < 0) {
			printk("Warning: could not read boot sector on device size change.\n");
		}
/* TODO: IoUpdateDiskGeometry(device_object, &old_geometry, &new_geometry); */
        } else {
                printk("Size set to 0, am I Diskless/Unconnected?\n");
                KeClearEvent(&bdev->capacity_event);
        }
	bdev->bd_nr_sectors = bdev->bd_inode->i_size / bdev->bd_block_size;
}

bool set_capacity_and_notify(struct gendisk *disk, sector_t size)
{
	struct block_device *bdev = disk->part0;

	bdev->bd_inode->i_size = size << 9;
	windrbd_device_size_change(bdev);

	if (size <= 0)
		return false;

	return true;
}

#if 0
static void set_partition_guid(struct block_device *bdev, const char *guid)
{
	int i, n;
	char buf[256];

	bdev->has_guid = true;
	memcpy(bdev->guid, guid, 16);

		/* TODO: store it somewhere (bootsector of partition?) */

		/* Ugh - remove this again ... */
	n = 0;
	n += snprintf(buf+n, sizeof(buf)-n, "Got GUID assigned: ");
	for (i=0;i<16;i++)
		n += snprintf(buf+n, sizeof(buf)-n, "%02x ", (unsigned char) guid[i]);
	n += snprintf(buf+n, sizeof(buf)-n, "\n");
	buf[n] = '\0';

	printk("%s", buf);
}
#endif

static NTSTATUS __attribute__((stdcall)) windrbd_scsi(struct _DEVICE_OBJECT *device, struct _IRP *irp) 
{
	NTSTATUS status;
	struct _SCSI_REQUEST_BLOCK *srb;
	struct _CDB16 *cdb16;
	union _CDB *cdb;
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	ULONG Temp;
	LONGLONG d_size, LargeTemp;
	struct block_device *bdev;
	char *buffer, *io_buffer = NULL;
	int64_t io_start_sector = 0, io_sector_count = 0;
	KIRQL flags;
	int retries;

	struct block_device_reference *ref = device->DeviceExtension;
	if (ref == NULL || ref->bdev == NULL || ref->bdev->delete_pending || ref->bdev->about_to_delete || ref->bdev->ref == NULL) {
//		printk(KERN_WARNING "Device %p accessed after it was deleted.\n", device);
		irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
		irp->IoStatus.Information = 0;
		srb = s->Parameters.Scsi.Srb;
		if (srb)
			srb->SrbStatus = SRB_STATUS_NO_DEVICE;

	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_SUCH_DEVICE;
	}
// cond_printk("SCSI IRQL is %d\n", KeGetCurrentIrql());
#if 0
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
			/* do not touch any (pageable) memory */
		status = irp->IoStatus.Status;
	        IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
/*		irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		irp->IoStatus.Information = 0;
		srb = s->Parameters.Scsi.Srb;
		if (srb)
			srb->SrbStatus = SRB_STATUS_NO_DEVICE;
*/
	}
#endif
	bdev = ref->bdev;
	IoAcquireRemoveLock(&ref->w_remove_lock, NULL);
	status = STATUS_INVALID_DEVICE_REQUEST;

	if (bdev->about_to_delete)
		goto out;

// printk("SCSI request for device %p\n", device);

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

	switch (srb->Function) {
	case SRB_FUNCTION_EXECUTE_SCSI:
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
			sector_t start_sector;
			int64_t sector_count;
			int rw;
			int call_drbd = 0;

			rw = (cdb->AsByte[0] == SCSIOP_READ16 || cdb->AsByte[0] == SCSIOP_READ) ? READ : WRITE;

			if (bdev != NULL) {
				if (rw == WRITE && bdev->is_bootdevice)
					status = wait_for_becoming_primary(bdev);
				else
					status = STATUS_SUCCESS;
			} else {
				printk("bdev is NULL on SCSI I/O, this should not happen (minor is %x)\n", s->MinorFunction);
				status = STATUS_INVALID_DEVICE_REQUEST;
			}

			if (status != STATUS_SUCCESS) {
				srb->SrbStatus = SRB_STATUS_NO_DEVICE;

				srb->DataTransferLength = 0;
				irp->IoStatus.Information = 0;
				break;
			}

			dbg("cdb->AsByte[0] is %d", cdb->AsByte[0]);
			if (cdb->AsByte[0] == SCSIOP_READ16 ||
			    cdb->AsByte[0] == SCSIOP_WRITE16) {
				REVERSE_BYTES_QUAD(&start_sector, &(cdb16->LogicalBlock[0]));
				sector_count = 0;	/* initialize all 8 bytes */
				REVERSE_BYTES(&sector_count, &(cdb16->TransferLength[0]));
			} else {
				start_sector = (unsigned long long) ((unsigned long long) cdb->CDB10.LogicalBlockByte0 << 24) + ((unsigned long long) cdb->CDB10.LogicalBlockByte1 << 16) + ((unsigned long long) cdb->CDB10.LogicalBlockByte2 << 8) + (unsigned long long) cdb->CDB10.LogicalBlockByte3;
				sector_count = (unsigned long long) ((unsigned long long) cdb->CDB10.TransferBlocksMsb << 8) + (unsigned long long) cdb->CDB10.TransferBlocksLsb;
			}
			if (sector_count * 512 > srb->DataTransferLength) {
				dbg("data transfer length too small for requested sectors: need %lld bytes, have %lld bytes\n", sector_count * 512, srb->DataTransferLength);
				sector_count = srb->DataTransferLength / 512;
			}

			if (srb->DataTransferLength % 512 != 0) {
				dbg("srb->DataTransferLength (%lld) not sector aligned\n", srb->DataTransferLength);
			}
			if (srb->DataTransferLength > sector_count * 512) {
				dbg("srb>DataTransferLength (%lld) too big\n", srb->DataTransferLength);
			}

			srb->DataTransferLength = sector_count * 512;
			srb->SrbStatus = SRB_STATUS_SUCCESS;
			if (sector_count == 0) {
				irp->IoStatus.Information = 0;
				break;
			}

			retries = 0;
			while (1) {
				buffer = ((char*)srb->DataBuffer - (char*)MmGetMdlVirtualAddress(irp->MdlAddress)) + (char*)MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority);

				if (buffer != NULL) {
		                        if (retries > 0)
						printk("succeeded after %d retries\n", retries);
		                        break;
				}

				if (retries % 10 == 0) {
					printk("cannot map transfer buffer, retrying\n");
				}
				if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
					if (retries == 0)
						printk("cannot sleep now, busy looping\n");
				} else {
					msleep(100);
				}
			}
// printk("Debug: SCSI I/O: %s sector %lld, %d sectors to %p irp is %p\n", rw == READ ? "Reading" : "Writing", start_sector, sector_count, srb->DataBuffer, irp);

			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = STATUS_PENDING;

			spin_lock_irqsave(&bdev->virtual_partition_table_lock, flags);
			if (start_sector < bdev->data_shift) {
				if (start_sector < bdev->data_shift && sector_count > 0) {
					size_t n = (bdev->data_shift - start_sector)*512;
					if (n>=sector_count*512) {
						n = sector_count*512;
					}
#if 0
					if (rw == WRITE && start_sector <= 2 && start_sector+sector_count > 2) {
						char *guid = buffer + (2 - start_sector) * 512 + 0x10;
						set_partition_guid(bdev, guid);
					}
#endif
					status = STATUS_SUCCESS;
					if (bdev->disk_prolog != NULL) {
						if (rw == READ) {
							memcpy(buffer, bdev->disk_prolog+start_sector*512, n);
						} else {
							printk("WRITE to partition table !!\n");
							memcpy(bdev->disk_prolog+start_sector*512, buffer, n);
						}
					} else {
						if (rw == READ) {
							memset(buffer, 0, n);
						} else {
							status = STATUS_INVALID_PARAMETER;
						}
					}
					start_sector += n/512;
					sector_count -= n/512;
					buffer += n;
				}
			}

			if (sector_count > 0) {
				int64_t num_sectors = sector_count;
				int64_t excess_sectors = (start_sector + num_sectors) - ((bdev->bd_inode->i_size/512) + bdev->data_shift);
				if (excess_sectors > 0) {
					num_sectors -= excess_sectors;
				}
				if (num_sectors > 0) {
						/* Normally we would call windrbd_make_drbd_requests()
						 * here but if the I/O is completed very fast then
						 * the buffer is already invalid / freed or whatever.
						 * So we cannot add epilog data after calling
						 * windrbd_make_drbd_requests(). Save parameters here
						 * and call windrbd_make_drbd_requests() after filling
						 * epilog data.
						 */
					io_buffer = buffer;
					io_start_sector = start_sector-bdev->data_shift;
					io_sector_count = num_sectors;
					call_drbd = 1;

					buffer += num_sectors*512;
					sector_count -= num_sectors;
					start_sector += num_sectors;
				}
			}
			if (sector_count > 0) {
				sector_t first_backup_sector = bdev->data_shift+bdev->bd_inode->i_size/512;
				sector_t last_sector = bdev->data_shift+bdev->bd_inode->i_size/512 + bdev->appended_sectors;
				if (start_sector >= first_backup_sector) {
					if (start_sector + sector_count > last_sector) {
						printk("Warning: attempt to read past device (start sector is %lld sector_count is %lld\n");
						sector_count = last_sector - start_sector;
					}
					status = STATUS_SUCCESS;
					if (rw == READ) {
						if (bdev->disk_epilog != NULL) {
							memcpy(buffer, bdev->disk_epilog+(start_sector-first_backup_sector)*512, sector_count*512);
						} else {
							memset(buffer, 0, sector_count*512);
						}
					} else {
						if (bdev->disk_epilog != NULL) {
							printk("WRITE to backup partition table !!\n");
							memcpy(bdev->disk_epilog+(start_sector-first_backup_sector)*512, buffer, sector_count*512);
						} else {
							status = STATUS_INVALID_PARAMETER;
						}
					}
				}
			}
			spin_unlock_irqrestore(&bdev->virtual_partition_table_lock, flags);

			if (call_drbd) {
				status = windrbd_make_drbd_requests(irp, bdev, io_buffer, io_sector_count*512, io_start_sector, rw);
					/* irp may already be freed here, don't access it.
					 * buffer also might already be freed here.
					 */
				if (status == STATUS_SUCCESS)
					return STATUS_PENDING;
			}

// printk("XXX Debug: windrbd_make_drbd_requests returned, status is %x sector is %lld irp is %p\n", status, start_sector, irp);

// printk("error initiating request status is %x\n", status);
			if (status != STATUS_SUCCESS) {
				srb->SrbStatus = SRB_STATUS_NO_DEVICE;
			}
			break;
		}

		case SCSIOP_READ_CAPACITY:
			if (bdev == NULL) {
				printk("bdev is NULL on SCSI READ_CAPACITY, this should not happen (minor is %x)\n", s->MinorFunction);
				status = STATUS_INVALID_DEVICE_REQUEST;
				srb->SrbStatus = SRB_STATUS_NO_DEVICE;
				break;
			}
			if (bdev->is_bootdevice) {
				d_size = wait_for_size(device);
			} else {
				d_size = bdev->bd_inode->i_size;
			}
			d_size += (bdev->data_shift + bdev->appended_sectors) * 512;

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
// printk("SCSI: Reporting %lld bytes as capacity ...\n", d_size);
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
			if (bdev == NULL) {
				printk("bdev is NULL on SCSI READ_CAPACITY16, this should not happen (minor is %x)\n", s->MinorFunction);
				status = STATUS_INVALID_DEVICE_REQUEST;
				srb->SrbStatus = SRB_STATUS_NO_DEVICE;
				break;
			}
			if (bdev->is_bootdevice) {
				d_size = wait_for_size(device);
			} else {
				d_size = bdev->bd_inode->i_size;
			}
			d_size += (bdev->data_shift + bdev->appended_sectors) * 512;

			Temp = 512;
			REVERSE_BYTES(&(((PREAD_CAPACITY_DATA_EX)srb->DataBuffer)->BytesPerBlock), &Temp);
			if (d_size > 0) {
				if ((d_size % 512) != 0)
					printk("Warning: device size (%lld) not a multiple of 512\n", d_size);
				LargeTemp = (d_size / 512) - 1;
				REVERSE_BYTES_QUAD(&(((PREAD_CAPACITY_DATA_EX)srb->DataBuffer)->LogicalBlockAddress.QuadPart), &LargeTemp);
// printk("SCSI: Reporting %lld bytes as capacity16 ...\n", d_size);
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
// mem_printk("RtlZeroMemory %p %d\n", ModeParameterHeader, srb->DataTransferLength);
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
#if 0
		if (bdev != NULL) {
				/* TODO: only if we are a boot device */
			status = wait_for_becoming_primary(bdev);
			if (status != STATUS_SUCCESS)
				printk("Fatal: wait_for_becoming_primary returned non-success (%x) in CLAIM_DEVICE\n", status);
		} else
			printk("Fatal: bdev is NULL in CLAIM_DEVICE\n", status);
#endif

		srb->DataBuffer = device;
		srb->SrbStatus = SRB_STATUS_SUCCESS;
		break;

	case SRB_FUNCTION_RELEASE_DEVICE:
//             ObDereferenceObject(device);
// printk("got SRB_FUNCTION_RELEASE_DEVICE, referencing device object\n");
		srb->SrbStatus = SRB_STATUS_SUCCESS;
		break;

	case SRB_FUNCTION_SHUTDOWN:
		srb->SrbStatus = SRB_STATUS_SUCCESS;
		break;

	case SRB_FUNCTION_FLUSH:
		srb->SrbStatus = SRB_STATUS_SUCCESS;
		break;

	default:
		printk("got unimplemented SCSI function %x\n", srb->Function);
		status = STATUS_NOT_IMPLEMENTED;
	}

out:
	IoReleaseRemoveLock(&ref->w_remove_lock, NULL);

	irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

	/* The purpose of this extra dispatch function is to create
	 * a valid windrbd thread context for everything that happens
	 * within the windrbd driver. This is neccessary since the
	 * new wait_event_xxx() implementation requires a valid
	 * thread object.
	 */

static NTSTATUS __attribute__((stdcall)) windrbd_dispatch(struct _DEVICE_OBJECT *device, struct _IRP *irp)
{
	struct task_struct *t;
	struct _IO_STACK_LOCATION *s = IoGetCurrentIrpStackLocation(irp);
	unsigned int major = s->MajorFunction;
	NTSTATUS ret;

	if (major > IRP_MJ_MAXIMUM_FUNCTION) {
		printk("Warning: got major function %x out of range\n", major);
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	t = make_me_a_windrbd_thread(thread_names[major]);
	if (t == NULL) {
		printk("Warning: cannot create a thread object for request.\n");
	} else {
		if (device == mvolRootDeviceObject)
			t->is_root = 1;
	}
// printk("got request major is 0x%02x minor is 0x%02x device object is %p (is %s device)\n", major, s->MinorFunction, device, device == mvolRootDeviceObject ? "root" : (device == drbd_bus_device ? "bus" : (device == user_device_object ? " user" : "disk")));

	ret = windrbd_dispatch_table[major](device, irp);

	if (t != NULL) {
		return_to_windows(t);
	}
	return ret;
}

void windrbd_set_major_functions(struct _DRIVER_OBJECT *obj)
{
	int i;
	NTSTATUS status;

	for (i=0; i<=IRP_MJ_MAXIMUM_FUNCTION; i++)
		obj->MajorFunction[i] = windrbd_dispatch;

	for (i=0; i<=IRP_MJ_MAXIMUM_FUNCTION; i++)
		windrbd_dispatch_table[i] = windrbd_not_implemented;

	windrbd_dispatch_table[IRP_MJ_DEVICE_CONTROL] = windrbd_device_control;
	windrbd_dispatch_table[IRP_MJ_READ] = windrbd_io;
	windrbd_dispatch_table[IRP_MJ_WRITE] = windrbd_io;
	windrbd_dispatch_table[IRP_MJ_CREATE] = windrbd_create;
	windrbd_dispatch_table[IRP_MJ_CLOSE] = windrbd_close;
	windrbd_dispatch_table[IRP_MJ_CLEANUP] = windrbd_cleanup;
	windrbd_dispatch_table[IRP_MJ_PNP] = windrbd_pnp;
	windrbd_dispatch_table[IRP_MJ_SHUTDOWN] = windrbd_shutdown;
	windrbd_dispatch_table[IRP_MJ_FLUSH_BUFFERS] = windrbd_flush;
	windrbd_dispatch_table[IRP_MJ_SCSI] = windrbd_scsi;
	windrbd_dispatch_table[IRP_MJ_POWER] = windrbd_power;
	windrbd_dispatch_table[IRP_MJ_SYSTEM_CONTROL] = windrbd_sysctl;

	status = IoRegisterShutdownNotification(mvolRootDeviceObject);
	if (status != STATUS_SUCCESS) {
		printk("Could not register shutdown notification.\n");
	}
#if 0
	spin_lock_init(&irps_in_progress_lock);
	kthread_run(check_irps_thread, NULL, "check-irps");
#endif
}

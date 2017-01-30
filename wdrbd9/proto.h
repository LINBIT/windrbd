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

#ifndef __PROTO_H__
#define __PROTO_H__
#include <mountdev.h>

//
// disp.c
//
NTSTATUS
mvolSendToNextDriver( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );

//
// sub.c
//
NTSTATUS
mvolStartDevice( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );
NTSTATUS
mvolRemoveDevice( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );
NTSTATUS
mvolDeviceUsage( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );
NTSTATUS
mvolReadWriteDevice( IN PVOLUME_EXTENSION VolumeExtension, IN PIRP Irp, IN ULONG Io );
NTSTATUS
mvolGetVolumeSize( PDEVICE_OBJECT TargetDeviceObject, PLARGE_INTEGER pVolumeSize );
extern NTSTATUS
mvolQueryMountPoint(PVOLUME_EXTENSION pvext);
VOID
mvolLogError( PDEVICE_OBJECT DeviceObject, ULONG UniqID,
	NTSTATUS ErrorCode, NTSTATUS Status );

NTSTATUS
IOCTL_SetIOFlag(PDEVICE_OBJECT DeviceObject, PIRP Irp, ULONG Val, BOOLEAN On);

//
// util.c
//
NTSTATUS
GetDeviceName( PDEVICE_OBJECT DeviceObject, PWCHAR Buffer, ULONG BufferLength );

PVOLUME_EXTENSION
mvolSearchDevice( PWCHAR PhysicalDeviceName );

VOID
mvolAddDeviceList( PVOLUME_EXTENSION VolumeExtension );
VOID
mvolDeleteDeviceList( PVOLUME_EXTENSION VolumeExtension );
ULONG
mvolGetDeviceCount();

VOID
MVOL_LOCK();
VOID
MVOL_UNLOCK();
VOID
COUNT_LOCK( PVOLUME_EXTENSION VolumeExtension );
VOID
COUNT_UNLOCK( PVOLUME_EXTENSION VolumeExtension );

//
// ops.c
//
NTSTATUS
IOCTL_GetAllVolumeInfo( PIRP Irp, PULONG ReturnLength );
NTSTATUS
IOCTL_GetVolumeInfo( PDEVICE_OBJECT DeviceObject, PIRP Irp, PULONG ReturnLength );
NTSTATUS
IOCTL_VolumeStart( PDEVICE_OBJECT DeviceObject, PIRP Irp );
NTSTATUS
IOCTL_VolumeStop( PDEVICE_OBJECT DeviceObject, PIRP Irp );
NTSTATUS
IOCTL_GetVolumeSize( PDEVICE_OBJECT DeviceObject, PIRP Irp );
NTSTATUS
IOCTL_VolumeReadOff( PDEVICE_OBJECT DeviceObject, PIRP Irp, BOOLEAN ReadEnable );
NTSTATUS
IOCTL_VolumeWriteOff( PDEVICE_OBJECT DeviceObject, PIRP Irp, BOOLEAN WriteEnable );
NTSTATUS
IOCTL_GetCountInfo( PDEVICE_OBJECT DeviceObject, PIRP Irp, PULONG ReturnLength );
NTSTATUS
IOCTL_MountVolume(PDEVICE_OBJECT DeviceObject, PIRP Irp, PULONG ReturnLength);
NTSTATUS
IOCTL_SetSimulDiskIoError( PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS
IOCTL_SetMinimumLogLevel(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS
IOCTL_GetDrbdLog(PDEVICE_OBJECT DeviceObject, PIRP Irp, ULONG* size);
NTSTATUS
IOCTL_SetHandlerUse(PDEVICE_OBJECT DeviceObject, PIRP Irp);

//
// thread.c
//
NTSTATUS
mvolInitializeThread( PVOLUME_EXTENSION DeviceExtension,
	PMVOL_THREAD pThreadInfo, PKSTART_ROUTINE ThreadRoutine );
VOID
mvolTerminateThread( PMVOL_THREAD pThreadInfo );
VOID
mvolWorkThread( PVOID arg );

#endif __PROTO_H__

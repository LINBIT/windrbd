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

#ifndef MVF_DISP_H
#define MVF_DISP_H

#include <mountdev.h>
#include "mvolse.h"
#include "windows/ioctl.h"
#include "windows/drbd.h"

#define	MVOL_IOCOMPLETE_REQ(Irp, status, size)		\
{							\
	Irp->IoStatus.Status = status;			\
	Irp->IoStatus.Information = size;		\
	IoCompleteRequest( Irp, IO_NO_INCREMENT );	\
	return status;					\
}

#define	MVOL_IOTYPE_SYNC		0x01
#define	MVOL_IOTYPE_ASYNC		0x02

typedef struct _MVOL_THREAD
{
	PDEVICE_OBJECT				DeviceObject;		// mvol Volume DeviceObject
	BOOLEAN						Active;
	BOOLEAN						exit_thread;
	LIST_ENTRY					ListHead;
	KSPIN_LOCK					ListLock;
	MVOL_SECURITY_CLIENT_CONTEXT	se_client_context;
	KEVENT						RequestEvent;
	PVOID						pThread;
	ULONG						Id;                 // MULTI_WRITE_HOOKER_THREADS
	KEVENT						SplitIoDoneEvent;
} MVOL_THREAD, *PMVOL_THREAD;

#define	MVOL_MAGIC				0x853a2954

#define	MVOL_READ_OFF			0x01
#define	MVOL_WRITE_OFF			0x02

/* flag bits per volume extension 
	DW-1277: volume type is marked when drbd attaches */
enum {
	VOLUME_TYPE_REPL,		// for replicating volume.
	VOLUME_TYPE_META,		// for meta volume.
};

typedef struct _VOLUME_EXTENSION
{
	struct _VOLUME_EXTENSION	*Next;

	PDEVICE_OBJECT		DeviceObject;		// volume deviceobject
	PDEVICE_OBJECT		PhysicalDeviceObject;
	PDEVICE_OBJECT		TargetDeviceObject;
#ifdef _WIN32_MVFL
    HANDLE              LockHandle;
#endif
	ULONG_PTR			Flag;
	ULONG				Magic;
	BOOLEAN				Active;

	IO_REMOVE_LOCK		RemoveLock; // RemoveLock for Block Device 
	KMUTEX				CountMutex;

	ULONG				IrpCount;

	USHORT				PhysicalDeviceNameLength;
	WCHAR				PhysicalDeviceName[MAXDEVICENAME];
	ULONG				VolIndex;
	//CHAR				Letter;
	UNICODE_STRING		MountPoint;	// IoVolumeDeviceToDosName()
	UNICODE_STRING		VolumeGuid;

#ifdef MULTI_WRITE_HOOKER_THREADS
	ULONG				Rr; // MULTI_WRITE_HOOKER_THREADS
	MVOL_THREAD			WorkThreadInfo[5]; 
#else
	MVOL_THREAD			WorkThreadInfo;
#endif
	struct block_device	*dev;
} VOLUME_EXTENSION, *PVOLUME_EXTENSION;

typedef struct _ROOT_EXTENSION
{
    PVOLUME_EXTENSION   Head;
    ULONG				Magic;
    USHORT				Count;
    USHORT				PhysicalDeviceNameLength;
    WCHAR				PhysicalDeviceName[MAXDEVICENAME];
    UNICODE_STRING      RegistryPath;
} ROOT_EXTENSION, *PROOT_EXTENSION;

extern PDEVICE_OBJECT		mvolRootDeviceObject;
extern PDRIVER_OBJECT		mvolDriverObject;

#define	IO_THREAD_WAIT(X)	KeWaitForSingleObject( &X->RequestEvent, Executive, KernelMode, FALSE, (PLARGE_INTEGER)NULL );
#define	IO_THREAD_SIG(X)	KeSetEvent( &X->RequestEvent, (KPRIORITY)0, FALSE ); 
#define	IO_THREAD_CLR(X)	KeClearEvent( &X->RequestEvent );

#define	FILTER_DEVICE_PROPOGATE_FLAGS			0
#define	FILTER_DEVICE_PROPOGATE_CHARACTERISTICS		(FILE_REMOVABLE_MEDIA | FILE_READ_ONLY_DEVICE | FILE_FLOPPY_DISKETTE)

extern KSPIN_LOCK			mvolVolumeLock;
extern KMUTEX				mvolMutex;
extern KMUTEX				eventlogMutex;

NTSTATUS GetDriverLetterByDeviceName(IN PUNICODE_STRING pDeviceName, OUT PUNICODE_STRING pDriveLetter);
extern int drbd_init(void);
#endif MVF_DISP_H

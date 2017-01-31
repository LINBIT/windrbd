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


#ifndef __MVF_IOCTL_H__
#define __MVF_IOCTL_H__


#define	MVOL_DEVICE		"\\\\.\\mvolCntl"

//
// IOCTL
//
#define	MVOL_TYPE		0x9800

#define	IOCTL_MVOL_GET_VOLUME_COUNT			CTL_CODE(MVOL_TYPE, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IOCTL_MVOL_GET_VOLUMES_INFO			CTL_CODE(MVOL_TYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IOCTL_MVOL_GET_VOLUME_INFO			CTL_CODE(MVOL_TYPE, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_MVOL_VOLUME_START				CTL_CODE(MVOL_TYPE, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IOCTL_MVOL_VOLUME_STOP				CTL_CODE(MVOL_TYPE, 11, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_MVOL_MOUNT_VOLUME             CTL_CODE(MVOL_TYPE, 15, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_MVOL_GET_VOLUME_SIZE			CTL_CODE(MVOL_TYPE, 21, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IOCTL_MVOL_VOLUME_READ_OFF			CTL_CODE(MVOL_TYPE, 22, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IOCTL_MVOL_VOLUME_READ_ON			CTL_CODE(MVOL_TYPE, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IOCTL_MVOL_VOLUME_WRITE_OFF			CTL_CODE(MVOL_TYPE, 24, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IOCTL_MVOL_VOLUME_WRITE_ON			CTL_CODE(MVOL_TYPE, 25, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_MVOL_GET_COUNT_INFO			CTL_CODE(MVOL_TYPE, 30, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_MVOL_GET_PROC_DRBD			CTL_CODE(MVOL_TYPE, 38, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MVOL_SET_SIMUL_DISKIO_ERROR	CTL_CODE(MVOL_TYPE, 40, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MVOL_SET_LOGLV_MIN			CTL_CODE(MVOL_TYPE, 46, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MVOL_GET_DRBD_LOG				CTL_CODE(MVOL_TYPE, 50, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MVOL_SET_HANDLER_USE			CTL_CODE(MVOL_TYPE, 52, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	MAXDEVICENAME			256     //  1024 -> 256
#define MAX_PROC_BUF			2048		

//
// Structure
//
typedef struct _MVOL_VOLUME_INFO
{
	BOOLEAN				Active;
	WCHAR				PhysicalDeviceName[MAXDEVICENAME];		// src device
	ULONG				PeerIp;
	USHORT				PeerPort;
	CHAR				Seq[MAX_PROC_BUF]; // DRBD_DW130: check enough? and chaneg to dynamically
} MVOL_VOLUME_INFO, *PMVOL_VOLUME_INFO;

typedef struct _MVOL_COUNT_INFO
{
	ULONG				IrpCount;
} MVOL_COUNT_INFO, *PMVOL_COUNT_INFO;

typedef struct _MVOL_SYNC_REQ
{
	WCHAR				PhysicalDeviceName[MAXDEVICENAME];
	LARGE_INTEGER			Offset;
	ULONG				BlockSize;
	ULONG				Count;
} MVOL_SYNC_REQ, *PMVOL_SYNC_REQ;

typedef struct _WDRBD_VOLUME_ENTRY
{
	WCHAR		PhysicalDeviceName[MAXDEVICENAME];
	WCHAR		MountPoint[MAXDEVICENAME];
	WCHAR		VolumeGuid[MAXDEVICENAME];

	ULONGLONG	Size;
	ULONGLONG	AgreedSize;

	UCHAR		VolIndex;
	BOOLEAN		ExtensionActive;
	BOOLEAN		ThreadActive;
	BOOLEAN		ThreadExit;
} WDRBD_VOLUME_ENTRY, *PWDRBD_VOLUME_ENTRY;

#define SIMUL_DISK_IO_ERROR_TYPE0		0 // generic_make_request fail
#define SIMUL_DISK_IO_ERROR_TYPE1		1 // Local I/O Completed with Error
#define SIMUL_DISK_IO_ERROR_TYPE2		2 // Peer Request I/O Completed with Error
#define SIMUL_DISK_IO_ERROR_TYPE3		3 // Meta I/O Completed with Error
#define SIMUL_DISK_IO_ERROR_TYPE4		4 // Bitmap I/O Completed with Error

typedef struct _SIMULATION_DISK_IO_ERROR {
	BOOLEAN 	bDiskErrorOn;
	UCHAR		ErrorType;
}SIMULATION_DISK_IO_ERROR, *PSIMULATION_DISK_IO_ERROR;

typedef struct _LOGGING_MIN_LV {
	int			nType;
	int			nErrLvMin;
}LOGGING_MIN_LV, *PLOGGING_MIN_LV;

#define _WIN32_DEBUG_OOS		// DW-1153: debug oos.

#define LOGGING_TYPE_SYSLOG		0
#define LOGGING_TYPE_DBGLOG		1
#ifdef _WIN32_DEBUG_OOS
// DW-1153
#define LOGGING_TYPE_OOSLOG		2
#endif

#ifdef _WIN32_DEBUG_OOS
#pragma warning (disable : 4055)
#define FRAME_DELIMITER		"@"
#define OOS_TRACE_STRING	"oos_trace"
#define STACK_FRAME_CAPTURE_COUNT	(10)
#define MAX_FUNC_NAME_LEN		(50)
#define MAX_FUNCS_STR_LEN		(MAX_FUNC_NAME_LEN * (STACK_FRAME_CAPTURE_COUNT + 1))
#define MAX_FUNC_ADDR_LEN		(20)
#endif

#define MAX_DRBDLOG_BUF				512
#ifdef _WIN32_DEBUG_OOS
#define LOGBUF_MAXCNT				100000
#else
#define LOGBUF_MAXCNT				10000
#endif

typedef struct _DRBD_LOG {
	LONGLONG 	totalcnt;
	char		LogBuf[1]; // LOGBUF_MAXCNT*MAX_DRBDLOG_BUF
}DRBD_LOG, *PDRBD_LOG;

#define DRBD_LOG_SIZE				((LOGBUF_MAXCNT*MAX_DRBDLOG_BUF) + sizeof(LONGLONG))


typedef struct _HANDLER_INFO
{
	BOOLEAN				use;
} HANDLER_INFO, *PHANDLER_INFO;

#endif __MVF_IOCTL_H__

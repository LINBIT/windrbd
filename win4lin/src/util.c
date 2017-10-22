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

#include <Ntifs.h>
#include <Ntstrsafe.h>
#include <ntddk.h>
#include <stdlib.h>
#include <Mountmgr.h>
#include <ntddvol.h>

#include "drbd_windows.h"
#include "drbd_wingenl.h"
#include "proto.h"
#include "drbd_int.h"

NTSTATUS
GetDeviceName( PDEVICE_OBJECT DeviceObject, PWCHAR Buffer, ULONG BufferLength )
{
	NTSTATUS					status;
	POBJECT_NAME_INFORMATION	nameInfo=NULL;
	ULONG						size;

	nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag( NonPagedPool, MAXDEVICENAME*sizeof(WCHAR), '26DW' );
	if( !nameInfo )
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory( nameInfo, MAXDEVICENAME * sizeof(WCHAR) );
	status = ObQueryNameString( DeviceObject, nameInfo, MAXDEVICENAME, &size );
	if( !NT_SUCCESS(status) )
	{
		WDRBD_ERROR("cannot get device name, err=0x%x\n", status);
		ExFreePool( nameInfo );
		return status;
	}

	if( BufferLength > nameInfo->Name.Length )
	{
		memcpy( Buffer, nameInfo->Name.Buffer, nameInfo->Name.Length );
	}
	else
	{
		memcpy( Buffer, nameInfo->Name.Buffer, BufferLength-4 );
	}

	ExFreePool( nameInfo );
	return STATUS_SUCCESS;
}

/* TODO: see if this is needed */
/* Update: yes it is */

#ifdef _WIN32_MVFL
/**
* @brief    do FSCTL_DISMOUNT_VOLUME in kernel.
*           advised to use this function in next sequence
*			lock - dismount - unlock
*			because this function can process regardless of using volume
*           reference to http://msdn.microsoft.com/en-us/library/windows/desktop/aa364562(v=vs.85).aspx 
*           using sequence is FsctlLockVolume() - FsctlFlushDismountVolume() - FsctlUnlockVolume() 
*           Opened volume's HANDLE value is in VOLUME_EXTENSION.
*           if you need, can be used Independently. 
*/
NTSTATUS FsctlFlushDismountVolume(unsigned int minor, bool bFlush)
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
#if 0
	PFILE_OBJECT pVolumeFileObject = NULL;
#endif
    HANDLE hFile = NULL;
    UNICODE_STRING device_name;

    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor);
    if (IS_ERR(pvext)) {
        return STATUS_UNSUCCESSFUL;
    }

	RtlUnicodeStringInit(&device_name, pvext->PhysicalDeviceName);
	
	// DW-1303 No dismount for already dismounted volume
	if(pvext->PhysicalDeviceObject && pvext->PhysicalDeviceObject->Vpb) {
		if( !(pvext->PhysicalDeviceObject->Vpb->Flags & VPB_MOUNTED) ) {
			WDRBD_INFO("no dismount. volume(%wZ) already dismounted\n", &device_name);
			return STATUS_SUCCESS;
		}
	}
	
    __try
    {
        if (!pvext->LockHandle)
        {
            InitializeObjectAttributes(&ObjectAttributes,
                &device_name,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                NULL,
                NULL);

            status = ZwCreateFile(&hFile,
                GENERIC_READ | GENERIC_WRITE,
                &ObjectAttributes,
                &StatusBlock,
                NULL,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0);
            if (!NT_SUCCESS(status))
            {
                WDRBD_WARN("ZwCreateFile Failed. status(0x%x)\n", status);
                __leave;
            }
        }
        else
        {
            hFile = pvext->LockHandle;
        }

#if 0
        status = ObReferenceObjectByHandle(hFile,
            FILE_READ_DATA,
            *IoFileObjectType,
            KernelMode,
            &pVolumeFileObject,
            NULL);
        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("ObReferenceObjectByHandle Failed. status(0x%x)\n", status);
            __leave;
        }
#endif
		if (bFlush)
		{
			status = ZwFlushBuffersFile(hFile, &StatusBlock);
			if (!NT_SUCCESS(status)) {
				WDRBD_ERROR("ZwFlushBuffersFile Failed. status(0x%x)\n", status);
			}
		}
		
        status = ZwFsControlFile(hFile, 0, 0, 0, &StatusBlock, FSCTL_DISMOUNT_VOLUME, 0, 0, 0, 0);
        if (!NT_SUCCESS(status)) {
            WDRBD_ERROR("ZwFsControlFile FSCTL_DISMOUNT_VOLUME Failed. status(0x%x)\n", status);
            __leave;
        }

        WDRBD_INFO("volume(%wZ) dismounted\n", &device_name);
    }
    __finally
    {
        if (!pvext->LockHandle && hFile)    // case of dismount Independently
        {
            ZwClose(hFile);
        }
#if 0
        if (pVolumeFileObject)
        {
            ObDereferenceObject(pVolumeFileObject);
        }
#endif
    }

    return status;
}

/**
* @brief    do FSCTL_LOCK_VOLUME in kernel.
*           If acuiring lock is success, volume's HANDLE value is in VOLUME_EXTENSION.
*           this handle must be closed by FsctlUnlockVolume()-ZwClose()
*           If volume is referenced by somewhere, aquiring lock will be failed.
*/
NTSTATUS FsctlLockVolume(unsigned int minor)
{
    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor);
    if (IS_ERR(pvext)) {
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
    HANDLE hFile = NULL;
    UNICODE_STRING device_name;

    RtlUnicodeStringInit(&device_name, pvext->PhysicalDeviceName);

	// DW-1303 No lock for already dismounted volume
	if(pvext->PhysicalDeviceObject && pvext->PhysicalDeviceObject->Vpb) {
		if( !(pvext->PhysicalDeviceObject->Vpb->Flags & VPB_MOUNTED) ) {
			WDRBD_INFO("no lock. volume(%wZ) already dismounted\n", &device_name);
			return STATUS_UNSUCCESSFUL;
		}
	}
	
    __try
    {
        InitializeObjectAttributes(&ObjectAttributes,
            &device_name,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        status = ZwCreateFile(&hFile,
            FILE_READ_DATA | FILE_WRITE_DATA,
            &ObjectAttributes,
            &StatusBlock,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);
        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("ZwCreateFile Failed. status(0x%x)\n", status);
            __leave;
        }

        int i = 0;
        do
        {
            status = ZwFsControlFile(hFile, 0, 0, 0, &StatusBlock, FSCTL_LOCK_VOLUME, 0, 0, 0, 0);            
            ++i;
        } while ((STATUS_ACCESS_DENIED == status) && i < 3);

        if (!NT_SUCCESS(status))
        {
            //printk(KERN_ERR "ZwFsControlFile Failed. status(0x%x)\n", status);
            WDRBD_ERROR("ZwFsControlFile Failed. status(0x%x) &ObjectAttributes(0x%p) hFile(0x%p)\n", status, &ObjectAttributes, hFile);
            __leave;
        }
        
        pvext->LockHandle = hFile;
        hFile = NULL;

        WDRBD_INFO("volume(%wZ) locked. handle(0x%p)\n", &device_name, pvext->LockHandle);
    }
    __finally
    {
        if (hFile)
        {
            ZwClose(hFile);
        }
    }

    return status;
}

/**
* @brief    do FSCTL_UNLOCK_VOLUME in kernel.
*/
NTSTATUS FsctlUnlockVolume(unsigned int minor)
{
    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor);
    if (IS_ERR(pvext)) {
        return STATUS_UNSUCCESSFUL;
    }

    if (!pvext->LockHandle)
    {
        WDRBD_WARN("volume(%ws) not locked\n", pvext->PhysicalDeviceName);
        return STATUS_NOT_LOCKED;
    }

    NTSTATUS status = STATUS_SUCCESS;
    IO_STATUS_BLOCK StatusBlock;

    __try
    {
        status = ZwFsControlFile(pvext->LockHandle, 0, 0, 0, &StatusBlock, FSCTL_UNLOCK_VOLUME, 0, 0, 0, 0);
        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("ZwFsControlFile Failed. status(0x%x)\n", status);
            __leave;
        }

        WDRBD_INFO("volume(%ws) unlocked\n", pvext->PhysicalDeviceName);
    }
    __finally
    {
        ZwClose(pvext->LockHandle);
        pvext->LockHandle = NULL;
    }

    return status;
}

/**
*/
NTSTATUS FsctlFlushVolume(unsigned int minor)
{
    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor);
    if (IS_ERR(pvext)) {
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
    HANDLE hFile = NULL;
    UNICODE_STRING device_name;

    RtlUnicodeStringInit(&device_name, pvext->PhysicalDeviceName);

    __try
    {
        InitializeObjectAttributes(&ObjectAttributes,
            &device_name,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        status = ZwCreateFile(&hFile,
            FILE_READ_DATA | FILE_WRITE_DATA,
            &ObjectAttributes,
            &StatusBlock,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);

        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("ZwCreateFile Failed. status(0x%x)\n", status);
            __leave;
        }

        status = ZwFlushBuffersFile(hFile, &StatusBlock);
    }
    __finally
    {
        if (hFile)
        {
            ZwClose(hFile);
        }
    }

    return status;
}

/**
*/
NTSTATUS FsctlCreateVolume(unsigned int minor)
{
    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor);
    if (IS_ERR(pvext)) {
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
    HANDLE hFile = NULL;
    UNICODE_STRING device_name;

    RtlUnicodeStringInit(&device_name, pvext->PhysicalDeviceName);

    __try
    {
        InitializeObjectAttributes(&ObjectAttributes,
            &device_name,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        status = ZwCreateFile(&hFile,
            FILE_READ_DATA | FILE_WRITE_DATA,
            &ObjectAttributes,
            &StatusBlock,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            NULL,
            0);

        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("ZwCreateFile Failed. status(0x%x)\n", status);
            __leave;
        }
    }
    __finally
    {
        if (hFile)
        {
            ZwClose(hFile);
        }
    }

    return status;
}

HANDLE GetVolumeHandleFromDeviceMinor(unsigned int minor)
{
	PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor);
	if (IS_ERR(pvext)) {
		WDRBD_ERROR("could not get volume extension from device minor(%u)\n", minor);
		return NULL;
	}

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hVolume = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0, };
	IO_STATUS_BLOCK ioStatus = { 0, };	
	UNICODE_STRING usPath = { 0, };
		
	do
	{
		RtlUnicodeStringInit(&usPath, pvext->PhysicalDeviceName);
		InitializeObjectAttributes(&ObjectAttributes,
			&usPath,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);

		status = ZwCreateFile(&hVolume,
			FILE_WRITE_DATA | FILE_READ_ATTRIBUTES,
			&ObjectAttributes,
			&ioStatus,
			NULL,
			0,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE,
			NULL,
			0);

		if (!NT_SUCCESS(status))
		{
			WDRBD_ERROR("ZwCreateFile Failed. status(0x%x)\n", status);
			break;
		}
		
	} while (false);
			
	return hVolume;
}

// returns file system type, NTFS(1), FAT(2), EXFAT(3), REFS(4)
USHORT GetFileSystemTypeWithHandle(HANDLE hVolume)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK iostatus = { 0, };
	FILESYSTEM_STATISTICS fss = { 0, };
	
	if (NULL == hVolume)
	{
		WDRBD_ERROR("Invalid parameter\n");
		return 0;
	}
	
	do
	{
		status = ZwFsControlFile(hVolume, NULL, NULL, NULL, &iostatus, FSCTL_FILESYSTEM_GET_STATISTICS, NULL, 0, &fss, sizeof(fss));
		// retrieved status might indicate there's more data, never mind this as long as the only thing we need is file system type.
		if (fss.FileSystemType == 0 &&
			!NT_SUCCESS(status))
		{
			WDRBD_ERROR("ZwFsControlFile with FSCTL_FILESYSTEM_GET_STATISTICS failed, status(0x%x)\n", status);
			break;
		}

	} while (false);

	return fss.FileSystemType;
}

// retrieves file system specified cluster information ( total cluster count, number of bytes per cluster )
BOOLEAN GetClusterInfoWithVolumeHandle(HANDLE hVolume, PULONGLONG pullTotalCluster, PULONG pulBytesPerCluster)
{
	BOOLEAN bRet = FALSE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK ioStatus = { 0, };
	USHORT usFileSystemType = 0;
	ULONGLONG ullTotalCluster = 0;
	ULONG ulBytesPerCluster = 0;
	HANDLE hEvent = NULL;

	if (NULL == hVolume ||
		NULL == pullTotalCluster ||
		NULL == pulBytesPerCluster)
	{
		WDRBD_ERROR("Invalid parameter, hVolume(%p), pullTotalCluster(%p), pulBytesPerCluster(%p)\n", hVolume, pullTotalCluster, pulBytesPerCluster);
		return FALSE;
	}

	do
	{
		usFileSystemType = GetFileSystemTypeWithHandle(hVolume);
		if (usFileSystemType == 0)
		{
			WDRBD_ERROR("GetFileSystemTypeWithHandle returned invalid file system type\n");
			break;		
		}

		// getting fs volume data sometimes gets pended when it coincides with another peer's, need to wait until the operation's done.
		status = ZwCreateEvent(&hEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
		if (!NT_SUCCESS(status))
		{
			WDRBD_ERROR("ZwCreateEvent failed, status : 0x%x\n", status);
			break;
		}
		
		// supported file systems
		// 1. NTFS
		// 2. REFS
		switch (usFileSystemType)
		{
		case FILESYSTEM_STATISTICS_TYPE_NTFS:
		{
			NTFS_VOLUME_DATA_BUFFER nvdb = { 0, };

			status = ZwFsControlFile(hVolume, hEvent, NULL, NULL, &ioStatus, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &nvdb, sizeof(nvdb));
			if (!NT_SUCCESS(status))
			{
				WDRBD_ERROR("ZwFsControlFile with FSCTL_GET_NTFS_VOLUME_DATA failed, status(%0x%x)\n", status);
				break;
			}

			ZwWaitForSingleObject(hEvent, FALSE, NULL);
			ullTotalCluster = nvdb.TotalClusters.QuadPart;
			ulBytesPerCluster = nvdb.BytesPerCluster;
			break;

		}
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
		case FILESYSTEM_STATISTICS_TYPE_REFS:
		{
			REFS_VOLUME_DATA_BUFFER rvdb = { 0, };

			status = ZwFsControlFile(hVolume, hEvent, NULL, NULL, &ioStatus, FSCTL_GET_REFS_VOLUME_DATA, NULL, 0, &rvdb, sizeof(rvdb));
			if (!NT_SUCCESS(status))
			{
				WDRBD_ERROR("ZwFsControlFile with FSCTL_GET_REFS_VOLUME_DATA failed, status(%0x%x)\n", status);
				break;
			}

			ZwWaitForSingleObject(hEvent, FALSE, NULL);
			ullTotalCluster = rvdb.TotalClusters.QuadPart;
			ulBytesPerCluster = rvdb.BytesPerCluster;
			break;
		}
#endif
		default:
			WDRBD_WARN("The file system %hu is not supported\n", usFileSystemType);
			break;
		}

		if (0 == ullTotalCluster ||
			0 == ulBytesPerCluster)
		{
			WDRBD_ERROR("Cluster information is invalid, ullTotalCluster(%llu), ulBytesPerCluster(%u)\n", ullTotalCluster, ulBytesPerCluster);
			break;
		}

		bRet = TRUE;

	} while (false);

	if (bRet)
	{
		*pullTotalCluster = ALIGN(ullTotalCluster, BITS_PER_BYTE);
		*pulBytesPerCluster = ulBytesPerCluster;
	}

	if (NULL != hEvent)
	{
		ZwClose(hEvent);
		hEvent = NULL;
	}
	
	return bRet;
}

/* DW-1317
   makes volume to be read-only. there will be no write at all when mounted, also any write operation to this volume will be failed. (0xC00000A2 : STATUS_MEDIA_WRITE_PROTECTED)
   be sure that drbd must not go sync target before clearing read-only attribute.
   for mounted read-only volume, write operation would come up as soon as read-only attribute is cleared.
*/
#define GPT_BASIC_DATA_ATTRIBUTE_READ_ONLY          (0x1000000000000000)
bool ChangeVolumeReadonly(unsigned int minor, bool set)
{
	HANDLE hVolume = NULL;
	bool bRet = FALSE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK iosb = { 0, };

	do
	{
		hVolume = GetVolumeHandleFromDeviceMinor(minor);
		if (NULL == hVolume)
		{
			WDRBD_ERROR("Could not get volume handle from minor(%u)\n", minor);
			break;
		}
		
		//VOLUME_GET_GPT_ATTRIBUTES_INFORMATION IOCTL_VOLUME_GET_GPT_ATTRIBUTES
		VOLUME_GET_GPT_ATTRIBUTES_INFORMATION vggai = { 0, };		

		status = ZwDeviceIoControlFile(hVolume, NULL, NULL, NULL, &iosb, IOCTL_VOLUME_GET_GPT_ATTRIBUTES, NULL, 0, &vggai, sizeof(vggai));
		if (status != STATUS_SUCCESS)
		{
			WDRBD_ERROR("ZwDeviceIoControlFile with IOCTL_VOLUME_GET_GPT_ATTRIBUTES failed, status(0x%x)\n", status);
			break;
		}

		if (vggai.GptAttributes & GPT_BASIC_DATA_ATTRIBUTE_READ_ONLY)
		{
			if (set)
			{
				// No additional setting attribute is required.
				WDRBD_INFO("specified volume is read-only already.\n");				
				bRet = true;
				break;
			}
			else
			{
				// clear read-only attribute.
				vggai.GptAttributes &= ~GPT_BASIC_DATA_ATTRIBUTE_READ_ONLY;
			}
		}
		else
		{
			if (!set)
			{
				// No additional setting attribute is required.
				WDRBD_INFO("specified volume is writable already\n");
				bRet = true;
				break;
			}
			else
			{
				// set read-only attribute.
				vggai.GptAttributes |= GPT_BASIC_DATA_ATTRIBUTE_READ_ONLY;
			}
		}

		VOLUME_SET_GPT_ATTRIBUTES_INFORMATION vsgai = { 0, };
		vsgai.GptAttributes = vggai.GptAttributes;
		// documentation says that ApplyToAllConnectedVolumes is required to support MBR disk.
		vsgai.ApplyToAllConnectedVolumes = TRUE;

		status = ZwDeviceIoControlFile(hVolume, NULL, NULL, NULL, &iosb, IOCTL_VOLUME_SET_GPT_ATTRIBUTES, &vsgai, sizeof(vsgai), NULL, 0);
		if (status != STATUS_SUCCESS)
		{
			WDRBD_ERROR("ZwDeviceIoControlFile with IOCTL_VOLUME_SET_GPT_ATTRIBUTES failed, status(0x%x)\n", status);
			break;
		}
		else
		{
			WDRBD_INFO("Read-only attribute for volume(minor: %d) has been %s\n", minor, set ? "set" : "cleared");
		}
		
		bRet = true;

	} while (false);
	
	if (hVolume != NULL)
	{
		ZwClose(hVolume);
		hVolume = NULL;
	}

	return bRet;
}

// returns volume bitmap and cluster information.
PVOLUME_BITMAP_BUFFER GetVolumeBitmap(unsigned int minor, PULONGLONG pullTotalCluster, PULONG pulBytesPerCluster)
{
	PVOLUME_BITMAP_BUFFER pVbb = NULL;
	HANDLE hVolume = NULL;
	IO_STATUS_BLOCK ioStatus = { 0, };
	STARTING_LCN_INPUT_BUFFER slib = { 0, };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BOOLEAN bRet = FALSE;

	if (NULL == pullTotalCluster ||
		NULL == pulBytesPerCluster)
	{
		WDRBD_ERROR("Invalid parameter, pullTotalCluster(%p), pulBytesPerCluster(%p)\n", pullTotalCluster, pulBytesPerCluster);
		return NULL;
	}

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		WDRBD_ERROR("Could not get volume bitmap because of high irql(%d)\n", KeGetCurrentIrql());
		return NULL;
	}

	do
	{
		hVolume = GetVolumeHandleFromDeviceMinor(minor);
		if (NULL == hVolume)
		{
			WDRBD_ERROR("Could not get volume handle from minor(%u)\n", minor);
			break;
		}
				
		if (FALSE == GetClusterInfoWithVolumeHandle(hVolume, pullTotalCluster, pulBytesPerCluster))
		{
			WDRBD_ERROR("Could not get cluster information\n");
			break;
		}

		ULONG ulBitmapSize = sizeof(VOLUME_BITMAP_BUFFER) + (ULONG)(*pullTotalCluster / BITS_PER_BYTE);
		
		pVbb = (PVOLUME_BITMAP_BUFFER)ExAllocatePool(NonPagedPool, ulBitmapSize);
		if (NULL == pVbb)
		{
			WDRBD_ERROR("pVbb allocation failed\n");
			break;
		}
				
		slib.StartingLcn.QuadPart = 0;
		status = ZwFsControlFile(hVolume, NULL, NULL, NULL, &ioStatus, FSCTL_GET_VOLUME_BITMAP, &slib, sizeof(slib), pVbb, ulBitmapSize);
		if (!NT_SUCCESS(status))
		{
			WDRBD_ERROR("ZwFsControlFile with FSCTL_GET_VOLUME_BITMAP failed, status(%0x%x)\n", status);
			break;
		}
				
		bRet = TRUE;

	} while (false);

	if (NULL != hVolume)
	{
		ZwClose(hVolume);
		hVolume = NULL;
	}

	if (!bRet)
	{
		*pullTotalCluster = 0;
		*pulBytesPerCluster = 0;

		if (NULL != pVbb)
		{
			ExFreePool(pVbb);
			pVbb = NULL;
		}
	}

	return pVbb;
}

/* drbd assumes bytes per cluster as 4096. convert if need.
ex:
      2048 bytes    ->    4096 bytes
       00110100              0110

        16 kb       ->    4096 bytes
        0110           00001111 11110000
*/
BOOLEAN ConvertVolumeBitmap(PVOLUME_BITMAP_BUFFER pVbb, PCHAR pConverted, ULONG bytesPerCluster, ULONG ulDrbdBitmapUnit)
{
	int readCount = 1;
	int writeCount = 1;

	if (NULL == pVbb ||
		NULL == pVbb->Buffer ||
		NULL == pConverted)
	{
		WDRBD_ERROR("Invalid parameter, pVbb(0x%p), pVbb->Buffer(0x%p), pConverted(0x%p)\n", pVbb, pVbb ? pVbb->Buffer : NULL, pConverted);
		return FALSE;
	}

	writeCount = (bytesPerCluster / ulDrbdBitmapUnit) + (bytesPerCluster < ulDrbdBitmapUnit);	// drbd bits count affected by a bit of volume bitmap. maximum value : 16
	readCount = (ulDrbdBitmapUnit / bytesPerCluster) + (bytesPerCluster > ulDrbdBitmapUnit);	// volume bits count to be converted into a drbd bit. maximum value : 8
	
	PCHAR pByte = (PCHAR)pVbb->Buffer;

	for (ULONGLONG ullBytePos = 0; ullBytePos < (pVbb->BitmapSize.QuadPart + 1) / BITS_PER_BYTE; ullBytePos += 1)
	{
		for (ULONGLONG ullBitPos = 0; ullBitPos < BITS_PER_BYTE; ullBitPos += readCount)
		{
			CHAR pBit = (pByte[ullBytePos] >> ullBitPos) & ((1 << readCount) - 1);

			if (pBit)
			{
				ULONGLONG ullBitPosTotal = ((ullBytePos * BITS_PER_BYTE + ullBitPos) * writeCount) / readCount;
				ULONGLONG ullBytePos = ullBitPosTotal / BITS_PER_BYTE;
				ULONGLONG ullBitPosInByte = ullBitPosTotal % BITS_PER_BYTE;

				for (int i = 0; i <= (writeCount - 1) / BITS_PER_BYTE; i++)
				{
					CHAR setBits = (1 << (writeCount - i * BITS_PER_BYTE)) - 1;

					if (i == 1)
						ullBitPosInByte = 0;
					pConverted[ullBytePos + i] |= (setBits << ullBitPosInByte);
				}
			}
		}
	}

	return TRUE;
}

PVOID GetVolumeBitmapForDrbd(unsigned int minor, ULONG ulDrbdBitmapUnit)
{
	PVOLUME_BITMAP_BUFFER pVbb = NULL;
	PVOLUME_BITMAP_BUFFER pDrbdBitmap = NULL;
	ULONG ulConvertedBitmapSize = 0;
	ULONGLONG ullTotalCluster = 0;
	ULONG ulBytesPerCluster = 0;

	do
	{
		// Get volume bitmap, bytes per cluster can be 512bytes ~ 64kb
		pVbb = GetVolumeBitmap(minor, &ullTotalCluster, &ulBytesPerCluster);
		if (NULL == pVbb)
		{
			WDRBD_ERROR("Could not get volume bitmap, minor(%u)\n", minor);
			break;
		}

		// use file system returned volume bitmap if it's compatible with drbd.
		if (ulBytesPerCluster == ulDrbdBitmapUnit)
		{
			pDrbdBitmap = pVbb;
			// retrived bitmap size from os indicates that total bit count, convert it into byte of total bit.
			pDrbdBitmap->BitmapSize.QuadPart = (ullTotalCluster / BITS_PER_BYTE);
			pVbb = NULL;
		}
		else
		{
			// Convert gotten bitmap into 4kb unit cluster bitmap.
			ullTotalCluster = (ullTotalCluster * ulBytesPerCluster) / ulDrbdBitmapUnit;
			ulConvertedBitmapSize = (ULONG)(ullTotalCluster / BITS_PER_BYTE);

			pDrbdBitmap = (PVOLUME_BITMAP_BUFFER)ExAllocatePool(NonPagedPool, sizeof(VOLUME_BITMAP_BUFFER) +  ulConvertedBitmapSize);
			if (NULL == pDrbdBitmap)
			{
				WDRBD_ERROR("pConvertedBitmap allocation failed\n");
				break;
			}

			pDrbdBitmap->StartingLcn.QuadPart = 0;
			pDrbdBitmap->BitmapSize.QuadPart = ulConvertedBitmapSize;

			RtlZeroMemory(pDrbdBitmap->Buffer, pDrbdBitmap->BitmapSize.QuadPart);
			if (FALSE == ConvertVolumeBitmap(pVbb, (PCHAR)pDrbdBitmap->Buffer, ulBytesPerCluster, ulDrbdBitmapUnit))
			{
				WDRBD_ERROR("Could not convert bitmap, ulBytesPerCluster(%u), ulDrbdBitmapUnit(%u)\n", ulBytesPerCluster, ulDrbdBitmapUnit);
				ExFreePool(pDrbdBitmap);
				pDrbdBitmap = NULL;
				break;
			}
		}

	} while (false);

	if (NULL != pVbb)
	{
		ExFreePool(pVbb);
		pVbb = NULL;
	}

	return (PVOLUME_BITMAP_BUFFER)pDrbdBitmap;
}
#endif

PVOLUME_EXTENSION
mvolSearchDevice( PWCHAR PhysicalDeviceName )
{
	PROOT_EXTENSION		RootExtension = NULL;
	PVOLUME_EXTENSION	VolumeExtension = NULL;

	RootExtension = mvolRootDeviceObject->DeviceExtension;
	VolumeExtension = RootExtension->Head;
	while( VolumeExtension != NULL )
	{
		if( !_wcsicmp(VolumeExtension->PhysicalDeviceName, PhysicalDeviceName) )
		{
			return VolumeExtension;
		}

		VolumeExtension = VolumeExtension->Next;
	}
	
	return NULL;
}

VOID
mvolAddDeviceList( PVOLUME_EXTENSION pEntry )
{
	PROOT_EXTENSION		RootExtension = mvolRootDeviceObject->DeviceExtension;
	PVOLUME_EXTENSION	pList = RootExtension->Head;

	if( pList == NULL )
	{
		RootExtension->Head = pEntry;
		InterlockedIncrement16( (SHORT*)&RootExtension->Count );
		return ;
	}

	while( pList->Next != NULL )
	{
		pList = pList->Next;
	}

	pList->Next = pEntry;
	InterlockedIncrement16((SHORT*)&RootExtension->Count);
	return ;
}

VOID
mvolDeleteDeviceList( PVOLUME_EXTENSION pEntry )
{
	PROOT_EXTENSION		RootExtension = mvolRootDeviceObject->DeviceExtension;
	PVOLUME_EXTENSION	pList = RootExtension->Head;
	PVOLUME_EXTENSION	pTemp = NULL;

	if( pList == NULL )	return ;
	
    if (pList == pEntry)
	{
		RootExtension->Head = pList->Next;
		InterlockedDecrement16((SHORT*)&RootExtension->Count);
		return ;
	}

    while (pList->Next && pList->Next != pEntry)
	{
		pList = pList->Next;
	}

	if( pList->Next == NULL )	return ;

	pTemp = pList->Next;
	pList->Next = pTemp->Next;
	InterlockedDecrement16((SHORT*)&RootExtension->Count);
}

ULONG
mvolGetDeviceCount()
{
	PROOT_EXTENSION		RootExtension = NULL;
	PVOLUME_EXTENSION	VolumeExtension = NULL;
	ULONG			count = 0;
	
	RootExtension = mvolRootDeviceObject->DeviceExtension;
	VolumeExtension = RootExtension->Head;
	while( VolumeExtension != NULL )
	{
		count++;
		VolumeExtension = VolumeExtension->Next;
	}

	WDRBD_TRACE("DeviceCount=%d\n", count);

	return count;
}

VOID
MVOL_LOCK()
{
	NTSTATUS					status;
	
	status = KeWaitForMutexObject( &mvolMutex, Executive, KernelMode, FALSE, NULL );
	if( !NT_SUCCESS(status) )
	{
		WDRBD_ERROR("cannot wait\n");
	}
}

VOID
MVOL_UNLOCK()
{
	KeReleaseMutex( &mvolMutex, FALSE );
}

VOID
COUNT_LOCK( PVOLUME_EXTENSION VolumeExtension )
{
	NTSTATUS	status;

	status = KeWaitForMutexObject( &VolumeExtension->CountMutex, Executive, KernelMode, FALSE, NULL );
	if( !NT_SUCCESS(status) )
	{
		WDRBD_ERROR("cannot wait\n");
	}
}

VOID
COUNT_UNLOCK( PVOLUME_EXTENSION VolumeExtension )
{
	KeReleaseMutex( &VolumeExtension->CountMutex, FALSE );
}

// Inputs:
//   MountPoint - this is the buffer containing the mountpoint structure used for the query
//   MountPointLength - this is the total size of the MountPoint buffer
//   MountPointInfoLength - the size of the mount point Info structure
//
// Outputs:
//   MountPointInfo - this is the returned mount point information
//   MountPointInfoLength - the # of bytes actually needed
//
// Returns:
//   Results of the underlying operation
//
// Notes:
//   Re-opening the mount manager could be optimized if that were an important goal;
//   We avoid it to minimize handle context problems.
//   http://www.osronline.com/article.cfm?name=mountmgr.zip&id=107
//
NTSTATUS QueryMountPoint(
	_In_ PVOID MountPoint,
	_In_ ULONG MountPointLength,
	_Inout_ PVOID MountPointInfo,
	_Out_ PULONG MountPointInfoLength)
{
	OBJECT_ATTRIBUTES mmgrObjectAttributes;
	UNICODE_STRING mmgrObjectName;
	NTSTATUS status;
	HANDLE mmgrHandle;
	IO_STATUS_BLOCK iosb;
	HANDLE testEvent;

	//
	// First, we need to obtain a handle to the mount manager, so we must:
	//
	//  - Initialize the unicode string with the mount manager name
	//  - Build an object attributes structure
	//  - Open the mount manager
	//
	// This should yield a valid handle for calling the mount manager
	//

	//
	// Initialize the unicode string with the mount manager's name
	//
	RtlInitUnicodeString(&mmgrObjectName, MOUNTMGR_DEVICE_NAME);

	//
	// Initialize object attributes.
	//
	mmgrObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	mmgrObjectAttributes.RootDirectory = NULL;
	mmgrObjectAttributes.ObjectName = &mmgrObjectName;

	//
	// Note: in a kernel driver, we'd add OBJ_KERNEL_HANDLE
	// as another attribute.
	//
	mmgrObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
	mmgrObjectAttributes.SecurityDescriptor = NULL;
	mmgrObjectAttributes.SecurityQualityOfService = NULL;

	//
	// Open the mount manager
	//
	status = ZwCreateFile(&mmgrHandle,
		FILE_READ_DATA | FILE_WRITE_DATA,
		&mmgrObjectAttributes,
		&iosb,
		0, // allocation is meaningless
		0, // no attributes specified
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, // we're willing to share
		FILE_OPEN, // must already exist
		FILE_NON_DIRECTORY_FILE, // must NOT be a directory
		NULL, // no EA buffer
		0); // no EA buffer size...
	if (!NT_SUCCESS(status) ||
		!NT_SUCCESS(iosb.Status)) {
		WDRBD_WARN("Unable to open %wZ, error = 0x%x\n", &mmgrObjectName, status);
		return status;
	}

	//
	// If we get to here, we assume it was successful.  We need an event object
	// for monitoring the completion of I/O operations.
	//
	status = ZwCreateEvent(&testEvent,
		GENERIC_ALL,
		0, // no object attributes
		NotificationEvent,
		FALSE);
	if (!NT_SUCCESS(status)) {
		WDRBD_WARN("Cannot create event (0x%x)\n", status);
		return status;
	}

	status = ZwDeviceIoControlFile(
		mmgrHandle,
		testEvent,
		0, // no apc
		0, // no apc context
		&iosb,
		IOCTL_MOUNTMGR_QUERY_POINTS,
		MountPoint, // input buffer
		MountPointLength, // size of input buffer
		MountPointInfo, // output buffer
		*MountPointInfoLength); // size of output buffer
	if (STATUS_PENDING == status) {
		//
		// Must wait for the I/O operation to complete
		//
		status = ZwWaitForSingleObject(testEvent, TRUE, 0);
		if (NT_SUCCESS(status)) {
			status = iosb.Status;
		}
	}

	//
	// Regardless of the results, we are done with the mount manager and event
	// handles so discard them.
	//
	(void)ZwClose(testEvent);
	(void)ZwClose(mmgrHandle);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	*MountPointInfoLength = iosb.Information;

	return STATUS_SUCCESS;
}

/**
* @brief
*   get volume's unique id
*   this id is in MOUNTDEV_UNIQUE_ID structure, you must free memory after using this
*   reference to <http://msdn.microsoft.com/en-us/library/windows/hardware/ff567603(v=vs.85).aspx> 
* @param
*   volmgr - driver's instance object pointer
* @return
*   volume's unique id type of PMOUNTDEV_UNIQUE_ID
*/
PMOUNTDEV_UNIQUE_ID QueryMountDUID(PDEVICE_OBJECT devObj)
{
    PMOUNTDEV_UNIQUE_ID guid = NULL;
    NTSTATUS result = STATUS_SUCCESS;
    SIZE_T cbBuf = sizeof(MOUNTDEV_UNIQUE_ID) + 256;

    PAGED_CODE();
    for (;;)
    {
        PIRP req = NULL;
        IO_STATUS_BLOCK ioStatus;
        KEVENT evnt;

        KeInitializeEvent(&evnt, NotificationEvent, FALSE);

        guid = (PMOUNTDEV_UNIQUE_ID)ExAllocatePoolWithTag(PagedPool, cbBuf, '08DW');
        if (NULL == guid)
        {
            WDRBD_TRACE("Out of memory.\n");
            return NULL;
        }

        req = IoBuildDeviceIoControlRequest(IOCTL_MOUNTDEV_QUERY_UNIQUE_ID
            , devObj, NULL, 0, guid, (ULONG)cbBuf, FALSE, &evnt, &ioStatus);
        if (NULL == req)
        {
            goto Finally;
        }

        result = IoCallDriver(devObj, req);
        if (STATUS_PENDING == result)
        {
            KeWaitForSingleObject(&evnt, Executive, KernelMode, FALSE, NULL);
        }

        if (!NT_SUCCESS(ioStatus.Status))
        {
            if (STATUS_BUFFER_OVERFLOW == ioStatus.Status)
            {
                // Buffer is too small to store unique id information. We re-allocate memory for
                // bigger size. If the desired buffer size is smaller than we created, something is
                // wrong. We don't retry.
                if (sizeof(guid->UniqueId) + guid->UniqueIdLength > cbBuf)
                {
                    cbBuf = sizeof(guid->UniqueIdLength) + guid->UniqueIdLength;
                    ExFreePool(guid);
                    guid = NULL;
                    continue;
                }
            }

            result = ioStatus.Status;
            goto Finally;
        }

        break;
    }

Finally:
    {
        if (!NT_SUCCESS(result))
        {
            WDRBD_TRACE("Failed to retrieve a GUID: 0x%lx", result);
            ExFreePool(guid);
            guid = NULL;
        }

        return guid;
    }
}

/**
* @brief
*/
void PrintVolumeDuid(PDEVICE_OBJECT devObj)
{
	PMOUNTDEV_UNIQUE_ID guid = QueryMountDUID(devObj);

    if (NULL == guid)
    {
        WDRBD_WARN("Volume GUID: NULL\n", 0);
        return;
    }

    int i;
    char pguid_text[128] = {0, };
    char temp[8] = {0, };

    for (i = 0; i < guid->UniqueIdLength; ++i)
    {
        _itoa_s(guid->UniqueId[i], temp, 8, 16);
        strcat(pguid_text, temp);
        strcat(pguid_text, " ");
    }

    WDRBD_TRACE("device object(0x%x), Volume GUID(%s)\n", devObj, pguid_text);

    ExFreePool(guid);
}

NTSTATUS
GetDriverLetterByDeviceName(IN PUNICODE_STRING pDeviceName, OUT PUNICODE_STRING pDriveLetter)
{
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK StatusBlock;
	PFILE_OBJECT pVolumeFileObject = NULL;
	HANDLE FileHandle;

	InitializeObjectAttributes(&ObjectAttributes,
		pDeviceName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	Status = ZwCreateFile(&FileHandle,
		SYNCHRONIZE | FILE_READ_DATA,
		&ObjectAttributes,
		&StatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (Status != STATUS_SUCCESS)
	{
		return Status;
	}
	Status = ObReferenceObjectByHandle(FileHandle,
		FILE_READ_DATA,
		*IoFileObjectType,
		KernelMode,
		&pVolumeFileObject,
		NULL);
	if (Status != STATUS_SUCCESS)
	{
		ZwClose(FileHandle);
		WDRBD_ERROR("ObReferenceObjectByHandle: %d\n", Status);
		return Status;
	}

	Status = IoVolumeDeviceToDosName(pVolumeFileObject->DeviceObject, pDriveLetter);
	if (Status != STATUS_SUCCESS)
	{
		WDRBD_ERROR("IoVolumeDeviceToDosName: %d\n", Status);
		// return Status;
	}
	ObDereferenceObject(pVolumeFileObject);
	ZwClose(FileHandle);
	return Status;
}

/**
* @brief
*   delete registry's value
* @param
*   preg_path - UNICODE_STRING type's path ex)"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\drbd\\volumes"
*   pvalue_name - UNICODE_STRING type's value
* @return
*   success : STATUS_SUCCESS 
*   fail : api's return value
*/
NTSTATUS DeleteRegistryValueKey(__in PUNICODE_STRING preg_path, __in PUNICODE_STRING pvalue_name)
{
    PAGED_CODE();

    OBJECT_ATTRIBUTES   attributes;
    NTSTATUS            status;
    HANDLE              hKey = NULL;

    InitializeObjectAttributes(&attributes,
        preg_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenKey(&hKey, DELETE, &attributes);
    if (!NT_SUCCESS(status))
    {
        WDRBD_WARN("Failed to ZwOpenKey(). status(0x%x)\n", status);
        goto cleanup;
    }

    status = ZwDeleteValueKey(hKey, pvalue_name);
    if (!NT_SUCCESS(status))
    {
        WDRBD_WARN("Failed to ZwDeleteValueKey(). status(0x%x)\n", status);
        goto cleanup;
    }

cleanup:
    if (hKey)
    {
        ZwClose(hKey);
    }

    return status;
}

NTSTATUS GetRegistryValue(PCWSTR pwcsValueName, ULONG *pReturnLength, UCHAR *pucReturnBuffer, PUNICODE_STRING pRegistryPath)
{
    HANDLE hKey;
    ULONG ulLength;
    NTSTATUS status;
    OBJECT_ATTRIBUTES stObjAttr;
    UNICODE_STRING valueName;
    KEY_VALUE_PARTIAL_INFORMATION stKeyInfo;
    PKEY_VALUE_PARTIAL_INFORMATION pstKeyInfo;

    RtlInitUnicodeString(&valueName, pwcsValueName);

    InitializeObjectAttributes(&stObjAttr, pRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &stObjAttr);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    ulLength = 0;
    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, &stKeyInfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION), &ulLength);
    if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW) && (status != STATUS_BUFFER_TOO_SMALL))
    {
        ZwClose(hKey);
        return status;
    }

    pstKeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulLength, '36DW');
    if (pstKeyInfo == NULL)
    {
        ZwClose(hKey);
        return status;
    }

    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, pstKeyInfo, ulLength, &ulLength);
    if (NT_SUCCESS(status))
    {
        *pReturnLength = pstKeyInfo->DataLength;
        RtlCopyMemory(pucReturnBuffer, pstKeyInfo->Data, pstKeyInfo->DataLength);
    }
    ExFreePool(pstKeyInfo);
    ZwClose(hKey);
    return status;
}

int initRegistry(__in PUNICODE_STRING RegPath_unicode)
{
	ULONG ulLength;
	ULONG ip_length;
	UCHAR aucTemp[255] = { 0 };
	NTSTATUS status;

#ifndef _WIN32
	// set proc_details
	status = GetRegistryValue(L"proc_details", &ulLength, &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		proc_details = *(int*) aucTemp;
	}
	else
	{
		proc_details = 1;
	}
#endif

	// set bypass_level
	status = GetRegistryValue(L"bypass_level", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_bypass_level = *(int*) aucTemp;
	}
	else
	{
		g_bypass_level = 0;
	}

	// set read_filter
#if 0	
	status = GetRegistryValue(L"read_filter", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_read_filter = *(int*) aucTemp;
	}
	else
	{
		g_read_filter = 0;
	}
#endif
	g_read_filter = 0;

	//set g_mj_flush_buffers_filter
	status = GetRegistryValue(L"flush_filter", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS) {
		g_mj_flush_buffers_filter = *(int*) aucTemp;
	}
	else
	{
		g_mj_flush_buffers_filter = 0;
	}
	
	// set use_volume_lock
	status = GetRegistryValue(L"use_volume_lock", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_use_volume_lock = *(int*) aucTemp;
	}
	else
	{
		g_use_volume_lock = 0;
	}

	// set log level
	int log_level = LOG_LV_DEFAULT;	
	status = GetRegistryValue(LOG_LV_REG_VALUE_NAME, &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		log_level = *(int*)aucTemp;;
	}
	Set_log_lv(log_level);

	// set g_netlink_tcp_port
	status = GetRegistryValue(L"netlink_tcp_port", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_netlink_tcp_port = *(int*) aucTemp;;
	}
	else
	{
		g_netlink_tcp_port = NETLINK_PORT;
	}

	// set daemon_tcp_port
	status = GetRegistryValue(L"daemon_tcp_port", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_daemon_tcp_port = *(int*) aucTemp;
	}
	else
	{
		g_daemon_tcp_port = 5679;
	}

#ifdef _WIN32_HANDLER_TIMEOUT
	status = GetRegistryValue(L"handler_use", &ulLength, (UCHAR*) &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_handler_use = *(int*) aucTemp;
	}
	else
	{
		g_handler_use = 0;
	}
	
	status = GetRegistryValue(L"handler_timeout", &ulLength, (UCHAR*) &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_handler_timeout = *(int*) aucTemp;
		if (g_handler_timeout < 0)
		{
			g_handler_timeout = 600;
		}
	}
	else
	{
		g_handler_timeout = 1;
	}	
	g_handler_timeout = g_handler_timeout * 1000; // change to ms
	
	status = GetRegistryValue(L"handler_retry", &ulLength, (UCHAR*) &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_handler_retry = *(int*) aucTemp;
		if (g_handler_retry < 0)
		{
			g_handler_retry = 0;
		}
	}
	else
	{
		g_handler_retry = 0;
	}
#endif

	// set ver
    // DRBD_DOC: not used
	status = GetRegistryValue(L"ver", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		RtlCopyMemory(g_ver, aucTemp, ulLength * 2);
	}
	else
	{
		RtlCopyMemory(g_ver, "DRBD", 4 * 2); 
	}

	ip_length = 0;
	status = GetRegistryValue(L"syslog_ip", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS) {
		status = RtlUnicodeToUTF8N(g_syslog_ip, SYSLOG_IP_SIZE, &ip_length, (WCHAR*) aucTemp, ulLength);
	}
	if (status != STATUS_SUCCESS) {
		strcpy(g_syslog_ip, "192.168.56.103");
	} else {
		g_syslog_ip[ip_length] = '\0';
	}
	// _WIN32_V9: proc_details is removed. 
	WDRBD_INFO("registry_path[%wZ]\n"
		"bypass_level=%d, read_filter=%d, use_volume_lock=%d, "
		"netlink_tcp_port=%d, daemon_tcp_port=%d, ver=%ws, syslog_ip=%s\n",
		RegPath_unicode,
		g_bypass_level,
		g_read_filter,
		g_use_volume_lock,
		g_netlink_tcp_port,
		g_daemon_tcp_port,
		g_ver,
		g_syslog_ip
		);

	return 0;
}

BOOLEAN isFastInitialSync()
{
	ULONG ulLength = 0;
	int nTemp = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PROOT_EXTENSION pRootExtension = NULL;
	BOOLEAN bRet = FALSE;

	pRootExtension = mvolRootDeviceObject->DeviceExtension;

	if (NULL != pRootExtension)
	{
		status = GetRegistryValue(L"use_fast_sync", &ulLength, (UCHAR*)&nTemp, &pRootExtension->RegistryPath);
		if (status == STATUS_SUCCESS)
			bRet = (nTemp ? TRUE : FALSE);
	}

	WDRBD_INFO("Fast sync %s\n", bRet ? "enabled" : "disabled");
	
	return bRet;
}

/**
 * @brief
 *	caller should release unicode's buffer(in bytes)
 */
ULONG ucsdup(_Out_ UNICODE_STRING * dst, _In_ WCHAR * src, ULONG size)
{
	if (!dst || !src) {
		return 0;
	}

    dst->Buffer = (WCHAR *)ExAllocatePoolWithTag(NonPagedPool, size, '46DW');
	if (dst->Buffer) {
		dst->Length = size;
		dst->MaximumLength = size + sizeof(WCHAR);
		RtlCopyMemory(dst->Buffer, src, size);
		return size;
	}

	return 0;
}


char *kvasprintf(int flags, const char *fmt, va_list args)
{
	char *buffer;
	const int size = 4096;
	NTSTATUS status;

	buffer = kzalloc(size, flags, 'AVDW');
	if (buffer) {
		status = RtlStringCchVPrintfA(buffer, size, fmt, args);
		if (status == STATUS_SUCCESS)
			return buffer;

		kfree(buffer);
	}

	return NULL;
}


// GetIrpName
// from:https://github.com/iocellnetworks/ndas4windows/blob/master/fremont/3.20-stable/src/drivers/ndasfat/ndasfat.c

#ifdef IRP_TEST
#define OPERATION_NAME_BUFFER_SIZE  256
CHAR UnknownIrpMinor [] = "Unknown Irp minor code (%u)";

VOID
GetIrpName(
IN UCHAR MajorCode,
IN UCHAR MinorCode,
IN ULONG FsctlCode,
OUT PCHAR MajorCodeName,
OUT PCHAR MinorCodeName
)
/*++

Routine Description:

This routine translates the given Irp codes into printable strings which
are returned.  This guarantees to routine valid strings in each buffer.
The MinorCode string may be a NULL string (not a null pointer).

Arguments:

MajorCode - the IRP Major code of the operation
MinorCode - the IRP Minor code of the operation
FsctlCode - if this is an IRP_MJ_FILE_SYSTEM_CONTROL/IRP_MN_USER_FS_REQUEST
operation then this is the FSCTL code whose name is also
translated.  This name is returned as part of the MinorCode
string.
MajorCodeName - a string buffer at least OPERATION_NAME_BUFFER_SIZE
characters long that receives the major code name.
MinorCodeName - a string buffer at least OPERATION_NAME_BUFFER_SIZE
characters long that receives the minor/fsctl code name.

Return Value:

None.

--*/
{
    PCHAR irpMajorString;
    PCHAR irpMinorString = "";
    CHAR nameBuf[OPERATION_NAME_BUFFER_SIZE];

    switch (MajorCode) {
    case IRP_MJ_CREATE:
        irpMajorString = "IRP_MJ_CREATE";
        break;
    case IRP_MJ_CREATE_NAMED_PIPE:
        irpMajorString = "IRP_MJ_CREATE_NAMED_PIPE";
        break;
    case IRP_MJ_CLOSE:
        irpMajorString = "IRP_MJ_CLOSE";
        break;
    case IRP_MJ_READ:
        irpMajorString = "IRP_MJ_READ";
        switch (MinorCode) {
        case IRP_MN_NORMAL:
            irpMinorString = "IRP_MN_NORMAL";
            break;
        case IRP_MN_DPC:
            irpMinorString = "IRP_MN_DPC";
            break;
        case IRP_MN_MDL:
            irpMinorString = "IRP_MN_MDL";
            break;
        case IRP_MN_COMPLETE:
            irpMinorString = "IRP_MN_COMPLETE";
            break;
        case IRP_MN_COMPRESSED:
            irpMinorString = "IRP_MN_COMPRESSED";
            break;
        case IRP_MN_MDL_DPC:
            irpMinorString = "IRP_MN_MDL_DPC";
            break;
        case IRP_MN_COMPLETE_MDL:
            irpMinorString = "IRP_MN_COMPLETE_MDL";
            break;
        case IRP_MN_COMPLETE_MDL_DPC:
            irpMinorString = "IRP_MN_COMPLETE_MDL_DPC";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_WRITE:
        irpMajorString = "IRP_MJ_WRITE";
        switch (MinorCode) {
        case IRP_MN_NORMAL:
            irpMinorString = "IRP_MN_NORMAL";
            break;
        case IRP_MN_DPC:
            irpMinorString = "IRP_MN_DPC";
            break;
        case IRP_MN_MDL:
            irpMinorString = "IRP_MN_MDL";
            break;
        case IRP_MN_COMPLETE:
            irpMinorString = "IRP_MN_COMPLETE";
            break;
        case IRP_MN_COMPRESSED:
            irpMinorString = "IRP_MN_COMPRESSED";
            break;
        case IRP_MN_MDL_DPC:
            irpMinorString = "IRP_MN_MDL_DPC";
            break;
        case IRP_MN_COMPLETE_MDL:
            irpMinorString = "IRP_MN_COMPLETE_MDL";
            break;
        case IRP_MN_COMPLETE_MDL_DPC:
            irpMinorString = "IRP_MN_COMPLETE_MDL_DPC";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_QUERY_INFORMATION:
        irpMajorString = "IRP_MJ_QUERY_INFORMATION";
        break;
    case IRP_MJ_SET_INFORMATION:
        irpMajorString = "IRP_MJ_SET_INFORMATION";
        break;
    case IRP_MJ_QUERY_EA:
        irpMajorString = "IRP_MJ_QUERY_EA";
        break;
    case IRP_MJ_SET_EA:
        irpMajorString = "IRP_MJ_SET_EA";
        break;
    case IRP_MJ_FLUSH_BUFFERS:
        irpMajorString = "IRP_MJ_FLUSH_BUFFERS";
        break;
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
        irpMajorString = "IRP_MJ_QUERY_VOLUME_INFORMATION";
        break;
    case IRP_MJ_SET_VOLUME_INFORMATION:
        irpMajorString = "IRP_MJ_SET_VOLUME_INFORMATION";
        break;
    case IRP_MJ_DIRECTORY_CONTROL:
        irpMajorString = "IRP_MJ_DIRECTORY_CONTROL";
        switch (MinorCode) {
        case IRP_MN_QUERY_DIRECTORY:
            irpMinorString = "IRP_MN_QUERY_DIRECTORY";
            break;
        case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
            irpMinorString = "IRP_MN_NOTIFY_CHANGE_DIRECTORY";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_FILE_SYSTEM_CONTROL:
        irpMajorString = "IRP_MJ_FILE_SYSTEM_CONTROL";
        switch (MinorCode) {
        case IRP_MN_USER_FS_REQUEST:
            switch (FsctlCode) {
            case FSCTL_REQUEST_OPLOCK_LEVEL_1:
                irpMinorString = "FSCTL_REQUEST_OPLOCK_LEVEL_1";
                break;
            case FSCTL_REQUEST_OPLOCK_LEVEL_2:
                irpMinorString = "FSCTL_REQUEST_OPLOCK_LEVEL_2";
                break;
            case FSCTL_REQUEST_BATCH_OPLOCK:
                irpMinorString = "FSCTL_REQUEST_BATCH_OPLOCK";
                break;
            case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE:
                irpMinorString = "FSCTL_OPLOCK_BREAK_ACKNOWLEDGE";
                break;
            case FSCTL_OPBATCH_ACK_CLOSE_PENDING:
                irpMinorString = "FSCTL_OPBATCH_ACK_CLOSE_PENDING";
                break;
            case FSCTL_OPLOCK_BREAK_NOTIFY:
                irpMinorString = "FSCTL_OPLOCK_BREAK_NOTIFY";
                break;
            case FSCTL_LOCK_VOLUME:
                irpMinorString = "FSCTL_LOCK_VOLUME";
                break;
            case FSCTL_UNLOCK_VOLUME:
                irpMinorString = "FSCTL_UNLOCK_VOLUME";
                break;
            case FSCTL_DISMOUNT_VOLUME:
                irpMinorString = "FSCTL_DISMOUNT_VOLUME";
                break;
            case FSCTL_IS_VOLUME_MOUNTED:
                irpMinorString = "FSCTL_IS_VOLUME_MOUNTED";
                break;
            case FSCTL_IS_PATHNAME_VALID:
                irpMinorString = "FSCTL_IS_PATHNAME_VALID";
                break;
            case FSCTL_MARK_VOLUME_DIRTY:
                irpMinorString = "FSCTL_MARK_VOLUME_DIRTY";
                break;
            case FSCTL_QUERY_RETRIEVAL_POINTERS:
                irpMinorString = "FSCTL_QUERY_RETRIEVAL_POINTERS";
                break;
            case FSCTL_GET_COMPRESSION:
                irpMinorString = "FSCTL_GET_COMPRESSION";
                break;
            case FSCTL_SET_COMPRESSION:
                irpMinorString = "FSCTL_SET_COMPRESSION";
                break;
            case FSCTL_MARK_AS_SYSTEM_HIVE:
                irpMinorString = "FSCTL_MARK_AS_SYSTEM_HIVE";
                break;
            case FSCTL_OPLOCK_BREAK_ACK_NO_2:
                irpMinorString = "FSCTL_OPLOCK_BREAK_ACK_NO_2";
                break;
            case FSCTL_INVALIDATE_VOLUMES:
                irpMinorString = "FSCTL_INVALIDATE_VOLUMES";
                break;
            case FSCTL_QUERY_FAT_BPB:
                irpMinorString = "FSCTL_QUERY_FAT_BPB";
                break;
            case FSCTL_REQUEST_FILTER_OPLOCK:
                irpMinorString = "FSCTL_REQUEST_FILTER_OPLOCK";
                break;
            case FSCTL_FILESYSTEM_GET_STATISTICS:
                irpMinorString = "FSCTL_FILESYSTEM_GET_STATISTICS";
                break;
            case FSCTL_GET_NTFS_VOLUME_DATA:
                irpMinorString = "FSCTL_GET_NTFS_VOLUME_DATA";
                break;
            case FSCTL_GET_NTFS_FILE_RECORD:
                irpMinorString = "FSCTL_GET_NTFS_FILE_RECORD";
                break;
            case FSCTL_GET_VOLUME_BITMAP:
                irpMinorString = "FSCTL_GET_VOLUME_BITMAP";
                break;
            case FSCTL_GET_RETRIEVAL_POINTERS:
                irpMinorString = "FSCTL_GET_RETRIEVAL_POINTERS";
                break;
            case FSCTL_MOVE_FILE:
                irpMinorString = "FSCTL_MOVE_FILE";
                break;
            case FSCTL_IS_VOLUME_DIRTY:
                irpMinorString = "FSCTL_IS_VOLUME_DIRTY";
                break;
            case FSCTL_ALLOW_EXTENDED_DASD_IO:
                irpMinorString = "FSCTL_ALLOW_EXTENDED_DASD_IO";
                break;
            case FSCTL_FIND_FILES_BY_SID:
                irpMinorString = "FSCTL_FIND_FILES_BY_SID";
                break;
            case FSCTL_SET_OBJECT_ID:
                irpMinorString = "FSCTL_SET_OBJECT_ID";
                break;
            case FSCTL_GET_OBJECT_ID:
                irpMinorString = "FSCTL_GET_OBJECT_ID";
                break;
            case FSCTL_DELETE_OBJECT_ID:
                irpMinorString = "FSCTL_DELETE_OBJECT_ID";
                break;
            case FSCTL_SET_REPARSE_POINT:
                irpMinorString = "FSCTL_SET_REPARSE_POINT";
                break;
            case FSCTL_GET_REPARSE_POINT:
                irpMinorString = "FSCTL_GET_REPARSE_POINT";
                break;
            case FSCTL_DELETE_REPARSE_POINT:
                irpMinorString = "FSCTL_DELETE_REPARSE_POINT";
                break;
            case FSCTL_ENUM_USN_DATA:
                irpMinorString = "FSCTL_ENUM_USN_DATA";
                break;
            case FSCTL_SECURITY_ID_CHECK:
                irpMinorString = "FSCTL_SECURITY_ID_CHECK";
                break;
            case FSCTL_READ_USN_JOURNAL:
                irpMinorString = "FSCTL_READ_USN_JOURNAL";
                break;
            case FSCTL_SET_OBJECT_ID_EXTENDED:
                irpMinorString = "FSCTL_SET_OBJECT_ID_EXTENDED";
                break;
            case FSCTL_CREATE_OR_GET_OBJECT_ID:
                irpMinorString = "FSCTL_CREATE_OR_GET_OBJECT_ID";
                break;
            case FSCTL_SET_SPARSE:
                irpMinorString = "FSCTL_SET_SPARSE";
                break;
            case FSCTL_SET_ZERO_DATA:
                irpMinorString = "FSCTL_SET_ZERO_DATA";
                break;
            case FSCTL_QUERY_ALLOCATED_RANGES:
                irpMinorString = "FSCTL_QUERY_ALLOCATED_RANGES";
                break;
            case FSCTL_SET_ENCRYPTION:
                irpMinorString = "FSCTL_SET_ENCRYPTION";
                break;
            case FSCTL_ENCRYPTION_FSCTL_IO:
                irpMinorString = "FSCTL_ENCRYPTION_FSCTL_IO";
                break;
            case FSCTL_WRITE_RAW_ENCRYPTED:
                irpMinorString = "FSCTL_WRITE_RAW_ENCRYPTED";
                break;
            case FSCTL_READ_RAW_ENCRYPTED:
                irpMinorString = "FSCTL_READ_RAW_ENCRYPTED";
                break;
            case FSCTL_CREATE_USN_JOURNAL:
                irpMinorString = "FSCTL_CREATE_USN_JOURNAL";
                break;
            case FSCTL_READ_FILE_USN_DATA:
                irpMinorString = "FSCTL_READ_FILE_USN_DATA";
                break;
            case FSCTL_WRITE_USN_CLOSE_RECORD:
                irpMinorString = "FSCTL_WRITE_USN_CLOSE_RECORD";
                break;
            case FSCTL_EXTEND_VOLUME:
                irpMinorString = "FSCTL_EXTEND_VOLUME";
                break;
            case FSCTL_QUERY_USN_JOURNAL:
                irpMinorString = "FSCTL_QUERY_USN_JOURNAL";
                break;
            case FSCTL_DELETE_USN_JOURNAL:
                irpMinorString = "FSCTL_DELETE_USN_JOURNAL";
                break;
            case FSCTL_MARK_HANDLE:
                irpMinorString = "FSCTL_MARK_HANDLE";
                break;
            case FSCTL_SIS_COPYFILE:
                irpMinorString = "FSCTL_SIS_COPYFILE";
                break;
            case FSCTL_SIS_LINK_FILES:
                irpMinorString = "FSCTL_SIS_LINK_FILES";
                break;
                //case FSCTL_HSM_MSG:
                //     irpMinorString = "FSCTL_HSM_MSG";
                //    break;
                //case FSCTL_HSM_DATA:
                //    irpMinorString = "FSCTL_HSM_DATA";
                //    break;
            case FSCTL_RECALL_FILE:
                irpMinorString = "FSCTL_RECALL_FILE";
                break;
#if WINVER >= 0x0501                            
            case FSCTL_READ_FROM_PLEX:
                irpMinorString = "FSCTL_READ_FROM_PLEX";
                break;
            case FSCTL_FILE_PREFETCH:
                irpMinorString = "FSCTL_FILE_PREFETCH";
                break;
#endif                            
            default:
                sprintf(nameBuf, "Unknown FSCTL (%u)", MinorCode);
                irpMinorString = nameBuf;
                break;
            }

            sprintf(nameBuf, "%s (USER)", irpMinorString);
            irpMinorString = nameBuf;
            break;

        case IRP_MN_MOUNT_VOLUME:
            irpMinorString = "IRP_MN_MOUNT_VOLUME";
            break;
        case IRP_MN_VERIFY_VOLUME:
            irpMinorString = "IRP_MN_VERIFY_VOLUME";
            break;
        case IRP_MN_LOAD_FILE_SYSTEM:
            irpMinorString = "IRP_MN_LOAD_FILE_SYSTEM";
            break;
        case IRP_MN_TRACK_LINK:
            irpMinorString = "IRP_MN_TRACK_LINK";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_DEVICE_CONTROL:
        irpMajorString = "IRP_MJ_DEVICE_CONTROL";
        switch (MinorCode) {
        case 0:
            irpMinorString = "User request";
            break;
        case IRP_MN_SCSI_CLASS:
            irpMinorString = "IRP_MN_SCSI_CLASS";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        irpMajorString = "IRP_MJ_INTERNAL_DEVICE_CONTROL";
        break;
    case IRP_MJ_SHUTDOWN:
        irpMajorString = "IRP_MJ_SHUTDOWN";
        break;
    case IRP_MJ_LOCK_CONTROL:
        irpMajorString = "IRP_MJ_LOCK_CONTROL";
        switch (MinorCode) {
        case IRP_MN_LOCK:
            irpMinorString = "IRP_MN_LOCK";
            break;
        case IRP_MN_UNLOCK_SINGLE:
            irpMinorString = "IRP_MN_UNLOCK_SINGLE";
            break;
        case IRP_MN_UNLOCK_ALL:
            irpMinorString = "IRP_MN_UNLOCK_ALL";
            break;
        case IRP_MN_UNLOCK_ALL_BY_KEY:
            irpMinorString = "IRP_MN_UNLOCK_ALL_BY_KEY";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_CLEANUP:
        irpMajorString = "IRP_MJ_CLEANUP";
        break;
    case IRP_MJ_CREATE_MAILSLOT:
        irpMajorString = "IRP_MJ_CREATE_MAILSLOT";
        break;
    case IRP_MJ_QUERY_SECURITY:
        irpMajorString = "IRP_MJ_QUERY_SECURITY";
        break;
    case IRP_MJ_SET_SECURITY:
        irpMajorString = "IRP_MJ_SET_SECURITY";
        break;
    case IRP_MJ_POWER:
        irpMajorString = "IRP_MJ_POWER";
        switch (MinorCode) {
        case IRP_MN_WAIT_WAKE:
            irpMinorString = "IRP_MN_WAIT_WAKE";
            break;
        case IRP_MN_POWER_SEQUENCE:
            irpMinorString = "IRP_MN_POWER_SEQUENCE";
            break;
        case IRP_MN_SET_POWER:
            irpMinorString = "IRP_MN_SET_POWER";
            break;
        case IRP_MN_QUERY_POWER:
            irpMinorString = "IRP_MN_QUERY_POWER";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_SYSTEM_CONTROL:
        irpMajorString = "IRP_MJ_SYSTEM_CONTROL";
        switch (MinorCode) {
        case IRP_MN_QUERY_ALL_DATA:
            irpMinorString = "IRP_MN_QUERY_ALL_DATA";
            break;
        case IRP_MN_QUERY_SINGLE_INSTANCE:
            irpMinorString = "IRP_MN_QUERY_SINGLE_INSTANCE";
            break;
        case IRP_MN_CHANGE_SINGLE_INSTANCE:
            irpMinorString = "IRP_MN_CHANGE_SINGLE_INSTANCE";
            break;
        case IRP_MN_CHANGE_SINGLE_ITEM:
            irpMinorString = "IRP_MN_CHANGE_SINGLE_ITEM";
            break;
        case IRP_MN_ENABLE_EVENTS:
            irpMinorString = "IRP_MN_ENABLE_EVENTS";
            break;
        case IRP_MN_DISABLE_EVENTS:
            irpMinorString = "IRP_MN_DISABLE_EVENTS";
            break;
        case IRP_MN_ENABLE_COLLECTION:
            irpMinorString = "IRP_MN_ENABLE_COLLECTION";
            break;
        case IRP_MN_DISABLE_COLLECTION:
            irpMinorString = "IRP_MN_DISABLE_COLLECTION";
            break;
        case IRP_MN_REGINFO:
            irpMinorString = "IRP_MN_REGINFO";
            break;
        case IRP_MN_EXECUTE_METHOD:
            irpMinorString = "IRP_MN_EXECUTE_METHOD";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_DEVICE_CHANGE:
        irpMajorString = "IRP_MJ_DEVICE_CHANGE";
        break;
    case IRP_MJ_QUERY_QUOTA:
        irpMajorString = "IRP_MJ_QUERY_QUOTA";
        break;
    case IRP_MJ_SET_QUOTA:
        irpMajorString = "IRP_MJ_SET_QUOTA";
        break;
    case IRP_MJ_PNP:
        irpMajorString = "IRP_MJ_PNP";
        switch (MinorCode) {
        case IRP_MN_START_DEVICE:
            irpMinorString = "IRP_MN_START_DEVICE";
            break;
        case IRP_MN_QUERY_REMOVE_DEVICE:
            irpMinorString = "IRP_MN_QUERY_REMOVE_DEVICE";
            break;
        case IRP_MN_REMOVE_DEVICE:
            irpMinorString = "IRP_MN_REMOVE_DEVICE";
            break;
        case IRP_MN_CANCEL_REMOVE_DEVICE:
            irpMinorString = "IRP_MN_CANCEL_REMOVE_DEVICE";
            break;
        case IRP_MN_STOP_DEVICE:
            irpMinorString = "IRP_MN_STOP_DEVICE";
            break;
        case IRP_MN_QUERY_STOP_DEVICE:
            irpMinorString = "IRP_MN_QUERY_STOP_DEVICE";
            break;
        case IRP_MN_CANCEL_STOP_DEVICE:
            irpMinorString = "IRP_MN_CANCEL_STOP_DEVICE";
            break;
        case IRP_MN_QUERY_DEVICE_RELATIONS:
            irpMinorString = "IRP_MN_QUERY_DEVICE_RELATIONS";
            break;
        case IRP_MN_QUERY_INTERFACE:
            irpMinorString = "IRP_MN_QUERY_INTERFACE";
            break;
        case IRP_MN_QUERY_CAPABILITIES:
            irpMinorString = "IRP_MN_QUERY_CAPABILITIES";
            break;
        case IRP_MN_QUERY_RESOURCES:
            irpMinorString = "IRP_MN_QUERY_RESOURCES";
            break;
        case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
            irpMinorString = "IRP_MN_QUERY_RESOURCE_REQUIREMENTS";
            break;
        case IRP_MN_QUERY_DEVICE_TEXT:
            irpMinorString = "IRP_MN_QUERY_DEVICE_TEXT";
            break;
        case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
            irpMinorString = "IRP_MN_FILTER_RESOURCE_REQUIREMENTS";
            break;
        case IRP_MN_READ_CONFIG:
            irpMinorString = "IRP_MN_READ_CONFIG";
            break;
        case IRP_MN_WRITE_CONFIG:
            irpMinorString = "IRP_MN_WRITE_CONFIG";
            break;
        case IRP_MN_EJECT:
            irpMinorString = "IRP_MN_EJECT";
            break;
        case IRP_MN_SET_LOCK:
            irpMinorString = "IRP_MN_SET_LOCK";
            break;
        case IRP_MN_QUERY_ID:
            irpMinorString = "IRP_MN_QUERY_ID";
            break;
        case IRP_MN_QUERY_PNP_DEVICE_STATE:
            irpMinorString = "IRP_MN_QUERY_PNP_DEVICE_STATE";
            break;
        case IRP_MN_QUERY_BUS_INFORMATION:
            irpMinorString = "IRP_MN_QUERY_BUS_INFORMATION";
            break;
        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
            irpMinorString = "IRP_MN_DEVICE_USAGE_NOTIFICATION";
            break;
        case IRP_MN_SURPRISE_REMOVAL:
            irpMinorString = "IRP_MN_SURPRISE_REMOVAL";
            break;
        case IRP_MN_QUERY_LEGACY_BUS_INFORMATION:
            irpMinorString = "IRP_MN_QUERY_LEGACY_BUS_INFORMATION";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    default:
        sprintf(nameBuf, "Unknown Irp major code (%u)", MajorCode);
        irpMajorString = nameBuf;
    }

    strcpy(MajorCodeName, irpMajorString);
    strcpy(MinorCodeName, irpMinorString);
}

VOID
PrintIrp(
PCHAR					Where,
PVOID					VolDo,
PIRP					Irp
)
{
#if 1 // DBG

    PIO_STACK_LOCATION  irpSp = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT		fileObject = irpSp->FileObject;
    UNICODE_STRING		nullName;
    UCHAR				minorFunction;
    CHAR				irpMajorString[OPERATION_NAME_BUFFER_SIZE];
    CHAR				irpMinorString[OPERATION_NAME_BUFFER_SIZE];

    GetIrpName(
        irpSp->MajorFunction,
        irpSp->MinorFunction,
        irpSp->Parameters.FileSystemControl.FsControlCode,
        irpMajorString,
        irpMinorString
        );

    RtlInitUnicodeString(&nullName, L"fileObject == NULL");

    if (irpSp->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL && irpSp->MinorFunction == IRP_MN_USER_FS_REQUEST)
        minorFunction = (UCHAR) ((irpSp->Parameters.FileSystemControl.FsControlCode & 0x00003FFC) >> 2);
    else if (irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL && irpSp->MinorFunction == 0)
        minorFunction = (UCHAR) ((irpSp->Parameters.DeviceIoControl.IoControlCode & 0x00003FFC) >> 2);
    else
        minorFunction = irpSp->MinorFunction;

    ASSERT(Irp->RequestorMode == KernelMode || Irp->RequestorMode == UserMode);

    if (KeGetCurrentIrql() < DISPATCH_LEVEL) {

        DbgPrint
            ("%s %p Irql:%d Irp:%p %s %s (%u:%u) %08x %02x ",
            (Where) ? Where : "", VolDo,
            KeGetCurrentIrql(),
            Irp, irpMajorString, irpMinorString, irpSp->MajorFunction, minorFunction,
            Irp->Flags, irpSp->Flags);

        /*"%s %c%c%c%c%c ", */
        /*(Irp->RequestorMode == KernelMode) ? "KernelMode" : "UserMode",
        (Irp->Flags & IRP_PAGING_IO) ? '*' : ' ',
        (Irp->Flags & IRP_SYNCHRONOUS_PAGING_IO) ? '+' : ' ',
        (Irp->Flags & IRP_SYNCHRONOUS_API) ? 'A' : ' ',
        BooleanFlagOn(Irp->Flags,IRP_NOCACHE) ? 'N' : ' ',
        (fileObject && fileObject->Flags & FO_SYNCHRONOUS_IO) ? '&':' ',*/

        DbgPrint
            ("file: %p  %08x %p %wZ %d\n",
            fileObject,
            fileObject ? fileObject->Flags : 0,
            fileObject ? fileObject->RelatedFileObject : NULL,
            fileObject ? &fileObject->FileName : &nullName,
            fileObject ? fileObject->FileName.Length : 0
            );
    }

#else

    UNREFERENCED_PARAMETER(DebugLevel);
    UNREFERENCED_PARAMETER(Where);
    UNREFERENCED_PARAMETER(VolDo);
    UNREFERENCED_PARAMETER(Irp);

#endif

    return;
}
#endif

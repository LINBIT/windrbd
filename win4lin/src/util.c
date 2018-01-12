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

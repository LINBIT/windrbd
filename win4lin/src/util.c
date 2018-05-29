/*
        Copyright(C) 2017-2018, Johannes Thoma <johannes@johannesthoma.com>
        Copyright(C) 2017-2018, LINBIT HA-Solutions GmbH  <office@linbit.com>
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

static NTSTATUS GetRegistryValue(PCWSTR pwcsValueName, ULONG *pReturnLength, UCHAR *pucReturnBuffer, PUNICODE_STRING pRegistryPath)
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
	WDRBD_INFO("registry_path[%wZ]\n"
		"netlink_tcp_port=%d, daemon_tcp_port=%d, syslog_ip=%s\n",
		RegPath_unicode,
		g_netlink_tcp_port,
		g_daemon_tcp_port,
		g_syslog_ip
		);

	return 0;
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



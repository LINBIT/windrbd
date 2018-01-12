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
#include <wdm.h>
#include "drbd_windows.h"
#include "proto.h"


NTSTATUS
mvolInitializeThread( PVOLUME_EXTENSION VolumeExtension,
	PMVOL_THREAD pThreadInfo, PKSTART_ROUTINE ThreadRoutine )
{
	NTSTATUS					status;
	HANDLE						threadhandle;
	SECURITY_QUALITY_OF_SERVICE	se_quality_service;

    if (pThreadInfo->Active)
    {
        return STATUS_DEVICE_ALREADY_ATTACHED;
    }

	pThreadInfo->exit_thread = FALSE;
	pThreadInfo->DeviceObject = VolumeExtension->DeviceObject;

	RtlZeroMemory( &se_quality_service, sizeof(SECURITY_QUALITY_OF_SERVICE) );
	se_quality_service.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
	se_quality_service.ImpersonationLevel = SecurityImpersonation;
	se_quality_service.ContextTrackingMode = SECURITY_STATIC_TRACKING;
	se_quality_service.EffectiveOnly = FALSE;

	status = SeCreateClientSecurity( PsGetCurrentThread(), &se_quality_service,
		FALSE, (PSECURITY_CLIENT_CONTEXT)&pThreadInfo->se_client_context);
	if( !NT_SUCCESS(status) )
	{
		WDRBD_ERROR("cannot create client security, err=0x%x\n", status);
		return status;
	}

	KeInitializeEvent(&pThreadInfo->RequestEvent, SynchronizationEvent, FALSE);
	KeInitializeEvent(&pThreadInfo->SplitIoDoneEvent, SynchronizationEvent, FALSE);
	InitializeListHead(&pThreadInfo->ListHead);
	KeInitializeSpinLock(&pThreadInfo->ListLock);

	status = PsCreateSystemThread( &threadhandle, 0L, NULL, 0L, NULL,
		(PKSTART_ROUTINE)ThreadRoutine, (PVOID)pThreadInfo );
	if( !NT_SUCCESS(status) )
	{
		WDRBD_ERROR("cannot create Thread, err=0x%x\n", status);
		SeDeleteClientSecurity( &pThreadInfo->se_client_context );
		return status;
	}

	status = ObReferenceObjectByHandle( threadhandle, THREAD_ALL_ACCESS, NULL, KernelMode,
		&pThreadInfo->pThread, NULL );
	ZwClose( threadhandle );
	if( !NT_SUCCESS(status) )
	{
		pThreadInfo->exit_thread = TRUE;
		IO_THREAD_SIG( pThreadInfo);
		SeDeleteClientSecurity( &pThreadInfo->se_client_context );
		return status;
	}

	pThreadInfo->Active = TRUE;
	return STATUS_SUCCESS;
}

VOID
mvolTerminateThread( PMVOL_THREAD pThreadInfo )
{
    if( NULL == pThreadInfo )   return ;
    if( TRUE == pThreadInfo->Active )
    {
        pThreadInfo->exit_thread = TRUE;
	    IO_THREAD_SIG( pThreadInfo );
        KeWaitForSingleObject( pThreadInfo->pThread, Executive, KernelMode, FALSE, NULL );
    }

    if( NULL != pThreadInfo->pThread )
    {
	    ObDereferenceObject( pThreadInfo->pThread );
	    SeDeleteClientSecurity( &pThreadInfo->se_client_context );
        pThreadInfo->pThread = NULL;
    }

	pThreadInfo->Active = FALSE;
}


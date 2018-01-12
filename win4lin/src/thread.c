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

#if 0
VOID
mvolWorkThread(PVOID arg)
{
	NTSTATUS					status;
	PMVOL_THREAD				pThreadInfo;
	PDEVICE_OBJECT				DeviceObject;
	PVOLUME_EXTENSION			VolumeExtension = NULL;
	PLIST_ENTRY					request;
	PIRP						irp;
	PIO_STACK_LOCATION			irpSp;
	pThreadInfo = (PMVOL_THREAD) arg;
	ULONG						id;
	int							high = 0;
	
	DeviceObject = pThreadInfo->DeviceObject;
	VolumeExtension = DeviceObject->DeviceExtension;
	
	id = pThreadInfo->Id;
    WDRBD_TRACE("WorkThread [%ws]:id %d handle 0x%x start\n", VolumeExtension->PhysicalDeviceName, id, KeGetCurrentThread());

	for (;;)
	{
		int loop = 0;

		IO_THREAD_WAIT(pThreadInfo);
		if (pThreadInfo->exit_thread)
		{
			WDRBD_TRACE("WorkThread [%ws]: Terminate Thread\n", VolumeExtension->PhysicalDeviceName);
			PsTerminateSystemThread(STATUS_SUCCESS);
		}

		while ((request = ExInterlockedRemoveHeadList(&pThreadInfo->ListHead, &pThreadInfo->ListLock)) != 0)
		{
			irp = CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);
			irpSp = IoGetCurrentIrpStackLocation(irp);

#ifdef DRBD_TRACE	
			DbgPrint("\n");
			WDRBD_TRACE("I/O Thread:IRQL(%d) start I/O(%s) loop(%d) .......................!\n", 
				KeGetCurrentIrql(), (irpSp->MajorFunction == IRP_MJ_WRITE)? "Write" : "Read", loop);
#endif

			switch (irpSp->MajorFunction)
			{
				case IRP_MJ_WRITE:
					status = mvolReadWriteDevice(VolumeExtension, irp, IRP_MJ_WRITE);
					if (status != STATUS_SUCCESS)
					{
						mvolLogError(VolumeExtension->DeviceObject, 111, MSG_WRITE_ERROR, status);

						irp->IoStatus.Information = 0;
						irp->IoStatus.Status = status;
						IoCompleteRequest(irp, (CCHAR)(NT_SUCCESS(irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
					}
					break;

			case IRP_MJ_READ:
				if (g_read_filter)
				{
					status = mvolReadWriteDevice(VolumeExtension, irp, IRP_MJ_READ);
					if (status != STATUS_SUCCESS)
					{
						mvolLogError(VolumeExtension->DeviceObject, 111, MSG_WRITE_ERROR, status);
						irp->IoStatus.Information = 0;
						irp->IoStatus.Status = status;
						IoCompleteRequest(irp, (CCHAR)(NT_SUCCESS(irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
					}
				}
				break;
			case IRP_MJ_FLUSH_BUFFERS:
				mvolSendToNextDriver(VolumeExtension->DeviceObject, irp);
				break;
			default:
				WDRBD_ERROR("WorkThread: invalid IRP MJ=0x%x\n", irpSp->MajorFunction);
				irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				IoCompleteRequest(irp, (CCHAR)(NT_SUCCESS(irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
				break;
			}
			loop++;
		}

		if (loop > 1)
		{
			if (high < loop)
			{
				high = loop;
				WDRBD_INFO("hooker[%ws] thread id %d: irp processing peek(%d)\n",
					VolumeExtension->PhysicalDeviceName, id, high);
			}
		}		
		loop = 0;
	}
}

#endif

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

#ifndef MVF_DISP_H
#define MVF_DISP_H

#include <mountdev.h>

extern NTSTATUS mvolAddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT PhysicalDeviceObject);

	/* TODO: this should go away also one day. Must figure out
	   what the root device should do one day. Maybe it is
	   not needed at all. */

typedef struct _ROOT_EXTENSION
{
	int dummy;
} ROOT_EXTENSION, *PROOT_EXTENSION;

extern PDEVICE_OBJECT		mvolRootDeviceObject;
extern PDRIVER_OBJECT		mvolDriverObject;

extern int drbd_init(void);

#endif MVF_DISP_H

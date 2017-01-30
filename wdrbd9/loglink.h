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

#pragma warning (disable : 4221 4706)

struct loglink_msg_list {
	char  *buf;
	struct list_head list;
};

struct loglink_worker {
	struct workqueue_struct *wq;
	struct work_struct worker;
	struct list_head loglist;
};

enum loglink_state {
	LOGLINK_UNINITIALIZED,	// you can't do anything with loglink.
	LOGLINK_USABLE,			// minimum state of using loglink, the only thing you can do is queueing buffer. sender thread isn't created yet.
	LOGLINK_TRANSFERABLE	// init completed and has client. data will be transfered to client immediately.
};

extern int g_loglink_tcp_port;
extern int g_loglink_usage;
extern PETHREAD g_LoglinkServerThread;
extern struct loglink_worker loglink;
extern struct mutex loglink_mutex;
extern NPAGED_LOOKASIDE_LIST loglink_printk_msg;
extern void LogLink_Sender(struct work_struct *ws);
extern DWORD msgids[];
extern VOID NTAPI LogLink_ListenThread(PVOID p);
VOID LogLink_MakeUsable();
VOID LogLink_MakeUnusable();
BOOLEAN LogLink_IsUsable();
BOOLEAN LogLink_HasClient();
NTSTATUS LogLink_QueueBuffer(char* buf);

#define LOGLINK_TIMEOUT		3000

#define	LOGLINK_NOT_USED	0	// kernel level log with multi-line
#define	LOGLINK_DUAL		1	// kernel level log + user level log
#define	LOGLINK_OLNY		2	// user level log, eventname = application/drbdService
#define	LOGLINK_NEW_NAME	3	// user level log, save drbd event only
#define	LOGLINK_2OUT		4	// user level log, save one event to two eventlog 
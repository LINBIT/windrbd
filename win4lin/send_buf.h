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


#ifndef __WIN32_SEND_BUFFING_H
#define __WIN32_SEND_BUFFING_H
#ifndef _WIN32_SEND_BUFFING
#include "drbd_windows.h"	
#include "wsk2.h"	
#endif
#define SENDER_IS_RECV			0
#define SENDER_IS_ASEND			1
#define SENDER_IS_WORKER		2
#define SENDER_IS_SUMBIT		3
#define SENDER_IS_OTHER			4
#define SENDER_IS_UNDEF			-1

// #define SENDBUF_TRACE // trace send buffring 

#ifdef SENDBUF_TRACE
struct _send_req {
	int seq;
	char *who;
	char *tconn;
	char *buf;
	int size;
	struct list_head list;
};
#endif

struct ring_buffer {
	char *name;
	char *mem;
	unsigned int length;
	unsigned int read_pos;
	unsigned int write_pos;
	struct mutex cs;
	int que;
	int deque;
	int seq;
	char *static_big_buf;
	unsigned int sk_wmem_queued;
#ifdef SENDBUF_TRACE
	struct list_head send_req_list;
#endif
};

struct _buffering_attr {
	HANDLE send_buf_thread_handle;
	KEVENT send_buf_kill_event;
	KEVENT send_buf_killack_event;
	KEVENT send_buf_thr_start_event;
	KEVENT ring_buf_event;
	struct ring_buffer *bab;
	bool quit;
};

typedef struct ring_buffer  ring_buffer;

extern ring_buffer *create_ring_buffer(char *name, unsigned int length);
extern void destroy_ring_buffer(ring_buffer *ring);
extern unsigned int get_ring_buffer_size(ring_buffer *ring);
//extern void read_ring_buffer(ring_buffer *ring, char *data, int len);
extern unsigned long read_ring_buffer(IN ring_buffer *ring, OUT char *data, OUT unsigned int* pLen);
extern int write_ring_buffer(struct drbd_transport *transport, enum drbd_stream stream, ring_buffer *ring, const char *data, int len, int highwater, int retry);
extern int send_buf(struct drbd_transport *transport, enum drbd_stream stream, struct socket *socket, PVOID buf, ULONG size);
#endif

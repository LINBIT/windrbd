/*
   drbd_transport_tcp.c

   This file is part of DRBD.

   Copyright (C) 2014-2017, LINBIT HA-Solutions GmbH.
   Copyright (C) 2016, ManTech Co., Ltd.

   This file was derived from the Linux version. All Linux relicts should
   be cleaned up.

   drbd is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   drbd is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/
#include <drbd_windows.h>
#include <drbd_transport.h>
#include "linux/drbd.h"
#include <linux/drbd_genl_api.h>
#include <drbd_protocol.h>
#include "drbd_wrappers.h"
#include <wsk2.h>
#include <linux/drbd_endian.h>
// #include <drbd_int.h> A transport layer must not use internals
#include <linux/drbd_limits.h>
#include <linux/bitops.h>

struct buffer {
	void *base;
	void *pos;
};

#define DTT_CONNECTING 1

struct drbd_tcp_transport {
	struct drbd_transport transport; /* Must be first! */
	atomic_t listening;
	struct mutex paths_mutex;
	ULONG_PTR flags;
	struct socket *stream[2];
	struct buffer rbuf[2];
};

struct dtt_listener {
	struct drbd_listener listener;
	struct socket *s_listen;
	WSK_SOCKET* paccept_socket;
};

struct dtt_wait_first {
	struct drbd_transport *transport;
};

struct dtt_path {
	struct drbd_path path;

	struct socket *socket;
	wait_queue_head_t wait;
	struct dtt_wait_first *first;
};

static int dtt_init(struct drbd_transport *transport);
static void dtt_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op);
static int dtt_connect(struct drbd_transport *transport);
static int dtt_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags);
static int dtt_recv_pages(struct drbd_transport *transport, struct drbd_page_chain_head *chain, size_t size);
static void dtt_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats);
static void dtt_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, LONG_PTR timeout);
static long dtt_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream);
static int dtt_send_page(struct drbd_transport *transport, enum drbd_stream, struct page *page,
		int offset, size_t size, unsigned msg_flags);
static int dtt_send_zc_bio(struct drbd_transport *, struct bio *bio);
static bool dtt_stream_ok(struct drbd_transport *transport, enum drbd_stream stream);
static bool dtt_hint(struct drbd_transport *transport, enum drbd_stream stream, enum drbd_tr_hints hint);
static void dtt_debugfs_show(struct drbd_transport *transport, struct seq_file *m);
static void dtt_update_congested(struct drbd_tcp_transport *tcp_transport);
static int dtt_add_path(struct drbd_transport *, struct drbd_path *path);
static int dtt_remove_path(struct drbd_transport *, struct drbd_path *);

static struct drbd_transport_class tcp_transport_class = {
	.name = "tcp",
	.instance_size = sizeof(struct drbd_tcp_transport),
	.path_instance_size = sizeof(struct dtt_path),
	.init = dtt_init,
	.list = LIST_HEAD_INIT(tcp_transport_class.list),
};

static struct drbd_transport_ops dtt_ops = {
	.free = dtt_free,
	.connect = dtt_connect,
	.recv = dtt_recv,
	.recv_pages = dtt_recv_pages,
	.stats = dtt_stats,
	.set_rcvtimeo = dtt_set_rcvtimeo,
	.get_rcvtimeo = dtt_get_rcvtimeo,
	.send_page = dtt_send_page,
	.send_zc_bio = dtt_send_zc_bio,
	.stream_ok = dtt_stream_ok,
	.hint = dtt_hint,
	.debugfs_show = dtt_debugfs_show,
	.add_path = dtt_add_path,
	.remove_path = dtt_remove_path,
};

#define SOCKET_SND_DEF_BUFFER       (16384)
#define DRBD_SIGKILL SIGHUP

static void dtt_nodelay(struct socket *socket)
{
	int val = 1;
	// nagle disable is supported (registry configuration)
}

int dtt_init(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;

	mutex_init(&tcp_transport->paths_mutex);
	tcp_transport->transport.ops = &dtt_ops;
	tcp_transport->transport.class = &tcp_transport_class;
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		void *buffer = kzalloc(4096, GFP_KERNEL, '0TDW');
		if (!buffer) {
			tcp_transport->rbuf[i].base = NULL;
			WDRBD_WARN("dtt_init kzalloc %s allocation fail\n", i ? "CONTROL_STREAM" : "DATA_STREAM" );
			goto fail;
		}
		tcp_transport->rbuf[i].base = buffer;
		tcp_transport->rbuf[i].pos = buffer;
	}

	return 0;
fail:
	kfree2(tcp_transport->rbuf[0].base);
	return -ENOMEM;
}

// MODIFIED_BY_MANTECH DW-1204: added argument bFlush.
#ifdef _WIN32_SEND_BUFFING
static void dtt_free_one_sock(struct socket *socket, bool bFlush)
#else
static void dtt_free_one_sock(struct socket *socket)
#endif
{
	if (socket) {
		synchronize_rcu();

#ifdef _WIN32_SEND_BUFFING
		// MODIFIED_BY_MANTECH DW-1204: flushing send buffer takes too long when network is slow, just shut it down if possible.
		if (!bFlush)
			kernel_sock_shutdown(socket, SHUT_RDWR);

        struct _buffering_attr *attr = &socket->buffering_attr;
        if (attr->send_buf_thread_handle)
        {
            KeSetEvent(&attr->send_buf_kill_event, 0, FALSE);
            KeWaitForSingleObject(&attr->send_buf_killack_event, Executive, KernelMode, FALSE, NULL);
            attr->send_buf_thread_handle = NULL;
        }
#endif		
#ifdef _WIN32_SEND_BUFFING
		// DW-1173: shut the socket down after send buf thread goes down.
		if (bFlush)
#endif
			kernel_sock_shutdown(socket, SHUT_RDWR);
		sock_release(socket);
	}
}

static void dtt_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;
	struct drbd_path *drbd_path;
	/* free the socket specific stuff,
	 * mutexes are handled by caller */

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		if (tcp_transport->stream[i]) {
#ifdef _WIN32_SEND_BUFFING
			// MODIFIED_BY_MANTECH DW-1204: provide boolean if send buffer has to be flushed.
			dtt_free_one_sock(tcp_transport->stream[i], test_bit(DISCONNECT_FLUSH, &transport->flags));
			clear_bit(DISCONNECT_FLUSH, &transport->flags);
#else
			dtt_free_one_sock(tcp_transport->stream[i]);
#endif
			tcp_transport->stream[i] = NULL;
		}
	}

	mutex_lock(&tcp_transport->paths_mutex);
	list_for_each_entry(struct drbd_path, drbd_path, &transport->paths, list) {
		bool was_established = drbd_path->established;
		drbd_path->established = false;
		if (was_established)
			drbd_path_event(transport, drbd_path);
	}

	if (free_op == DESTROY_TRANSPORT) {
		struct drbd_path *tmp;

		for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
			kfree((void *)tcp_transport->rbuf[i].base);
			tcp_transport->rbuf[i].base = NULL;
		}
		list_for_each_entry_safe(struct drbd_path, drbd_path, tmp, &transport->paths, list) {
			list_del(&drbd_path->list);
			kref_put(&drbd_path->kref, drbd_destroy_path);
		}
	}
	mutex_unlock(&tcp_transport->paths_mutex);
}

static int _dtt_send(struct drbd_tcp_transport *tcp_transport, struct socket *socket,
		      void *buf, size_t size, unsigned msg_flags)
{
	size_t iov_len = size;
	char* DataBuffer = (char*)buf;
	int rv, sent = 0;

	/* THINK  if (signal_pending) return ... ? */

	do {
		/* STRANGE
		 * tcp_sendmsg does _not_ use its size parameter at all ?
		 *
		 * -EAGAIN on timeout, -EINTR on signal.
		 */
/* THINK
 * do we need to block DRBD_SIG if sock == &meta.socket ??
 * otherwise wake_asender() might interrupt some send_*Ack !
 */
#ifdef _WIN32_SEND_BUFFING
		 // _dtt_send is only used when dtt_connect is processed(dtt_send_first_packet), at this time send buffering is not done yet.
		rv = Send(socket->sk, DataBuffer, iov_len, 0, socket->sk_linux_attr->sk_sndtimeo, NULL, NULL, 0);
#else
#if 1 
		rv = Send(socket->sk, DataBuffer, iov_len, 0, socket->sk_linux_attr->sk_sndtimeo, NULL, &tcp_transport->transport, 0);
#else
		rv = kernel_sendmsg(socket, &msg, &iov, 1, size);
#endif
		if (rv == -EAGAIN) {
			struct drbd_transport *transport = &tcp_transport->transport;
			enum drbd_stream stream =
				tcp_transport->stream[DATA_STREAM] == socket ?
					DATA_STREAM : CONTROL_STREAM;

			if (drbd_stream_send_timed_out(transport, stream))
				break;
			else
				continue;
		}
#endif
		if (rv == -EINTR) {
			flush_signals(current);
			rv = 0;
		}
		if (rv < 0)
			break;
		sent += rv;
		DataBuffer += rv;
		iov_len -= rv;
	} while (sent < size);

	if (rv <= 0)
		return rv;

	return sent;
}

static int dtt_recv_short(struct socket *socket, void *buf, size_t size, int flags)
{
	flags = WSK_FLAG_WAITALL;
	return Receive(socket->sk, buf, size, flags, socket->sk_linux_attr->sk_rcvtimeo);
}

static int dtt_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];
	UCHAR *buffer = NULL; 
	int rv;

	if (flags & CALLER_BUFFER) {
		buffer = *buf;
		rv = dtt_recv_short(socket, buffer, size, flags & ~CALLER_BUFFER);
	} else if (flags & GROW_BUFFER) {
		TR_ASSERT(transport, *buf == tcp_transport->rbuf[stream].base);
		buffer = tcp_transport->rbuf[stream].pos;
        TR_ASSERT(transport, (buffer - (UCHAR*)*buf) + size <= PAGE_SIZE);//gcc void* pointer increment is based by 1 byte operation
		rv = dtt_recv_short(socket, buffer, size, flags & ~GROW_BUFFER);
	} else {
		buffer = tcp_transport->rbuf[stream].base;

		rv = dtt_recv_short(socket, buffer, size, flags);
		if (rv > 0)
			*buf = buffer;
	}

	if (rv > 0)
		tcp_transport->rbuf[stream].pos = buffer + rv;

	return rv;
}

static int dtt_recv_pages(struct drbd_transport *transport, struct drbd_page_chain_head *chain, size_t size)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[DATA_STREAM];
	struct page *page;
	int err;

	drbd_alloc_page_chain(transport, chain, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
	page = chain->head;
	if (!page)
		return -ENOMEM;
	err = dtt_recv_short(socket, page, size, 0); // required to verify *peer_req_databuf pointer buffer , size value 's validity 
	WDRBD_TRACE_RS("kernel_recvmsg(%d) socket(0x%p) size(%d) all_pages(0x%p)\n", err, socket, size, page);
    if (err < 0) {
		goto fail;
	}
	return 0;
fail:
	drbd_free_page_chain(transport, chain, 0);
	kfree(page);
	return err;
}

static void dtt_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[DATA_STREAM];

	if (socket) {
		struct sock *sk = socket->sk_linux_attr;
		// not supported
		stats->send_buffer_size = sk->sk_sndbuf;
#ifdef _WIN32_SEND_BUFFING
		{
			struct _buffering_attr *buffering_attr = &tcp_transport->stream[DATA_STREAM]->buffering_attr;
			struct ring_buffer *bab = buffering_attr->bab;

			if (bab)
			{
				stats->send_buffer_used = bab->sk_wmem_queued;
			}
			else
			{
				stats->send_buffer_used = 0; // don't know how to get WSK tx buffer usage yet. Ignore it.
			}
		}
#else
		stats->send_buffer_used = sk->sk_wmem_queued;
#endif
	}
}

static void dtt_setbufsize(struct socket *socket, unsigned int snd,
			   unsigned int rcv)
{
    if (snd) { 
        socket->sk_linux_attr->sk_sndbuf = snd;
    }
    else { 
        socket->sk_linux_attr->sk_sndbuf = SOCKET_SND_DEF_BUFFER;
    }

    if (rcv) {
        ControlSocket(socket->sk, WskSetOption, SO_RCVBUF, SOL_SOCKET,
            sizeof(unsigned int), &rcv, 0, NULL, NULL);
    }
}

static bool dtt_path_cmp_addr(struct dtt_path *path)
{
	struct drbd_path *drbd_path = &path->path;
	int addr_size;

	addr_size = min(drbd_path->my_addr_len, drbd_path->peer_addr_len);
	return memcmp(&drbd_path->my_addr, &drbd_path->peer_addr, addr_size) > 0;
}

static int dtt_try_connect(struct drbd_transport *transport, struct dtt_path *path, struct socket **ret_socket)
{
	KIRQL rcu_flags;
	const char *what;
	struct socket *socket;
	struct sockaddr_storage_win my_addr, peer_addr;
	SOCKADDR_IN		LocalAddressV4 = { 0, };
	SOCKADDR_IN6	LocalAddressV6 = { 0, };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	struct net_conf *nc;
	int err;
	int sndbuf_size, rcvbuf_size, connect_int;
	char sbuf[128] = {0,};
	char dbuf[128] = {0,};
	
	rcu_flags = rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock(rcu_flags);
		return -EIO;
	}

#ifdef _WIN32_SEND_BUFFING
	if (nc->sndbuf_size < DRBD_SNDBUF_SIZE_DEF)
	{
		if (nc->sndbuf_size > 0)
		{
			tr_warn(transport, "sndbuf_size(%d) -> (%d)\n", nc->sndbuf_size, DRBD_SNDBUF_SIZE_DEF);
			nc->sndbuf_size = DRBD_SNDBUF_SIZE_DEF; 
		}
	}
#endif

	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	connect_int = nc->connect_int;
	rcu_read_unlock(rcu_flags);

	my_addr = path->path.my_addr;
	if (my_addr.ss_family == AF_INET6)
		((struct sockaddr_in6 *)&my_addr)->sin6_port = 0;
	else
		((struct sockaddr_in *)&my_addr)->sin_port = 0; /* AF_INET & AF_SCI */

	/* In some cases, the network stack can end up overwriting
	   peer_addr.ss_family, so use a copy here. */
	peer_addr = path->path.peer_addr;

	what = "sock_create_kern";
#ifdef _WSK_SOCKETCONNECT // DW-1007 replace wskconnect with wsksocketconnect for VIP source addressing problem	

	socket = kzalloc(sizeof(struct socket), 0, '1TDW');
	if (!socket) {
		err = -ENOMEM; 
		goto out;
	}
	sprintf(socket->name, "conn_sock\0");
	socket->sk_linux_attr = 0;
	err = 0;

	socket->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '2TDW');
	if (!socket->sk_linux_attr) {
		err = -ENOMEM;
		goto out;
	}
	socket->sk_linux_attr->sk_rcvtimeo =
		socket->sk_linux_attr->sk_sndtimeo = connect_int * HZ;

	what = "create-connect";

	if (my_addr.ss_family == AF_INET6) {
		WDRBD_TRACE("dtt_try_connect: Connecting: %s -> %s\n", get_ip6(sbuf, (struct sockaddr_in6*)&my_addr), get_ip6(dbuf, (struct sockaddr_in6*)&peer_addr));
	} else {
		WDRBD_TRACE("dtt_try_connect: Connecting: %s -> %s\n", get_ip4(sbuf, (struct sockaddr_in*)&my_addr), get_ip4(dbuf, (struct sockaddr_in*)&peer_addr));
	}			
	socket->sk = SocketConnect(SOCK_STREAM, IPPROTO_TCP, (PSOCKADDR)&my_addr, (PSOCKADDR)&peer_addr, &status);
		
	if (!NT_SUCCESS(status)) {
		err = status;
		WDRBD_TRACE("dtt_try_connect: SocketConnect fail status:%x\n",status);
		switch (status) {
		case STATUS_CONNECTION_REFUSED: err = -ECONNREFUSED; break;
		// DW-1272, DW-1290 : retry SocketConnect if STATUS_INVALID_ADDRESS_COMPONENT
		case STATUS_INVALID_ADDRESS_COMPONENT: err = -EAGAIN; break;
		case STATUS_INVALID_DEVICE_STATE: err = -EAGAIN; break;
		case STATUS_NETWORK_UNREACHABLE: err = -ENETUNREACH; break;
		case STATUS_HOST_UNREACHABLE: err = -EHOSTUNREACH; break;
		case STATUS_IO_TIMEOUT: err = -ETIMEDOUT; break;
		default: err = -EINVAL; break;
		}
	} else {
		if (status == STATUS_TIMEOUT) { 
			err = -ETIMEDOUT; 
		} else { 
			if (status == 0) {
				err = 0;
			} else {
				err = -EINVAL;
			}
			if (socket->sk == NULL) {
				err = -1;
				goto out;
			}
		}
	}
	// _WSK_SOCKETCONNECT
#else 

	socket = kzalloc(sizeof(struct socket), 0, '3TDW');
	if (!socket) {
		err = -ENOMEM; 
		goto out;
	}
	sprintf(socket->name, "conn_sock\0");
	socket->sk_linux_attr = 0;
	err = 0;

	if (my_addr.ss_family == AF_INET6) {
		socket->sk = CreateSocket(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSK_FLAG_CONNECTION_SOCKET);
	} else {
		socket->sk = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSK_FLAG_CONNECTION_SOCKET);
	}

	if (socket->sk == NULL) {
		err = -1;
		goto out;
	}

	socket->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '4TDW');
	if (!socket->sk_linux_attr) {
		err = -ENOMEM;
		goto out;
	}
	socket->sk_linux_attr->sk_rcvtimeo =
		socket->sk_linux_attr->sk_sndtimeo = connect_int * HZ;
	dtt_setbufsize(socket, sndbuf_size, rcvbuf_size);

	/* explicitly bind to the configured IP as source IP
	*  for the outgoing connections.
	*  This is needed for multihomed hosts and to be
	*  able to use lo: interfaces for drbd.
	* Make sure to use 0 as port number, so linux selects
	*  a free one dynamically.
	*/
	what = "bind before connect";
	// DW-835 Bind fail issue(fix with INADDR_ANY address parameter) 
	if(my_addr.ss_family == AF_INET ) {
		LocalAddressV4.sin_family = AF_INET;
		LocalAddressV4.sin_addr.s_addr = INADDR_ANY;
		LocalAddressV4.sin_port = HTONS(0);
	} else {
		//AF_INET6
		LocalAddressV6.sin6_family = AF_INET6;
		//LocalAddressV6.sin6_addr.s_addr = IN6ADDR_ANY_INIT;
		LocalAddressV6.sin6_port = HTONS(0); 
	}
	status = Bind(socket->sk, (my_addr.ss_family == AF_INET) ? (PSOCKADDR)&LocalAddressV4 : (PSOCKADDR)&LocalAddressV6 );
	if (!NT_SUCCESS(status)) {
		WDRBD_ERROR("Bind() failed with status 0x%08X \n", status);
		err = -EINVAL;
		goto out;
	}
	if (err < 0)
		goto out;

	/* connect may fail, peer not yet available.
	 * stay C_CONNECTING, don't go Disconnecting! */
	what = "connect";
	status = Connect(socket->sk, (struct sockaddr *) &peer_addr);
	if (!NT_SUCCESS(status)) {
		err = status;
		switch (status) {
		case STATUS_CONNECTION_REFUSED: err = -ECONNREFUSED; break;
		case STATUS_INVALID_DEVICE_STATE: err = -EAGAIN; break;
		case STATUS_NETWORK_UNREACHABLE: err = -ENETUNREACH; break;
		case STATUS_HOST_UNREACHABLE: err = -EHOSTUNREACH; break;
		default: err = -EINVAL; break;
		}
	} else {
		if (status == STATUS_TIMEOUT) { 
			err = -ETIMEDOUT; 
		} else { 
			if (status == 0) {
				err = 0;
			} else {
				err = -EINVAL;
			}
		}
	}
	
#endif 	// _WSK_SOCKETCONNECT end

	if (err < 0) {
		switch (err) {
		case -ETIMEDOUT:
		case -EINPROGRESS:
		case -EINTR:
		case -ERESTARTSYS:
		case -ECONNREFUSED:
		case -ENETUNREACH:
		case -EHOSTDOWN:
		case -EHOSTUNREACH:
			err = -EAGAIN;
		}
	}

out:
	if (err < 0) {
		if (socket)
			sock_release(socket);
		// DW-1272 : retry SocketConnect if STATUS_INVALID_ADDRESS_COMPONENT
		if (err != -EAGAIN && err != -EINVALADDR)
			tr_err(transport, "%s failed, err = %d\n", what, err);
	} else {
		*ret_socket = socket;
	}

	return err;
}

static int dtt_send_first_packet(struct drbd_tcp_transport *tcp_transport, struct socket *socket,
			     enum drbd_packet cmd, enum drbd_stream stream)
{
	struct p_header80 h;
	int msg_flags = 0;
	int err;

	if (!socket)
		return -EIO;

	h.magic = cpu_to_be32(DRBD_MAGIC);
	h.command = cpu_to_be16(cmd);
	h.length = 0;

	err = _dtt_send(tcp_transport, socket, &h, sizeof(h), msg_flags);

	return err;
}

/**
 * dtt_socket_ok_or_free() - Free the socket if its connection is not okay
 * @sock:	pointer to the pointer to the socket.
 */
static bool dtt_socket_ok_or_free(struct socket **socket)
{
	if (!*socket)
		return false;

    SIZE_T out = 0;
    NTSTATUS Status = ControlSocket( (*socket)->sk, WskIoctl, SIO_WSK_QUERY_RECEIVE_BACKLOG, 0, 0, NULL, sizeof(SIZE_T), &out, NULL );
	if (!NT_SUCCESS(Status)) {
        WDRBD_ERROR("socket(0x%p), ControlSocket(%s): SIO_WSK_QUERY_RECEIVE_BACKLOG failed=0x%x\n", (*socket), (*socket)->name, Status); // _WIN32
		kernel_sock_shutdown(*socket, SHUT_RDWR);
		sock_release(*socket);
        *socket = NULL;
        return false;
	}

    WDRBD_TRACE_SK("socket(0x%p) wsk(0x%p) ControlSocket(%s): backlog=%d\n", (*socket), (*socket)->sk, (*socket)->name, out); // _WIN32
    return true;
}

static bool dtt_connection_established(struct drbd_transport *transport,
				       struct socket **socket1,
				       struct socket **socket2,
				       struct dtt_path **first_path)
{
	KIRQL rcu_flags;
	struct net_conf *nc;
	int timeout, good = 0;

	if (!*socket1 || !*socket2)
		return false;

	rcu_flags = rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	timeout = (nc->sock_check_timeo ? nc->sock_check_timeo : nc->ping_timeo) * HZ / 10;
	rcu_read_unlock(rcu_flags);
	schedule_timeout_interruptible(timeout);

	good += dtt_socket_ok_or_free(socket1);
	good += dtt_socket_ok_or_free(socket2);

	if (good == 0)
		*first_path = NULL;

	return good == 2;
}

static struct dtt_path *dtt_wait_connect_cond(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_listener *listener;
	struct drbd_path *drbd_path;
	struct dtt_path *path = 0;
	bool rv = false;

	mutex_lock(&tcp_transport->paths_mutex);
	list_for_each_entry(struct drbd_path, drbd_path, &transport->paths, list) {
		path = container_of(drbd_path, struct dtt_path, path);
		listener = drbd_path->listener;
		spin_lock_bh(&listener->waiters_lock);
		rv = listener->pending_accepts > 0 || path->socket != NULL;
		spin_unlock_bh(&listener->waiters_lock);

		if (rv)
			break;
	}
	mutex_unlock(&tcp_transport->paths_mutex);

	return rv ? path : NULL;
}

static int dtt_wait_for_connect(struct drbd_transport *drbd_transport,
		struct drbd_listener *drbd_listener,
		struct socket **socket,
		struct dtt_path **ret_path)
{
	KIRQL rcu_flags;
	struct sockaddr_storage_win my_addr, peer_addr;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PWSK_SOCKET paccept_socket = NULL;
	int connect_int, peer_addr_len, err = 0;
	long timeo;
    struct socket *s_estab = NULL;
	struct net_conf *nc;
	struct drbd_path *drbd_path2;
	struct drbd_tcp_transport *transport = container_of(drbd_transport, struct drbd_tcp_transport, transport);
	struct dtt_listener *listener = container_of(drbd_listener, struct dtt_listener, listener);
	struct dtt_path *path = NULL;

	rcu_flags = rcu_read_lock();
	nc = rcu_dereference(drbd_transport->net_conf);
	if (!nc) {
		rcu_read_unlock(rcu_flags);
		return -EINVAL;
	}
	connect_int = nc->connect_int;
	rcu_read_unlock(rcu_flags);

	timeo = connect_int * HZ;
	timeo += (prandom_u32() & 1) ? timeo / 7 : -timeo / 7; /* 28.5% random jitter */

retry:
    atomic_set(&(transport->listening), 1);
	wait_event_interruptible_timeout(timeo, path->wait,
		(path = dtt_wait_connect_cond(drbd_transport)),
			timeo);
	atomic_set(&(transport->listening), 0);
	if (-DRBD_SIGKILL == timeo)
	{
		return -DRBD_SIGKILL;
	}
    if (-ETIMEDOUT == timeo)
		return -EAGAIN;

	spin_lock_bh(&listener->listener.waiters_lock);
	if (path->socket) {
		s_estab = path->socket;
		path->socket = NULL;
	} else if (listener->listener.pending_accepts > 0) {
		listener->listener.pending_accepts--;
		spin_unlock_bh(&listener->listener.waiters_lock);

		s_estab = NULL;
		// Accept and, create s_estab.
		memset(&peer_addr, 0, sizeof(struct sockaddr_storage_win));
		// saved paccept_socket in Accept Event Callback
		// paccept_socket = Accept(listener->s_listen->sk, (PSOCKADDR)&my_addr, (PSOCKADDR)&peer_addr, status, timeo / HZ);
		// 
		if (listener->paccept_socket) {
			s_estab = kzalloc(sizeof(struct socket), 0, '5TDW');
			if (!s_estab) {
				return -ENOMEM;
			}
			s_estab->sk = listener->paccept_socket;
			sprintf(s_estab->name, "estab_sock");
			s_estab->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '6TDW');
			if (!s_estab->sk_linux_attr) {
				kfree(s_estab);
				return -ENOMEM;
			}
#ifdef _WIN32_SEND_BUFFING
			if (nc->sndbuf_size < DRBD_SNDBUF_SIZE_DEF)
			{
				if (nc->sndbuf_size > 0)
				{
					tr_warn(transport, "sndbuf_size(%d) -> (%d)\n", nc->sndbuf_size, DRBD_SNDBUF_SIZE_DEF);
					nc->sndbuf_size = DRBD_SNDBUF_SIZE_DEF;
				}
			}
			dtt_setbufsize(s_estab, nc->sndbuf_size, nc->rcvbuf_size);
#endif
            s_estab->sk_linux_attr->sk_sndbuf = SOCKET_SND_DEF_BUFFER;
		}
		else {
			if (status == STATUS_TIMEOUT) {
				err = -EAGAIN;
			}
			else {
				err = -1;
			}
		}
		if (err < 0)
			return err;

		/* The established socket inherits the sk_state_change callback
		   from the listening socket. */
		status = GetRemoteAddress(s_estab->sk, (PSOCKADDR)&peer_addr);
		if(status != STATUS_SUCCESS) {
			kfree(s_estab->sk_linux_attr);
			kfree(s_estab);
			return -1;
		}
		spin_lock_bh(&listener->listener.waiters_lock);
		drbd_path2 = drbd_find_path_by_addr(&listener->listener, &peer_addr);
		if (!drbd_path2) {
			struct sockaddr_in6 *from_sin6;
			struct sockaddr_in *from_sin;

			switch (peer_addr.ss_family) {
			case AF_INET6:
				from_sin6 = (struct sockaddr_in6 *)&peer_addr;
				tr_err(&transport->transport, "Closing unexpected connection from "
				       "%pI6\n", &from_sin6->sin6_addr);
				break;
			default:
				from_sin = (struct sockaddr_in *)&peer_addr;
				tr_err(&transport->transport, "Closing unexpected connection from "
					 "%pI4\n", &from_sin->sin_addr);
				break;
			}

			goto retry_locked;
		}
		if (drbd_path2 != &path->path) {
			struct dtt_path *path2 =
				container_of(drbd_path2, struct dtt_path, path);
			if (path2->socket) {
				tr_err(&transport->transport, /* path2->transport, */
					 "Receiver busy; rejecting incoming connection\n");
				goto retry_locked;
			}
			path2->socket = s_estab;
			s_estab = NULL;
			wake_up(&path2->wait);
			goto retry_locked;
		}
	}
	WDRBD_TRACE_CO("%p dtt_wait_for_connect ok done.\n", KeGetCurrentThread());
	spin_unlock_bh(&listener->listener.waiters_lock);
	*socket = s_estab;
	*ret_path = path;
	return 0;

retry_locked:
	spin_unlock_bh(&listener->listener.waiters_lock);
	if (s_estab) {
		kernel_sock_shutdown(s_estab, SHUT_RDWR);
		sock_release(s_estab);
		s_estab = NULL;
	}
	goto retry;
}

static int dtt_receive_first_packet(struct drbd_tcp_transport *tcp_transport, struct socket *socket)
{
	KIRQL rcu_flags;
	struct drbd_transport *transport = &tcp_transport->transport;
	struct p_header80 *h = tcp_transport->rbuf[DATA_STREAM].base;
	const unsigned int header_size = sizeof(*h);
	struct net_conf *nc;
	int err;

	rcu_flags = rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock(rcu_flags);
		return -EIO;
	}
	socket->sk_linux_attr->sk_rcvtimeo = nc->ping_timeo * 4 * HZ / 10;
	rcu_read_unlock(rcu_flags);

	err = dtt_recv_short(socket, h, header_size, 0);
    WDRBD_TRACE_SK("socket(0x%p) err(%d) header_size(%d)\n", socket, err, header_size);
	if (err != header_size) {
		if (err >= 0)
			err = -EIO;
		return err;
	}
	if (h->magic != cpu_to_be32(DRBD_MAGIC)) {
		tr_err(transport, "Wrong magic value 0x%08x in receive_first_packet\n",
			 be32_to_cpu(h->magic));
		return -EINVAL;
	}
	return be16_to_cpu(h->command);
}

NTSTATUS WSKAPI
dtt_incoming_connection (
    _In_  PVOID         SocketContext,
    _In_  ULONG         Flags,
    _In_  PSOCKADDR     LocalAddress,
    _In_  PSOCKADDR     RemoteAddress,
    _In_opt_  PWSK_SOCKET AcceptSocket,
    _Outptr_result_maybenull_ PVOID *AcceptSocketContext,
    _Outptr_result_maybenull_ CONST WSK_CLIENT_CONNECTION_DISPATCH **AcceptSocketDispatch
)
{
    struct socket * s_estab = kzalloc(sizeof(struct socket), 0, '7TDW');

    if (!s_estab)
    {
        return STATUS_REQUEST_NOT_ACCEPTED;
    }

    s_estab->sk = AcceptSocket;
    sprintf(s_estab->name, "estab_sock");
    s_estab->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '8TDW');

    if (s_estab->sk_linux_attr)
    {
        s_estab->sk_linux_attr->sk_sndbuf = SOCKET_SND_DEF_BUFFER;
    }
    else
    {
        kfree(s_estab);
        return STATUS_REQUEST_NOT_ACCEPTED;
    }
    
    struct dtt_listener *listener = (struct dtt_listener *)SocketContext;
	if(!listener) {
		kfree(s_estab->sk_linux_attr);
		kfree(s_estab);
        return STATUS_REQUEST_NOT_ACCEPTED;
	}
    spin_lock(&listener->listener.waiters_lock);
    struct drbd_path *drbd_path = drbd_find_path_by_addr(&listener->listener, (struct sockaddr_storage_win*)RemoteAddress);
	if(!drbd_path) {
		kfree(s_estab->sk_linux_attr);
		kfree(s_estab);
		spin_unlock(&listener->listener.waiters_lock);
        return STATUS_REQUEST_NOT_ACCEPTED;
	}

    if (drbd_path)
    {
		struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);
        path->socket = s_estab;
		wake_up(&path->wait);
    }
    else
    {
        listener->listener.pending_accepts++;
        listener->paccept_socket = AcceptSocket;
    }
	spin_unlock(&listener->listener.waiters_lock);
//    WDRBD_TRACE_SK("waiter(0x%p) s_estab(0x%p) wsk(0x%p) wake!!!!\n", waiter, s_estab, AcceptSocket);

	return STATUS_SUCCESS;
}

static void dtt_destroy_listener(struct drbd_listener *generic_listener)
{
	struct dtt_listener *listener =
		container_of(generic_listener, struct dtt_listener, listener);

	sock_release(listener->s_listen);
	kfree(listener);
}

// A listening socket's WskInspectEvent event callback function
WSK_INSPECT_ACTION WSKAPI
dtt_inspect_incoming(
    PVOID SocketContext,
    PSOCKADDR LocalAddress,
    PSOCKADDR RemoteAddress,
    PWSK_INSPECT_ID InspectID
)
{
    // Check for a valid inspect ID
    if (NULL == InspectID)
    {
        return WskInspectReject;
    }

    WSK_INSPECT_ACTION action = WskInspectAccept;
    struct dtt_listener *listener = (struct dtt_listener *)SocketContext;

    spin_lock(&listener->listener.waiters_lock);
	struct drbd_path *drbd_path = drbd_find_path_by_addr(&listener->listener, (struct sockaddr_storage_win*)RemoteAddress);
	if (!drbd_path) {
        action = WskInspectReject;
        goto out;
    }
    struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);
    struct drbd_tcp_transport *transport = container_of(&path->first->transport, struct drbd_tcp_transport, transport);

    if (!atomic_read(&transport->listening)) {
        action = WskInspectReject;
        goto out;
    }

    atomic_set(&transport->listening, 0);
out:
    spin_unlock(&listener->listener.waiters_lock);
 
    return action;
}

// A listening socket's WskAbortEvent event callback function
NTSTATUS WSKAPI
dtt_abort_inspect_incoming(
    PVOID SocketContext,
    PWSK_INSPECT_ID InspectID
)
{
    // Terminate the inspection for the incoming connection
    // request with a matching inspect ID. To test for a matching
    // inspect ID, the contents of the WSK_INSPECT_ID structures
    // must be compared, not the pointers to the structures.
    return STATUS_SUCCESS;
}

WSK_CLIENT_LISTEN_DISPATCH dispatch = {
	dtt_incoming_connection,
    dtt_inspect_incoming,       // WskInspectEvent is required only if conditional-accept is used.
    dtt_abort_inspect_incoming  // WskAbortEvent is required only if conditional-accept is used.
};


static int dtt_create_listener(struct drbd_transport *transport,
			       const struct sockaddr *addr,
			       struct drbd_listener **ret_listener)
{
	KIRQL rcu_flags;
	int err = 0, sndbuf_size, rcvbuf_size; 
	struct sockaddr_storage_win my_addr;
	NTSTATUS status;
	SOCKADDR_IN ListenV4Addr = {0,};
	SOCKADDR_IN6 ListenV6Addr = {0,};
	struct dtt_listener *listener = NULL;
	struct socket *s_listen;
	struct net_conf *nc;
	const char *what;

	rcu_flags = rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock(rcu_flags);
		return -EINVAL;
	}
	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	rcu_read_unlock(rcu_flags);

	my_addr = *(struct sockaddr_storage_win *)addr;

	what = "sock_create_kern";
	s_listen = kzalloc(sizeof(struct socket), 0, '9TDW');
	if (!s_listen)
	{
		err = -ENOMEM;
		goto out;
	}
	sprintf(s_listen->name, "listen_sock\0");
	s_listen->sk_linux_attr = 0;
	err = 0;
	listener = kzalloc(sizeof(struct dtt_listener), 0, 'ATDW');
	if (!listener) {
		err = -ENOMEM;
		goto out;
	}

	if (my_addr.ss_family == AF_INET6) {
		s_listen->sk = CreateSocket(AF_INET6, SOCK_STREAM, IPPROTO_TCP, (PVOID*)listener, &dispatch, WSK_FLAG_LISTEN_SOCKET); // this is listen socket
	} else {
		s_listen->sk = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, (PVOID*)listener, &dispatch, WSK_FLAG_LISTEN_SOCKET); // this is listen socket
	}
	if (s_listen->sk == NULL) {
		err = -1;
		goto out;
	}

	status = SetConditionalAccept(s_listen->sk, 1);
	if (!NT_SUCCESS(status))
	{
		WDRBD_ERROR("Failed to set SO_CONDITIONAL_ACCEPT. err(0x%x)\n", status);
		err = status;
		goto out;
	}
	s_listen->sk_linux_attr = kzalloc(sizeof(struct sock), 0, 'BTDW');
	if (!s_listen->sk_linux_attr)
	{
		err = -ENOMEM;
		goto out;
	}

	s_listen->sk_linux_attr->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
	LONG InputBuffer = 1;
	status = ControlSocket(s_listen->sk, WskSetOption, SO_REUSEADDR, SOL_SOCKET, sizeof(ULONG), &InputBuffer, 0, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		WDRBD_ERROR("ControlSocket: s_listen socket SO_REUSEADDR: failed=0x%x\n", status);
		err = -1;
		goto out;
	}
	dtt_setbufsize(s_listen, sndbuf_size, rcvbuf_size);

	what = "bind before listen";

	// DW-835 Bind fail issue(fix with INADDR_ANY address parameter) 
	if(my_addr.ss_family == AF_INET ) {
		ListenV4Addr.sin_family = AF_INET;
		ListenV4Addr.sin_port = *((USHORT*)my_addr.__data);
		ListenV4Addr.sin_addr.s_addr = INADDR_ANY;
	} else {
		//AF_INET6
		ListenV6Addr.sin6_family = AF_INET6;
		ListenV6Addr.sin6_port = *((USHORT*)my_addr.__data); 
		//ListenV6Addr.sin6_addr = IN6ADDR_ANY_INIT;
	}

	status = Bind(s_listen->sk, (my_addr.ss_family == AF_INET) ? (PSOCKADDR)&ListenV4Addr : (PSOCKADDR)&ListenV6Addr);

	if (!NT_SUCCESS(status)) {
		if(my_addr.ss_family == AF_INET) {
			WDRBD_ERROR("AF_INET Failed to socket Bind(). err(0x%x) %02X.%02X.%02X.%02X:0x%X%X\n", status, (UCHAR)my_addr.__data[2], (UCHAR)my_addr.__data[3], (UCHAR)my_addr.__data[4], (UCHAR)my_addr.__data[5],(UCHAR)my_addr.__data[0],(UCHAR)my_addr.__data[1]);
		} else {
			WDRBD_ERROR("AF_INET6 Failed to socket Bind(). err(0x%x) [%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X]:0x%X%X\n", status, (UCHAR)my_addr.__data[2],(UCHAR)my_addr.__data[3], (UCHAR)my_addr.__data[4],(UCHAR)my_addr.__data[5],
					(UCHAR)my_addr.__data[6],(UCHAR)my_addr.__data[7], (UCHAR)my_addr.__data[8],(UCHAR)my_addr.__data[9],
					(UCHAR)my_addr.__data[10],(UCHAR)my_addr.__data[11], (UCHAR)my_addr.__data[12],(UCHAR)my_addr.__data[13],
					(UCHAR)my_addr.__data[14],(UCHAR)my_addr.__data[15],(UCHAR)my_addr.__data[16],(UCHAR)my_addr.__data[17],
					(UCHAR)my_addr.__data[0], (UCHAR)my_addr.__data[1]);
		}
		err = -1;
		goto out;
	}

	if (err < 0)
		goto out;


	listener->listener.listen_addr = my_addr;
	listener->listener.destroy = dtt_destroy_listener;

	*ret_listener = &listener->listener;

	// DW-845 fix crash issue(EventCallback is called when listener is not initialized, then reference to invalid Socketcontext at dtt_inspect_incoming.)
	status = SetEventCallbacks(s_listen->sk, WSK_EVENT_ACCEPT);
	if (!NT_SUCCESS(status)) {
		WDRBD_ERROR("Failed to set WSK_EVENT_ACCEPT. err(0x%x)\n", status);
		err = -1;
		goto out;
	}
	return 0;
out:
	if (s_listen)
		sock_release(s_listen);

	if (err < 0 &&
			err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS && err != -EADDRINUSE)
		tr_err(transport, "%s failed, err = %d\n", what, err);

	kfree(listener);

	return err;
}


static void dtt_put_listeners(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_path *drbd_path;

	mutex_lock(&tcp_transport->paths_mutex);
	clear_bit(DTT_CONNECTING, &tcp_transport->flags);

	list_for_each_entry(struct drbd_path, drbd_path, &transport->paths, list) {
		struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);

		path->first = NULL;
		drbd_put_listener(&path->path);
		if (path->socket) {
			sock_release(path->socket);
			path->socket = NULL;
		}
	}
	mutex_unlock(&tcp_transport->paths_mutex);
}

static struct dtt_path *dtt_next_path(struct drbd_tcp_transport *tcp_transport, struct dtt_path *path)
{
	struct drbd_transport *transport = &tcp_transport->transport;
	struct drbd_path *drbd_path;

	mutex_lock(&tcp_transport->paths_mutex);
	if (list_is_last(&path->path.list, &transport->paths))
		drbd_path = list_first_entry(&transport->paths, struct drbd_path, list);
	else
		drbd_path = list_next_entry(struct drbd_path, &path->path, list);
	mutex_unlock(&tcp_transport->paths_mutex);

	return container_of(drbd_path, struct dtt_path, path);
}
extern char * get_ip4(char *buf, struct sockaddr_in *sockaddr);
extern char * get_ip6(char *buf, struct sockaddr_in6 *sockaddr);

static int dtt_connect(struct drbd_transport *transport)
{
	KIRQL rcu_flags;
	NTSTATUS status;
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_path *drbd_path;
	struct dtt_path *connect_to_path, *first_path = NULL;
	struct socket *dsocket, *csocket;
	struct net_conf *nc;
	struct dtt_wait_first waiter;
	int timeout, err;
	bool ok;
	char sbuf[128], dbuf[128];
	ok = FALSE;
	dsocket = NULL;
	csocket = NULL;

	waiter.transport = transport;
//	init_waitqueue_head(&waiter.wait);

	mutex_lock(&tcp_transport->paths_mutex);
	set_bit(DTT_CONNECTING, &tcp_transport->flags);

	err = -EDESTADDRREQ;
	if (list_empty(&transport->paths))
		goto out_unlock;

	list_for_each_entry(struct drbd_path, drbd_path, &transport->paths, list) {
		struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);
		{
			if (path->path.my_addr.ss_family == AF_INET6) {
				WDRBD_TRACE("dtt_connect: dtt_connect: path: %s -> %s.\n", get_ip6(sbuf, (struct sockaddr_in6*)&path->path.my_addr), get_ip6(dbuf, (struct sockaddr_in6*)&path->path.peer_addr));
			}
			else {
				WDRBD_TRACE("dtt_connect: dtt_connect: path: %s -> %s.\n", get_ip4(sbuf, (struct sockaddr_in*)&path->path.my_addr), get_ip4(dbuf, (struct sockaddr_in*)&path->path.peer_addr));
			}
		}
		path->first = &waiter;
		err = drbd_get_listener(transport, &path->path, dtt_create_listener);
		if (err)
			goto out_unlock;
	}

	drbd_path = list_first_entry(&transport->paths, struct drbd_path, list);
        {
		if (drbd_path->my_addr.ss_family == AF_INET6) {
			WDRBD_TRACE("dtt_connect: drbd_path: %s -> %s \n", get_ip6(sbuf, (struct sockaddr_in6*)&drbd_path->my_addr), get_ip6(dbuf, (struct sockaddr_in6*)&drbd_path->peer_addr));
		} else {
			WDRBD_TRACE("dtt_connect: drbd_path: %s -> %s \n", get_ip4(sbuf, (struct sockaddr_in*)&drbd_path->my_addr), get_ip4(dbuf, (struct sockaddr_in*)&drbd_path->peer_addr));
		}
	}


	connect_to_path = container_of(drbd_path, struct dtt_path, path);
	{
		if(connect_to_path->path.my_addr.ss_family == AF_INET6) {
			WDRBD_TRACE("dtt_connect: connect_to_path: %s -> %s \n", get_ip6(sbuf, (struct sockaddr_in6*)&connect_to_path->path.my_addr), get_ip6(dbuf, (struct sockaddr_in6*)&connect_to_path->path.peer_addr));
		} else {
			WDRBD_TRACE("dtt_connect: connect_to_path: %s -> %s \n", get_ip4(sbuf, (struct sockaddr_in*)&connect_to_path->path.my_addr), get_ip4(dbuf, (struct sockaddr_in*)&connect_to_path->path.peer_addr));
		}
	}
	mutex_unlock(&tcp_transport->paths_mutex);

	do {
		struct socket *s = NULL;

		err = dtt_try_connect(transport, connect_to_path, &s);

		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
#ifdef WDRBD_TRACE_IP4
			{
				if (connect_to_path->path.my_addr.ss_family == AF_INET6) {
					WDRBD_TRACE("dtt_connect: Connected: %s -> %s\n", get_ip6(sbuf, (struct sockaddr_in6*)&connect_to_path->path.my_addr), get_ip6(dbuf, (struct sockaddr_in6*)&connect_to_path->path.peer_addr));
				} else {
					WDRBD_TRACE("dtt_connect: Connected: %s -> %s\n", get_ip4(sbuf, (struct sockaddr_in*)&connect_to_path->path.my_addr), get_ip4(dbuf, (struct sockaddr_in*)&connect_to_path->path.peer_addr));
				}
			}
#endif

			bool use_for_data;

			if (!first_path) {
				first_path = connect_to_path;
			} else if (first_path != connect_to_path) {
				tr_warn(transport, "initial pathes crossed A\n");
				kernel_sock_shutdown(s, SHUT_RDWR);
				sock_release(s);
				connect_to_path = first_path;
				continue;
			}

			// MODIFIED_BY_MANTECH DW-1297 : rollback 'Avoid initial packet S crossed' because a feature packet timeout occurs.
			if (!dsocket) {
				dsocket = s;
                sprintf(dsocket->name, "data_sock\0");
                if (dtt_send_first_packet(tcp_transport, dsocket, P_INITIAL_DATA, DATA_STREAM) <= 0) {
                    sock_release(s);
                    dsocket = 0;
                    goto retry;
                }
			} else if (!csocket) {
				clear_bit(RESOLVE_CONFLICTS, &transport->flags);
				csocket = s;
                sprintf(csocket->name, "meta_sock\0");
                if (dtt_send_first_packet(tcp_transport, csocket, P_INITIAL_META, CONTROL_STREAM) <= 0)
                {
                    sock_release(s);
                    csocket = 0;
                    goto retry;
                }
			} else {
				tr_err(transport, "Logic error in conn_connect()\n");
				goto out_eagain;
			}
		} else if (!first_path)
			connect_to_path = dtt_next_path(tcp_transport, connect_to_path);

		if (dtt_connection_established(transport, &dsocket, &csocket, &first_path))
			break;

retry:
		s = NULL;
		err = dtt_wait_for_connect(transport, connect_to_path->path.listener, &s, &connect_to_path);
		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
#ifdef WDRBD_TRACE_IP4 
			{
				if (connect_to_path->path.my_addr.ss_family == AF_INET6) {
					WDRBD_TRACE("dtt_connect:(%p) Accepted:  %s <- %s\n", KeGetCurrentThread(), get_ip6(sbuf, (struct sockaddr_in6*)&connect_to_path->path.my_addr), get_ip6(dbuf, (struct sockaddr_in6*)&connect_to_path->path.peer_addr));
				} else {
					WDRBD_TRACE("dtt_connect:(%p) Accepted:  %s <- %s\n", KeGetCurrentThread(), get_ip4(sbuf, (struct sockaddr_in*)&connect_to_path->path.my_addr), get_ip4(dbuf, (struct sockaddr_in*)&connect_to_path->path.peer_addr));
				}				
			}
#endif
			int fp = dtt_receive_first_packet(tcp_transport, s);

			if (!first_path) {
				first_path = connect_to_path;
			} else if (first_path != connect_to_path) {
				tr_warn(transport, "initial pathes crossed P\n");
				kernel_sock_shutdown(s, SHUT_RDWR);
				sock_release(s);
				connect_to_path = first_path;
				goto randomize;
			}
			dtt_socket_ok_or_free(&dsocket);
			dtt_socket_ok_or_free(&csocket);
			switch (fp) {
			case P_INITIAL_DATA:
				if (dsocket) {
					tr_warn(transport, "initial packet S crossed\n");
					kernel_sock_shutdown(dsocket, SHUT_RDWR);
					sock_release(dsocket);
					dsocket = s;
					goto randomize;
				}
				dsocket = s;
				break;
			case P_INITIAL_META:
				set_bit(RESOLVE_CONFLICTS, &transport->flags);
				if (csocket) {
					tr_warn(transport, "initial packet M crossed\n");
					kernel_sock_shutdown(csocket, SHUT_RDWR);
					sock_release(csocket);
					csocket = s;
					goto randomize;
				}
				csocket = s;
				break;
			default:
				tr_warn(transport, "Error receiving initial packet\n");
				kernel_sock_shutdown(s, SHUT_RDWR);
				sock_release(s);
randomize:
				if (prandom_u32() & 1)
					goto retry;
			}
		}

		if (drbd_should_abort_listening(transport))
			goto out_eagain;

		ok = dtt_connection_established(transport, &dsocket, &csocket, &first_path);
	} while (!ok);
	TR_ASSERT(transport, first_path == connect_to_path);
	connect_to_path->path.established = true;
	drbd_path_event(transport, &connect_to_path->path);
	dtt_put_listeners(transport);

    LONG InputBuffer = 1;
    status = ControlSocket(dsocket->sk, WskSetOption, SO_REUSEADDR, SOL_SOCKET, sizeof(ULONG), &InputBuffer, 0, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        WDRBD_ERROR("ControlSocket: SO_REUSEADDR: failed=0x%x\n", status);
        goto out;
    }

    status = ControlSocket(csocket->sk, WskSetOption, SO_REUSEADDR, SOL_SOCKET, sizeof(ULONG), &InputBuffer, 0, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        WDRBD_ERROR("ControlSocket: SO_REUSEADDR: failed=0x%x\n", status);
        goto out;
    }
	/* NOT YET ...
	 * sock.socket->sk->sk_sndtimeo = transport->net_conf->timeout*HZ/10;
	 * sock.socket->sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;
	 * first set it to the P_CONNECTION_FEATURES timeout,
	 * which we set to 4x the configured ping_timeout. */

	/* we don't want delays.
	 * we use TCP_CORK where appropriate, though */
	dtt_nodelay(dsocket);
	dtt_nodelay(csocket);

	tcp_transport->stream[DATA_STREAM] = dsocket;
	tcp_transport->stream[CONTROL_STREAM] = csocket;

	rcu_flags = rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);

	timeout = nc->timeout * HZ / 10;
	rcu_read_unlock(rcu_flags);

	dsocket->sk_linux_attr->sk_sndtimeo = timeout;
	csocket->sk_linux_attr->sk_sndtimeo = timeout;

#ifdef _WIN32_SEND_BUFFING
    if ((nc->wire_protocol == DRBD_PROT_A) && (nc->sndbuf_size > 0) )
    {
        bool send_buffring = FALSE;

        send_buffring = dtt_start_send_buffring(transport, nc->sndbuf_size);
        if (send_buffring)
            drbd_info(connection, "buffering s(%d) c(%d)\n", nc->sndbuf_size, (nc->cong_fill * 512));
        else
            drbd_warn(connection, "send-buffering disabled\n");
    }
    else
    {
        drbd_warn(connection, "send-buffering disabled\n");
    }
#endif

	return 0;

out_eagain:
	err = -EAGAIN;

	if (0) {
out_unlock:
		mutex_unlock(&tcp_transport->paths_mutex);
	}
out:
	dtt_put_listeners(transport);

	if (dsocket) {
		kernel_sock_shutdown(dsocket, SHUT_RDWR);
		sock_release(dsocket);
	}
	if (csocket) {
		kernel_sock_shutdown(csocket, SHUT_RDWR);
		sock_release(csocket);
	}

	return err;
}

static void dtt_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, LONG_PTR timeout)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];
	socket->sk_linux_attr->sk_rcvtimeo = timeout;
}

static long dtt_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];
	return socket->sk_linux_attr->sk_rcvtimeo;
}

static bool dtt_stream_ok(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];

	return socket && socket->sk;
}

static int dtt_send_page(struct drbd_transport *transport, enum drbd_stream stream,
			 struct page *page, int offset, size_t size, unsigned msg_flags)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];

	if(!socket) { 
		return -EIO;
	}
	
	int len = size;
	int err = -EIO;

	msg_flags |= MSG_NOSIGNAL;
	dtt_update_congested(tcp_transport);
	do {
		int sent;
		if (stream == DATA_STREAM)
		{
			// ignore rcu_dereference
			transport->ko_count = transport->net_conf->ko_count;
		}

#ifdef _WIN32_SEND_BUFFING 
		sent = send_buf(transport, stream, socket, (void *)((unsigned char *)(page->addr) +offset), len);
		// WIN32_SEND_ERR_FIX: move we_should_drop_the_connection to inside of send_buf, because retransmission occurred
#else
		sent = Send(socket->sk, (void *)((unsigned char *)(page->addr) + offset), len, 0, socket->sk_linux_attr->sk_sndtimeo, NULL, transport, stream);
#endif
		if (sent <= 0) {
#ifdef _WIN32_SEND_BUFFING
			if (sent == -EAGAIN) 
			{
				break;
			}
#else
			if (sent == -EAGAIN) {
				if (drbd_stream_send_timed_out(transport, stream))
					break;
				continue;
			}
#endif
			tr_warn(transport, "%s: size=%d len=%d sent=%d\n",
			     __func__, (int)size, len, sent);
			if (sent < 0)
				err = sent;
			break;
		}
		len    -= sent;
		offset += sent;
	} while (len > 0 /* THINK && peer_device->repl_state[NOW] >= L_ESTABLISHED */);
	clear_bit(NET_CONGESTED, &tcp_transport->transport.flags);

	if (len == 0)
		err = 0;

	return err;
}

static int dtt_send_zc_bio(struct drbd_transport *transport, struct bio *bio)
{
	DRBD_BIO_VEC_TYPE bvec;
	DRBD_ITER_TYPE iter;

	bio_for_each_segment(bvec, bio, iter) {
		int err;

		err = dtt_send_page(transport, DATA_STREAM, bvec BVD bv_page,
				      bvec BVD bv_offset, bvec BVD bv_len,
				      bio_iter_last(bvec, iter) ? 0 : MSG_MORE);
		if (err)
			return err;

		if (bio->bi_rw & DRBD_REQ_WSAME)
			break;
	}
	return 0;
}

static bool dtt_hint(struct drbd_transport *transport, enum drbd_stream stream,
		enum drbd_tr_hints hint)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	bool rv = true;
	struct socket *socket = tcp_transport->stream[stream];

	if (!socket)
		return false;

	switch (hint) {
	case CORK:
	case UNCORK:
	case NODELAY:
	case NOSPACE:
	case QUICKACK:
	default: /* not implemented, but should not trigger error handling */
		return true;
	}

	return rv;
}


static void dtt_debugfs_show(struct drbd_transport *transport, struct seq_file *m)
{
}

static int dtt_add_path(struct drbd_transport *transport, struct drbd_path *drbd_path)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);
	int err = 0;

	drbd_path->established = false;
	path->socket = NULL;
	path->first = NULL;
	init_waitqueue_head(&path->wait);

	mutex_lock(&tcp_transport->paths_mutex);
	if (test_bit(DTT_CONNECTING, &tcp_transport->flags)) {
		err = drbd_get_listener(transport, &path->path, dtt_create_listener);
		if (err)
			goto out_unlock;
	}

	list_add(&drbd_path->list, &transport->paths);

out_unlock:
	mutex_unlock(&tcp_transport->paths_mutex);

	return err;
}

static int dtt_remove_path(struct drbd_transport *transport, struct drbd_path *drbd_path)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);

	if (drbd_path->established)
		return -EBUSY;

	mutex_lock(&tcp_transport->paths_mutex);
	list_del_init(&drbd_path->list);
	drbd_put_listener(&path->path);
	mutex_unlock(&tcp_transport->paths_mutex);

	return 0;
}

int __init dtt_initialize(void)
{
	return drbd_register_transport_class(&tcp_transport_class,
					     DRBD_TRANSPORT_API_VERSION,
					     sizeof(struct drbd_transport));
}

static void __exit dtt_cleanup(void)
{
	drbd_unregister_transport_class(&tcp_transport_class);
}

#ifdef _WIN32_SEND_BUFFING

extern VOID NTAPI send_buf_thread(PVOID p);

static bool dtt_start_send_buffring(struct drbd_transport *transport, int size)
{
	struct drbd_tcp_transport *tcp_transport = container_of(transport, struct drbd_tcp_transport, transport);

	if (size > 0 )
	{
		int i;
		for (int i = 0; i < 2; i++)
		{
			if (tcp_transport->stream[i] != NULL)
			{
				struct _buffering_attr *attr = &tcp_transport->stream[i]->buffering_attr;

				if (attr->bab != NULL)
				{
					tr_warn(transport, "Unexpected: send buffer bab(%s) already exists!\n", tcp_transport->stream[i]->name);
					return FALSE;
				}

				if (attr->send_buf_thread_handle != NULL)
				{
					tr_warn(transport, "Unexpected: send buffer thread(%s) already exists!\n", tcp_transport->stream[i]->name);
					return FALSE;
				}

				if (i == CONTROL_STREAM)
				{
					size = 1024 * 5120; // meta bab is about 5MB
				}

				if ((attr->bab = create_ring_buffer(tcp_transport->stream[i]->name, size)) != NULL)
				{
					KeInitializeEvent(&attr->send_buf_kill_event, SynchronizationEvent, FALSE);
					KeInitializeEvent(&attr->send_buf_killack_event, SynchronizationEvent, FALSE);
					KeInitializeEvent(&attr->send_buf_thr_start_event, SynchronizationEvent, FALSE);
					KeInitializeEvent(&attr->ring_buf_event, SynchronizationEvent, FALSE);

					NTSTATUS Status = PsCreateSystemThread(&attr->send_buf_thread_handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, send_buf_thread, attr);
					if (!NT_SUCCESS(Status)) {
						tr_warn(transport, "send-buffering: create thread(%s) failed(0x%08X)\n", tcp_transport->stream[i]->name, Status);
						destroy_ring_buffer(attr->bab);
						attr->bab = NULL;
						return FALSE;
					}

					// wait send buffering thread start...
					KeWaitForSingleObject(&attr->send_buf_thr_start_event, Executive, KernelMode, FALSE, NULL);
				}
				else
				{
					if (i == CONTROL_STREAM)
					{
						attr = &tcp_transport->stream[DATA_STREAM]->buffering_attr;

						// kill DATA_STREAM thread
						KeSetEvent(&attr->send_buf_kill_event, 0, FALSE);
						//WDRBD_INFO("wait for send_buffering_data_thread(%s) ack\n", tcp_transport->stream[i]->name);
						KeWaitForSingleObject(&attr->send_buf_killack_event, Executive, KernelMode, FALSE, NULL);
						//WDRBD_INFO("send_buffering_data_thread(%s) acked\n", tcp_transport->stream[i]->name);
						attr->send_buf_thread_handle = NULL;
						
						// free DATA_STREAM bab
						destroy_ring_buffer(attr->bab);
						attr->bab = NULL;
					}
					return FALSE;
				}
			}
			else
			{
				tr_warn(transport, "Unexpected: send buffer socket(channel:%d) is null!\n", i);
				return FALSE;
			}
		}
		return TRUE;
	}
	return FALSE;
}

static void dtt_stop_send_buffring(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport = container_of(transport, struct drbd_tcp_transport, transport);
	struct _buffering_attr *attr;
	int err_ret = 0;
	int i;

	for (int i = 0; i < 2; i++)
	{
		if (tcp_transport->stream[i] != NULL)
		{
			attr = &tcp_transport->stream[i]->buffering_attr;

			if (attr->send_buf_thread_handle != NULL)
			{
				KeSetEvent(&attr->send_buf_kill_event, 0, FALSE);
				//WDRBD_INFO("wait for send_buffering_data_thread(%s) ack\n", tcp_transport->stream[i]->name);
				KeWaitForSingleObject(&attr->send_buf_killack_event, Executive, KernelMode, FALSE, NULL);
				//WDRBD_INFO("send_buffering_data_thread(%s) acked\n", tcp_transport->stream[i]->name);
				attr->send_buf_thread_handle = NULL;
			}
			else
			{
				WDRBD_WARN("No send_buffering thread(%s)\n", tcp_transport->stream[i]->name);
			}
		}
		else
		{
			//WDRBD_WARN("No stream(channel:%d)\n", i);
		}
	}
	return;
}
#endif // _WIN32_SEND_BUFFING


static void dtt_update_congested(struct drbd_tcp_transport *tcp_transport)
{
	/* TODO */
}

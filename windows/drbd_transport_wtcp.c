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
	struct mutex paths_lock;
	ULONG_PTR flags;
	struct socket *stream[2];
	struct buffer rbuf[2];
};

struct dtt_listener {
	struct drbd_listener listener;
	struct socket *s_listen;

	wait_queue_head_t wait; /* woken if a connection came in */
};

/* Since each path might have a different local IP address, each
   path might need its own listener. Therefore the drbd_waiter object
   is embedded into the dtt_path and _not_ the dtt_waiter. */

struct dtt_socket_container {
	struct list_head list;
	struct socket *socket;
};

struct dtt_wait_first {
	struct drbd_transport *transport;
};

struct dtt_path {
	struct drbd_path path;

	struct list_head sockets; /* sockets passed to me by other receiver threads */
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
	.listener_instance_size = sizeof(struct dtt_listener),
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

/* Might restart iteration, if current element is removed from list!! */
#define for_each_path_ref(path, transport)			\
	for (path = __drbd_next_path_ref(NULL, transport);	\
	     path;						\
	     path = __drbd_next_path_ref(path, transport))

/* This is save as long you use list_del_init() everytime something is removed
   from the list. */
static struct drbd_path *__drbd_next_path_ref(struct drbd_path *drbd_path,
					      struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	mutex_lock(&tcp_transport->paths_lock);
	if (!drbd_path) {
		drbd_path = list_first_entry_or_null(&transport->paths, struct drbd_path, list);
	} else {
		bool in_list = !list_empty(&drbd_path->list);
		kref_put(&drbd_path->kref, drbd_destroy_path);
		if (in_list) {
			/* Element still on the list, ref count can not drop to zero! */
			if (list_is_last(&drbd_path->list, &transport->paths))
				drbd_path = NULL;
			else
				drbd_path = list_next_entry(struct drbd_path, drbd_path, list);
		} else {
			/* No longer on the list, element might be freed already, restart from the start */
			drbd_path = list_first_entry_or_null(&transport->paths, struct drbd_path, list);
		}
	}
	if (drbd_path)
		kref_get(&drbd_path->kref);
	mutex_unlock(&tcp_transport->paths_lock);

	return drbd_path;
}

static void dtt_nodelay(struct socket *socket)
{
    /* No easy support in WSK.
     *   http://microsoft.public.win32.programmer.kernel.narkive.com/66x3EuCP/how-disabled-nagle-algorithm-in-kernel-mode
     *   http://www.osronline.com/showthread.cfm?link=137078
     *   https://msdn.microsoft.com/en-us/library/bb432313(v=vs.85).aspx
     *
     * Done via a flag WSK_FLAG_NODELAY on WskSend():
     *   https://msdn.microsoft.com/en-us/library/windows/hardware/ff571146(v=vs.85).aspx
     * */
    socket->no_delay = 1;
}

int dtt_init(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;

	mutex_init(&tcp_transport->paths_lock);
	tcp_transport->transport.ops = &dtt_ops;
	tcp_transport->transport.class = &tcp_transport_class;
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		void *buffer = __get_free_page(GFP_KERNEL);
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
	free_page(tcp_transport->rbuf[0].base);
	return -ENOMEM;
}

static void dtt_free_one_sock(struct socket *socket)
{
	if (socket) {
		synchronize_rcu();

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
			dtt_free_one_sock(tcp_transport->stream[i]);
			tcp_transport->stream[i] = NULL;
		}
	}

	for_each_path_ref(drbd_path, transport) {
		bool was_established = drbd_path->established;
		drbd_path->established = false;
		if (was_established)
			drbd_path_event(transport, drbd_path);
	}

	if (free_op == DESTROY_TRANSPORT) {
		struct drbd_path *tmp;

		for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
			free_page(tcp_transport->rbuf[i].base);
			tcp_transport->rbuf[i].base = NULL;
		}
		mutex_lock(&tcp_transport->paths_lock);
		list_for_each_entry_safe(struct drbd_path, drbd_path, tmp, &transport->paths, list) {
			list_del_init(&drbd_path->list);
			kref_put(&drbd_path->kref, drbd_destroy_path);
		}
		mutex_unlock(&tcp_transport->paths_lock);
	}
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
		rv = Send(socket->sk, DataBuffer, iov_len, 0, socket->sk_sndtimeo);

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
	return Receive(socket->sk, buf, size, flags, socket->sk_rcvtimeo);
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

	page_chain_for_each(page) {
		size_t len = min_t(int, size, PAGE_SIZE);
		void *data = kmap(page);
		err = dtt_recv_short(socket, data, len, 0);
		kunmap(page);
		set_page_chain_offset(page, 0);
		set_page_chain_size(page, len);
		if (err < 0)
			goto fail;
		size -= len;
	}
	return 0;
fail:
	drbd_free_page_chain(transport, chain, 0);
	kfree(page); // PMaskPR
	return err;
}

static void dtt_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[DATA_STREAM];

	if (socket) {
		/* https://msdn.microsoft.com/de-de/library/ff570818(v=vs.85).aspx */
		/* TODO: implement */
//		printk("stats not implemented.\n");
		// not supported
	}
}

static void dtt_setbufsize(struct socket *socket, unsigned int snd,
			   unsigned int rcv)
{
	NTSTATUS status;

	if (snd) {
		status = ControlSocket(socket->sk, WskSetOption, SO_SNDBUF, SOL_SOCKET, sizeof(snd), &snd, 0, NULL, NULL);
		if (status != STATUS_SUCCESS)
			printk(KERN_WARNING "Could not set send buffer size to %d, status is %x\n", snd, status);
	}

	if (rcv) {
		status = ControlSocket(socket->sk, WskSetOption, SO_RCVBUF, SOL_SOCKET, sizeof(rcv), &rcv, 0, NULL, NULL);
		if (status != STATUS_SUCCESS)
			printk(KERN_WARNING "Could not set receive buffer size to %d, status is %x\n", rcv, status);
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
	const char *what;
	struct socket *socket;
	struct sockaddr_storage_win my_addr, peer_addr;
	struct net_conf *nc;
	int err;
	int sndbuf_size, rcvbuf_size, connect_int;
	KIRQL rcu_flags;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	char sbuf[128] = {0,};
	char dbuf[128] = {0,};

	rcu_flags = rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock(rcu_flags);
		return -EIO;
	}

	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	connect_int = nc->connect_int;
	rcu_read_unlock(rcu_flags);

	my_addr = path->path.my_addr;
	if (my_addr.ss_family == AF_INET6) {
		((struct sockaddr_in6 *)&my_addr)->sin6_port = 0;
	} else {
		((struct sockaddr_in *)&my_addr)->sin_addr.s_addr = INADDR_ANY; 
		((struct sockaddr_in *)&my_addr)->sin_port = 0; /* AF_INET & AF_SCI */
	}

	/* In some cases, the network stack can end up overwriting
	   peer_addr.ss_family, so use a copy here. */
	peer_addr = path->path.peer_addr;

	what = "sock_create_kern";
	err = sock_create_kern(NULL, my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSK_FLAG_CONNECTION_SOCKET, &socket);
	if (err < 0) {
		socket = NULL;
		goto out;
	}
	sprintf(socket->name, "conn_sock\0");

	socket->sk_rcvtimeo =
	socket->sk_sndtimeo = connect_int * HZ;

	dtt_setbufsize(socket, sndbuf_size, rcvbuf_size);

	/* explicitly bind to the configured IP as source IP
	*  for the outgoing connections.
	*  This is needed for multihomed hosts and to be
	*  able to use lo: interfaces for drbd.
	* Make sure to use 0 as port number, so linux selects
	*  a free one dynamically.
	*/
	what = "bind before connect";
	status = Bind(socket->sk, (PSOCKADDR)&my_addr);
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
	err = Connect(socket->sk, (struct sockaddr *) &peer_addr);
	/* missing? EINPROGRESS EINTR ERESTARTSYS ECONNRESET EHOSTDOWN */
	switch (err) {
	case STATUS_SUCCESS:
		err = 0;
		break;
	case STATUS_CONNECTION_REFUSED: 	/* ECONNREFUSED */
	case STATUS_INVALID_DEVICE_STATE:
	case STATUS_NETWORK_UNREACHABLE: 	/* ENETUNREACH */
	case STATUS_HOST_UNREACHABLE: 		/* EHOSTUNREACH */
	case STATUS_TIMEOUT: 			/* ETIMEDOUT */
		err = -EAGAIN;
		break;
	default:
		tr_err(transport, "%s failed, detailed err = 0x%x\n", what, err);
		err = - EINVAL;
		break;
	}

out:
	if (err < 0) {
		if (socket)
			sock_release(socket);
		if (err != -EAGAIN)
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
	struct dtt_path *path = NULL;
	bool rv = false;

	mutex_lock(&tcp_transport->paths_lock);
	list_for_each_entry(struct drbd_path, drbd_path, &transport->paths, list) {
		path = container_of(drbd_path, struct dtt_path, path);
		listener = drbd_path->listener;

		spin_lock_bh(&listener->waiters_lock);
		rv = listener->pending_accepts > 0 || !list_empty(&path->sockets);
		spin_unlock_bh(&listener->waiters_lock);

		if (rv)
			break;
	}
	mutex_unlock(&tcp_transport->paths_lock);

	return rv ? path : NULL;
}

static int dtt_wait_for_connect(struct drbd_transport *drbd_transport,
		struct drbd_listener *drbd_listener,
		struct socket **socket,
		struct dtt_path **ret_path)
{
	KIRQL rcu_flags;
	struct dtt_socket_container *socket_c;
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

	wait_event_interruptible_timeout(timeo, listener->wait,
		(path = dtt_wait_connect_cond(drbd_transport)),
			timeo);
	if (-DRBD_SIGKILL == timeo)
	{
		return -DRBD_SIGKILL;
	}
	if (-ETIMEDOUT == timeo)
		return -EAGAIN;

	spin_lock_bh(&listener->listener.waiters_lock);
	socket_c = list_first_entry_or_null(&path->sockets, struct dtt_socket_container, list);
	if (socket_c) {
		s_estab = socket_c->socket;
		list_del(&socket_c->list);
		kfree(socket_c);
	} else if (listener->listener.pending_accepts > 0) {
		panic("must never happen - who did increase pending_accepts??");
	}
	WDRBD_TRACE_CO("%p dtt_wait_for_connect ok done.\n", KeGetCurrentThread());
	spin_unlock_bh(&listener->listener.waiters_lock);
	*socket = s_estab;
	*ret_path = path;
	return 0;
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
	socket->sk_rcvtimeo = nc->ping_timeo * 4 * HZ / 10;
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

NTSTATUS WSKAPI dtt_incoming_connection (
    _In_  PVOID         SocketContext,
    _In_  ULONG         Flags,
    _In_  PSOCKADDR     LocalAddress,
    _In_  PSOCKADDR     RemoteAddress,
    _In_opt_  PWSK_SOCKET AcceptSocket,
    _Outptr_result_maybenull_ PVOID *AcceptSocketContext,
    _Outptr_result_maybenull_ CONST WSK_CLIENT_CONNECTION_DISPATCH **AcceptSocketDispatch
)
{
	struct dtt_listener *listener = (struct dtt_listener *)SocketContext;
	struct socket *socket = NULL;
	struct dtt_socket_container *socket_c = NULL;
	struct drbd_path *path_d;
	struct dtt_path *path_t;

	/* Already invalid again */
	if (AcceptSocket == NULL)
		goto error;

	socket_c = kmalloc(sizeof(*socket_c), GFP_ATOMIC, 'CTWD');
	if (!socket_c) {
		printk(KERN_ERR "No mem, dropped an incoming connection\n");
		goto error;
	}

	socket = kzalloc(sizeof(*socket), GFP_ATOMIC, 'CTWD');
	if (!socket) {
		printk(KERN_ERR "No mem, dropped an incoming connection\n");
		goto error;
	}

	spin_lock_bh(&listener->listener.waiters_lock);
	/* In Windows the event triggered function (this here) "eats" the new
	 * socket; ie. the socket won't be reported by ->WskAccept() any more.
	 * This means we just store them on the list, and are done. */
	path_d = drbd_find_path_by_addr(&listener->listener,
			(struct sockaddr_storage_win*)RemoteAddress);
	if (!path_d) {
		struct sockaddr *sa = (struct sockaddr*) RemoteAddress;
		struct sockaddr_in6 *from_sin6;

		switch (RemoteAddress->sa_family) {
		case AF_INET6:
/* TODO: print IPv6 address instead of pointer */
			from_sin6 = (struct sockaddr_in6 *)&sa->sa_data[2];
			printk(KERN_WARNING "Closing unexpected connection from "
					"%pI6\n", &from_sin6->sin6_addr);
			break;
		default:
			printk(KERN_WARNING "Closing unexpected connection from "
					"%hhu.%hhu.%hhu.%hhu\n", (unsigned char) sa->sa_data[2], (unsigned char) sa->sa_data[3], (unsigned char) sa->sa_data[4], (unsigned char) sa->sa_data[5]);
			break;
		}

		spin_unlock(&listener->listener.waiters_lock);
		goto error;
	}


	path_t = container_of(path_d, struct dtt_path, path);
	socket->sk = AcceptSocket;
	socket->error_status = STATUS_SUCCESS;

		/* This will be overridden soon (sk_rcvtimeo) or
		 * isn't usable on windows anyway (except for
		 * sending the first packet) (sk_sndtimeo).
		 */

	socket->sk_rcvtimeo =
	socket->sk_sndtimeo = 5000;	/* just something != 0 */

	socket_c->socket = socket;
	list_add_tail(&socket_c->list, &path_t->sockets);
	spin_unlock(&listener->listener.waiters_lock);
	wake_up(&listener->wait);
	return STATUS_SUCCESS;

error:
	kfree(socket);
	kfree(socket_c);

	return STATUS_REQUEST_NOT_ACCEPTED;
}

static void dtt_destroy_listener(struct drbd_listener *generic_listener)
{
	struct dtt_listener *listener =
		container_of(generic_listener, struct dtt_listener, listener);

	sock_release(listener->s_listen);
	kfree(listener);
}

WSK_CLIENT_LISTEN_DISPATCH dispatch = {
	dtt_incoming_connection,
	NULL,
	NULL,
};


static int dtt_init_listener(struct drbd_transport *transport,
			       const struct sockaddr *addr,
			       struct drbd_listener *drbd_listener)
{
	int err, sndbuf_size, rcvbuf_size; 
	struct sockaddr_storage_win my_addr;
	struct dtt_listener *listener = container_of(drbd_listener, struct dtt_listener, listener);
	NTSTATUS status;
	KIRQL rcu_flags;
	struct socket *s_listen;
	struct net_conf *nc;
	const char *what;
	LONG InputBuffer = 1;

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
	err = 0;

	what = "sock_create_kern";
	err = sock_create_kern(NULL, my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, listener, &dispatch, WSK_FLAG_LISTEN_SOCKET, &s_listen);
	if (err) {
		s_listen = NULL;
		goto out;
	}
	sprintf(s_listen->name, "listen_sock\0");

	status = ControlSocket(s_listen->sk, WskSetOption, SO_REUSEADDR, SOL_SOCKET, sizeof(ULONG), &InputBuffer, 0, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		WDRBD_ERROR("ControlSocket: s_listen socket SO_REUSEADDR: failed=0x%x\n", status);
		err = -1;
		goto out;
	}
	dtt_setbufsize(s_listen, sndbuf_size, rcvbuf_size);

	what = "bind before listen";
	status = Bind(s_listen->sk, (PSOCKADDR)&my_addr);

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

	listener->s_listen = s_listen;

	listener->listener.listen_addr = my_addr;
	listener->listener.destroy = dtt_destroy_listener;
	init_waitqueue_head(&listener->wait);

	status = SetEventCallbacks(s_listen->sk, WSK_EVENT_ACCEPT);
	if (!NT_SUCCESS(status)) {
		printk(KERN_ERR "Could not set event accept mask on socket %p\n", s_listen->sk);
		/* TODO: clean up */
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

	return err;
}

static void dtt_cleanup_accepted_sockets(struct dtt_path *path)
{
	while (!list_empty(&path->sockets)) {
		struct dtt_socket_container *socket_c =
			list_first_entry(&path->sockets, struct dtt_socket_container, list);

		list_del(&socket_c->list);
		kernel_sock_shutdown(socket_c->socket, SHUT_RDWR);
		sock_release(socket_c->socket);
		kfree(socket_c);
	}
}

static void dtt_put_listeners(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_path *drbd_path;

	mutex_lock(&tcp_transport->paths_lock);
	clear_bit(DTT_CONNECTING, &tcp_transport->flags);
	mutex_unlock(&tcp_transport->paths_lock);

	for_each_path_ref(drbd_path, transport) {
		struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);

		drbd_put_listener(drbd_path);
		dtt_cleanup_accepted_sockets(path);
	}
}

static struct dtt_path *dtt_next_path(struct drbd_tcp_transport *tcp_transport, struct dtt_path *path)
{
	struct drbd_transport *transport = &tcp_transport->transport;
	struct drbd_path *drbd_path;

	mutex_lock(&tcp_transport->paths_lock);
	if (list_is_last(&path->path.list, &transport->paths))
		drbd_path = list_first_entry(&transport->paths, struct drbd_path, list);
	else
		drbd_path = list_next_entry(struct drbd_path, &path->path, list);
	mutex_unlock(&tcp_transport->paths_lock);

	return container_of(drbd_path, struct dtt_path, path);
}
extern char * get_ip4(char *buf, struct sockaddr_in *sockaddr);
extern char * get_ip6(char *buf, struct sockaddr_in6 *sockaddr);
char* get_ip(char *buf, struct sockaddr_storage_win *addr) {
	if (addr->ss_family == AF_INET6)
		get_ip6(buf, (struct sockaddr_in6*)addr);
	else
		get_ip4(buf, (struct sockaddr_in*)addr);
	return buf;
}

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
	LONG InputBuffer = 1;
	ok = FALSE;
	dsocket = NULL;
	csocket = NULL;

	waiter.transport = transport;

	for_each_path_ref(drbd_path, transport) {
		struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);

		dtt_cleanup_accepted_sockets(path);
	}

	mutex_lock(&tcp_transport->paths_lock);
	set_bit(DTT_CONNECTING, &tcp_transport->flags);

	err = -EDESTADDRREQ;
	if (list_empty(&transport->paths)) {
		mutex_unlock(&tcp_transport->paths_lock);
		goto out;
	}

	list_for_each_entry(struct drbd_path, drbd_path, &transport->paths, list) {
		struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);
		WDRBD_TRACE("dtt_connect: dtt_connect: path: %s -> %s.\n", 
				get_ip(sbuf, &path->path.my_addr),
				get_ip(dbuf, &path->path.peer_addr));
		if (!drbd_path->listener) {
			kref_get(&drbd_path->kref);
			mutex_unlock(&tcp_transport->paths_lock);
			err = drbd_get_listener(transport, drbd_path, dtt_init_listener);
			kref_put(&drbd_path->kref, drbd_destroy_path);
			if (err)
				goto out;
			mutex_lock(&tcp_transport->paths_lock);
			drbd_path = list_first_entry_or_null(&transport->paths, struct drbd_path, list);
			if (drbd_path)
				continue;
			else
				break;
		}
	}

	drbd_path = list_first_entry(&transport->paths, struct drbd_path, list);
	WDRBD_TRACE("dtt_connect: drbd_path: %s -> %s \n",
			get_ip(sbuf, &drbd_path->my_addr),
			get_ip(dbuf, &drbd_path->peer_addr));


	connect_to_path = container_of(drbd_path, struct dtt_path, path);
	mutex_unlock(&tcp_transport->paths_lock);
	WDRBD_TRACE("dtt_connect: connect_to_path: %s -> %s \n",
			get_ip(sbuf, &connect_to_path->path.my_addr),
			get_ip(dbuf, &connect_to_path->path.peer_addr));

//	connect_and_send((struct sockaddr_in*) &connect_to_path->path.peer_addr);

	do {
		struct socket *s = NULL;

/* TODO: needed? */
// schedule_timeout_interruptible(0.4*HZ);
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

			if (!dsocket && !csocket) {
				use_for_data = dtt_path_cmp_addr(first_path);
			} else if (!dsocket) {
				use_for_data = true;
			} else {
				if (csocket) {
					tr_err(transport, "Logic error in conn_connect()\n");
					goto out_eagain;
				}
				use_for_data = false;
			}

			if (use_for_data) {
				dsocket = s;
				sprintf(dsocket->name, "data_sock\0");
				dtt_send_first_packet(tcp_transport, dsocket, P_INITIAL_DATA, DATA_STREAM);
			} else {
				clear_bit(RESOLVE_CONFLICTS, &transport->flags);
				csocket = s;
				sprintf(csocket->name, "meta_sock\0");
				dtt_send_first_packet(tcp_transport, csocket, P_INITIAL_META, CONTROL_STREAM);
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
			WDRBD_TRACE("dtt_connect:(%p) Accepted:  %s <- %s\n", KeGetCurrentThread(),
					get_ip(sbuf, &connect_to_path->path.my_addr),
					get_ip(dbuf, &connect_to_path->path.peer_addr));
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

	dsocket->sk_sndtimeo = timeout;
	csocket->sk_sndtimeo = timeout;

	return 0;

out_eagain:
	err = -EAGAIN;

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

	socket->sk_rcvtimeo = timeout;
}

static long dtt_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];

	return socket->sk_rcvtimeo;
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

		sent = SendPage(socket, page, offset, len, 0);
		if (sent <= 0) {
			if (sent == -EAGAIN) {
				if (drbd_stream_send_timed_out(transport, stream))
					break;
				continue;
			}
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
	bool active;

	drbd_path->established = false;
	INIT_LIST_HEAD(&path->sockets);

retry:
	active = test_bit(DTT_CONNECTING, &tcp_transport->flags);
	if (!active && drbd_path->listener)
		drbd_put_listener(drbd_path);

	if (active && !drbd_path->listener) {
		int err = drbd_get_listener(transport, drbd_path, dtt_init_listener);
		if (err)
			return err;
	}

	mutex_lock(&tcp_transport->paths_lock);
	if (active != test_bit(DTT_CONNECTING, &tcp_transport->flags)) {
		mutex_unlock(&tcp_transport->paths_lock);
		goto retry;
	}
	list_add(&drbd_path->list, &transport->paths);
	mutex_unlock(&tcp_transport->paths_lock);

	return 0;
}

static int dtt_remove_path(struct drbd_transport *transport, struct drbd_path *drbd_path)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);

	if (drbd_path->established)
		return -EBUSY;

	mutex_lock(&tcp_transport->paths_lock);
	list_del_init(&drbd_path->list);
	mutex_unlock(&tcp_transport->paths_lock);
	drbd_put_listener(&path->path);

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

static void dtt_update_congested(struct drbd_tcp_transport *tcp_transport)
{
	/* TODO: implement */
}

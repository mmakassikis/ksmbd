// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/freezer.h>

#include "smb_common.h"
#include "server.h"
#include "auth.h"
#include "buffer_pool.h"
#include "connection.h"
#include "transport_tcp.h"

struct interface {
	struct task_struct	*ksmbd_kthread;
	struct socket		*ksmbd_socket;
	struct list_head	entry;
	char			*name;
	struct mutex		sock_release_lock;
};

static LIST_HEAD(iface_list);

struct tcp_transport {
	struct ksmbd_transport		transport;
	struct socket			*sock;
	struct kvec			*iov;
	unsigned int			nr_iov;
};

static struct ksmbd_transport_ops ksmbd_tcp_transport_ops;

#define KSMBD_TRANS(t)	(&(t)->transport)
#define TCP_TRANS(t)	((struct tcp_transport *)container_of(t, \
				struct tcp_transport, transport))

static inline void ksmbd_tcp_nodelay(struct socket *sock)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
	int val = 1;

	kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY,
		(char *)&val, sizeof(val));
#else
	tcp_sock_set_nodelay(sock->sk);
#endif
}

static inline void ksmbd_tcp_reuseaddr(struct socket *sock)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
	int val = 1;

	kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		(char *)&val, sizeof(val));
#else
	sock_set_reuseaddr(sock->sk);
#endif
}

static inline void ksmbd_tcp_rcv_timeout(struct socket *sock, s64 secs)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 18, 0)
	struct timeval tv = { .tv_sec = secs, .tv_usec = 0 };
#else
	struct __kernel_old_timeval tv = { .tv_sec = secs, .tv_usec = 0 };
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	kernel_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO_OLD, (char *)&tv,
			  sizeof(tv));
#else
	kernel_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,
			  sizeof(tv));
#endif
#else
	lock_sock(sock->sk);
	if (secs && secs < MAX_SCHEDULE_TIMEOUT / HZ - 1)
		sock->sk->sk_rcvtimeo = secs * HZ;
	else
		sock->sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;
	release_sock(sock->sk);
#endif
}

static inline void ksmbd_tcp_snd_timeout(struct socket *sock, s64 secs)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 18, 0)
	struct timeval tv = { .tv_sec = secs, .tv_usec = 0 };
#else
	struct __kernel_old_timeval tv = { .tv_sec = secs, .tv_usec = 0 };
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO_OLD, (char *)&tv,
			  sizeof(tv));
#else
	kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv,
			  sizeof(tv));
#endif
#else
	sock_set_sndtimeo(sock->sk, secs);
#endif
}

static struct tcp_transport *alloc_transport(struct socket *client_sk)
{
	struct tcp_transport *t;
	struct ksmbd_conn *conn;

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return NULL;
	t->sock = client_sk;

	conn = ksmbd_conn_alloc();
	if (!conn) {
		kfree(t);
		return NULL;
	}

	conn->transport = KSMBD_TRANS(t);
	KSMBD_TRANS(t)->conn = conn;
	KSMBD_TRANS(t)->ops = &ksmbd_tcp_transport_ops;
	return t;
}

static void free_transport(struct tcp_transport *t)
{
	kernel_sock_shutdown(t->sock, SHUT_RDWR);
	sock_release(t->sock);
	t->sock = NULL;

	ksmbd_conn_free(KSMBD_TRANS(t)->conn);
	kfree(t->iov);
	kfree(t);
}

/**
 * kvec_array_init() - initialize a IO vector segment
 * @new:	IO vector to be initialized
 * @iov:	base IO vector
 * @nr_segs:	number of segments in base iov
 * @bytes:	total iovec length so far for read
 *
 * Return:	Number of IO segments
 */
static unsigned int kvec_array_init(struct kvec *new, struct kvec *iov,
				    unsigned int nr_segs, size_t bytes)
{
	size_t base = 0;

	while (bytes || !iov->iov_len) {
		int copy = min(bytes, iov->iov_len);

		bytes -= copy;
		base += copy;
		if (iov->iov_len == base) {
			iov++;
			nr_segs--;
			base = 0;
		}
	}

	memcpy(new, iov, sizeof(*iov) * nr_segs);
	new->iov_base += base;
	new->iov_len -= base;
	return nr_segs;
}

/**
 * get_conn_iovec() - get connection iovec for reading from socket
 * @t:		TCP transport instance
 * @nr_segs:	number of segments in iov
 *
 * Return:	return existing or newly allocate iovec
 */
static struct kvec *get_conn_iovec(struct tcp_transport *t,
				     unsigned int nr_segs)
{
	struct kvec *new_iov;

	if (t->iov && nr_segs <= t->nr_iov)
		return t->iov;

	/* not big enough -- allocate a new one and release the old */
	new_iov = kmalloc_array(nr_segs, sizeof(*new_iov), GFP_KERNEL);
	if (new_iov) {
		kfree(t->iov);
		t->iov = new_iov;
		t->nr_iov = nr_segs;
	}
	return new_iov;
}

static unsigned short ksmbd_tcp_get_port(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return ntohs(((struct sockaddr_in *)sa)->sin_port);
	case AF_INET6:
		return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
	}
	return 0;
}

/**
 * ksmbd_tcp_new_connection() - create a new tcp session on mount
 * @sock:	socket associated with new connection
 *
 * whenever a new connection is requested, create a conn thread
 * (session thread) to handle new incoming smb requests from the connection
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_tcp_new_connection(struct socket *client_sk)
{
	struct sockaddr *csin;
	int rc = 0;
	struct tcp_transport *t;

	t = alloc_transport(client_sk);
	if (!t)
		return -ENOMEM;

	csin = KSMBD_TCP_PEER_SOCKADDR(KSMBD_TRANS(t)->conn);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 16, 0)
	if (kernel_getpeername(client_sk, csin, &rc) < 0) {
		ksmbd_err("client ip resolution failed\n");
		rc = -EINVAL;
		goto out_error;
	}
	rc = 0;
#else
	if (kernel_getpeername(client_sk, csin) < 0) {
		ksmbd_err("client ip resolution failed\n");
		rc = -EINVAL;
		goto out_error;
	}
#endif
	KSMBD_TRANS(t)->handler = kthread_run(ksmbd_conn_handler_loop,
					KSMBD_TRANS(t)->conn,
					"ksmbd:%u", ksmbd_tcp_get_port(csin));
	if (IS_ERR(KSMBD_TRANS(t)->handler)) {
		ksmbd_err("cannot start conn thread\n");
		rc = PTR_ERR(KSMBD_TRANS(t)->handler);
		free_transport(t);
	}
	return rc;

out_error:
	free_transport(t);
	return rc;
}

/**
 * ksmbd_tcp_readv() - read data from socket in given iovec
 * @t:		TCP transport instance
 * @iov_orig:	base IO vector
 * @nr_segs:	number of segments in base iov
 * @to_read:	number of bytes to read from socket
 *
 * Return:	on success return number of bytes read from socket,
 *		otherwise return error number
 */
static int ksmbd_tcp_readv(struct tcp_transport *t,
			   struct kvec *iov_orig,
			   unsigned int nr_segs,
			   unsigned int to_read)
{
	int length = 0;
	int total_read;
	unsigned int segs;
	struct msghdr ksmbd_msg;
	struct kvec *iov;
	struct ksmbd_conn *conn = KSMBD_TRANS(t)->conn;

	iov = get_conn_iovec(t, nr_segs);
	if (!iov)
		return -ENOMEM;

	ksmbd_msg.msg_control = NULL;
	ksmbd_msg.msg_controllen = 0;

	for (total_read = 0; to_read; total_read += length, to_read -= length) {
		try_to_freeze();

		if (!ksmbd_conn_alive(conn)) {
			total_read = -ESHUTDOWN;
			break;
		}
		segs = kvec_array_init(iov, iov_orig, nr_segs, total_read);

		length = kernel_recvmsg(t->sock, &ksmbd_msg,
					iov, segs, to_read, 0);

		if (length == -EINTR) {
			total_read = -ESHUTDOWN;
			break;
		} else if (conn->status == KSMBD_SESS_NEED_RECONNECT) {
			total_read = -EAGAIN;
			break;
		} else if (length == -ERESTARTSYS || length == -EAGAIN) {
			usleep_range(1000, 2000);
			length = 0;
			continue;
		} else if (length <= 0) {
			total_read = -EAGAIN;
			break;
		}
	}
	return total_read;
}

/**
 * ksmbd_tcp_read() - read data from socket in given buffer
 * @t:		TCP transport instance
 * @buf:	buffer to store read data from socket
 * @to_read:	number of bytes to read from socket
 *
 * Return:	on success return number of bytes read from socket,
 *		otherwise return error number
 */
static int ksmbd_tcp_read(struct ksmbd_transport *t,
		   char *buf,
		   unsigned int to_read)
{
	struct kvec iov;

	iov.iov_base = buf;
	iov.iov_len = to_read;

	return ksmbd_tcp_readv(TCP_TRANS(t), &iov, 1, to_read);
}

static int ksmbd_tcp_writev(struct ksmbd_transport *t,
			struct kvec *iov, int nvecs, int size,
			bool need_invalidate, unsigned int remote_key)

{
	struct msghdr smb_msg = {.msg_flags = MSG_NOSIGNAL};

	return kernel_sendmsg(TCP_TRANS(t)->sock, &smb_msg, iov, nvecs, size);
}

static void ksmbd_tcp_disconnect(struct ksmbd_transport *t)
{
	free_transport(TCP_TRANS(t));
}

static struct ksmbd_transport_ops ksmbd_tcp_transport_ops = {
	.read		= ksmbd_tcp_read,
	.writev		= ksmbd_tcp_writev,
	.disconnect	= ksmbd_tcp_disconnect,
};

/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __KSMBD_TRANSPORT_TCP_H__
#define __KSMBD_TRANSPORT_TCP_H__

struct socket;

int ksmbd_tcp_new_connection(struct socket *sock);

#endif /* __KSMBD_TRANSPORT_TCP_H__ */

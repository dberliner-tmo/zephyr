/*
 * Copyright (c) 2021 t-mobile.com
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <kernel.h>
#include <net/net_ip.h>
#include <net/socket.h>

#define MAX_MODEM_SOCKS		5

//enum {
//	CONN_FLG = 1,
//	ACT_FLG
//};
//
//struct tmo_socket {
//	sa_family_t family;
//	enum net_sock_type type;
//	int ip_proto;
//	struct sockaddr src;
//	struct sockaddr dst;
//	int id;
//	int sock_fd;
//
//	/** socket state */
//	bool is_connected;
//};
//
//
//struct tmo_shell_user_data {
//	const struct shell *shell;
//	struct tmo_socket socks[MAX_MODEM_SOCKS];
//	int tot_sock;	//active socks
//
//	void *user_data;
//};

#define MAX_SOCK_REC	16
#define XFER_SIZE		1500

enum sock_rec_flags {
    sock_open = 0,
    sock_udp,
    sock_tcp,
    sock_connected,
    sock_bound
};


struct sock_rec_s {
    int sd;
    uint8_t flags;
    struct net_if *dev;
};

static inline void gen_payload(uint8_t *buf, int len)
{
    for (int i=0;i<len;i++)
        buf[i] = 0x20 + (i % 97);
}

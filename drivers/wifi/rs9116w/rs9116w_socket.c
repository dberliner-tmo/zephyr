/*
 * Copyright (c) 2021 T-Mobile USA, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_MODULE_NAME wifi_rs9116w_offload
#define LOG_LEVEL CONFIG_WIFI_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

#include <net/net_ip.h>
#include <net/net_context.h>
#include <net/net_offload.h>
#include <net/net_pkt.h>

#include "rs9116w.h"

#include <rsi_wlan_apis.h>
#include "rsi_wlan.h"

static int rs9116w_dummy_get(sa_family_t family,
				enum net_sock_type type,
				enum net_ip_protocol ip_proto,
				struct net_context **context)
{

	LOG_ERR("NET_SOCKETS_OFFLOAD must be configured for this driver");

	return -1;
}

static struct net_offload rs9116w_offload = {
    .get      = rs9116w_dummy_get,
    .bind     = NULL,
    .connect  = NULL,
    .send     = NULL,
    .sendto   = NULL,
    .recv     = NULL,
    .put      = NULL
};

int rs9116w_offload_init(struct rs9116w_device *rs9116w)
{
    rs9116w->net_iface->if_dev->offload = &rs9116w_offload;

    // TBD: What else goes here?

#if defined(CONFIG_NET_SOCKETS_OFFLOAD)
    rs9116w->net_iface->if_dev->socket_offload = rs9116w_socket_create;
    rs9116w_socket_offload_init();
#endif

    return 0;
}

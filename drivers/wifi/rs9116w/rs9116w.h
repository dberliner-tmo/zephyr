/*
 * Copyright (c) 2022 T-Mobile USA, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_WIFI_RS9116W_RS9116W_H_
#define ZEPHYR_DRIVERS_WIFI_RS9116W_RS9116W_H_

#include <device.h>
#include <drivers/spi.h>
#include <net/wifi_mgmt.h>
#include <net/net_if.h>

#include <net/net_if.h>

#include "rsi_wlan_apis.h"
#include "rsi_socket.h"

// NOTE: Zephyr defines AF_INET as 1 and AF_INET6 as 2
#define RS_AF_INET  2
#define RS_AF_INET6 3

// TBD: Following line is defined in rsi_wlan_apis.h, but isn't defined here
// SO THERE ARE LIKELY ADDITIONAL #defines THAT NEED TO BE SET!
#define MAX_PER_PACKET_SIZE         1500

struct rs9116w_socket {
    int sock_id;                               /* socket ID, 0-9 */
    uint8_t pkt_data_out[MAX_PER_PACKET_SIZE]; /* single outbound packet data */
    int32_t pkt_size_out;                      /* outbound packet size */
    uint8_t pkt_data_in [MAX_PER_PACKET_SIZE]; /* single inbound packet data */
    int32_t pkt_size_in;                       /* inbound packet size */
    uint8_t local_bound;                       /* non-0 if rsi_bind has been called for local port */
    uint16_t port;                             /* port number that has been bound */
    /* TBD: what else goes here?
     */
};

struct rs9116w_device {
    uint8_t iface_idx;        /* iface index of this device, ie 0 for 1st instance, 1 for 2nd, ... */
    struct net_if *net_iface; /* ptr to the net_iface */
    struct rs9116w_socket sockets[BSD_MAX_SOCKETS];     /* array of sockets */
    struct device *spi_data;
    struct spi_dt_spec spi;
    uint8_t fw_version[20];
    char mac[6];
    /* TBD what else goes here?
     * winc1500 has iface, mac, scan results, and connecting / connected flags
     */
    rsi_rsp_scan_t scan_results;
};

struct rs9116w_device *rs9116w_by_iface_idx(uint8_t iface);

static inline
struct rs9116w_device *rs9116w_socket_to_dev(struct rs9116w_socket *socket) {
    return CONTAINER_OF(socket - socket->sock_id, struct rs9116w_device, sockets);
}

int rs9116w_offload_init(struct rs9116w_device *rs9116w);

#if defined(CONFIG_NET_SOCKETS_OFFLOAD)
int rs9116w_socket_offload_init();
int rs9116w_socket_create(int family, int type, int proto);
#endif
#endif

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

/* Undef macros before redefining to eliminate warnings */
#undef AF_INET
#undef AF_INET6
#undef AF_UNSPEC
#undef PF_INET
#undef PF_INET6
#undef TCP_NODELAY
#include <rsi_wlan_apis.h>
#include <rsi_socket.h>

// NOTE: Zephyr defines AF_INET as 1 and AF_INET6 as 2
#define RS_AF_INET  2
#define RS_AF_INET6 3

// TBD: Following line is defined in rsi_wlan_apis.h, but isn't defined here
// SO THERE ARE LIKELY ADDITIONAL #defines THAT NEED TO BE SET!
#define MAX_PER_PACKET_SIZE         1500
struct rs9116w_device {
    struct net_if *net_iface; /* ptr to the net_iface */
    // struct device *spi_data;
    struct spi_dt_spec spi;
    uint8_t fw_version[20];
    char mac[6];
    /* TBD what else goes here?
     * winc1500 has iface, mac, scan results, and connecting / connected flags
     */
    rsi_rsp_scan_t scan_results;
};

struct rs9116w_device *rs9116w_by_iface_idx(uint8_t iface);

int rs9116w_offload_init(struct rs9116w_device *rs9116w);

#if defined(CONFIG_NET_SOCKETS_OFFLOAD)
int rs9116w_socket_offload_init();
int rs9116w_socket_create(int family, int type, int proto);
#endif
#endif

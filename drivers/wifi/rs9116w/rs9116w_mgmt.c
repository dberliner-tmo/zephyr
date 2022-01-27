/*
 * Copyright (c) 2022 T-Mobile USA, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#define LOG_MODULE_NAME wifi_rs9116w_mgmt
#define LOG_LEVEL CONFIG_WIFI_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

#define DT_DRV_COMPAT silabs_rs9116w
#include <zephyr.h>
#include <kernel.h>
#include <debug/stack.h>
#include <device.h>
#include <errno.h>
#include <net/net_pkt.h>
#include <net/net_if.h>
#include <net/net_l2.h>
#include <net/net_context.h>
#include <net/net_offload.h>
#include <net/wifi_mgmt.h>

#include "rs9116w.h"

#include "rsi_common_apis.h"
#include "rsi_wlan_apis.h"
#include "rsi_bootup_config.h"
#include "rsi_wlan.h"
#include "rsi_wlan_apis.h"


#define RSI_OPERMODE_WLAN_BLE 13

#define RS9116W_MAX_IFACES 1

static struct rs9116w_device s_rs9116w_dev[RS9116W_MAX_IFACES] = {0};


// rsi_wlan_get_state() is not defined in WiseConnect, so define it here
uint8_t rsi_wlan_get_state(void);

struct rs9116w_config {
    struct spi_dt_spec spi;
};

static struct rs9116w_config rs9116w_conf = {
    .spi = SPI_DT_SPEC_INST_GET(0, SPI_OP_MODE_MASTER | SPI_WORD_SET(8), 2)
};

// TBD: Make GLOBAL_BUFF_LEN a config param
#define GLOBAL_BUFF_LEN 15000
uint8_t global_buf[GLOBAL_BUFF_LEN];

struct rs9116w_device *rs9116w_by_iface_idx(uint8_t iface_idx) {

    return &s_rs9116w_dev[0];

    /* TBD Need to use the index, but input param isn't correct yet
    if (iface_idx > RS9116W_MAX_IFACES)
        return NULL;

    return &s_rs9116w_dev[iface_idx];
    */
}

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? a : b)
#endif

// mgmt functions

/****************************************************************************/
static int rs9116w_mgmt_scan(const struct device *dev, scan_result_cb_t cb)
{
    int ret;
    struct rs9116w_device *rs9116w_dev = dev->data;

    /*
     * 9.1.1 int32_t rsi_wlan_scan(uint8_t *ssid, uint8_t chno, rsi_rsp_scan_t *result,uint32_t length)
     */
    printk("Got to rs9116w_mgmt_scan\n");
    ret = rsi_wlan_scan(NULL, 0, &(rs9116w_dev->scan_results), sizeof(rsi_rsp_scan_t));
    if (ret != 0)
        return ret;

    printk("rsi_wlan_scan returned %d APs\n", rs9116w_dev->scan_results.scan_count[0]);

    for (int i=0;i<rs9116w_dev->scan_results.scan_count[0];i++) {

        rsi_scan_info_t *r_result = &rs9116w_dev->scan_results.scan_info[i];
        struct wifi_scan_result z_result;

        // convert index i to result
        //
        // SSID
        // RSI:    #define RSI_SSID_LEN 34
        // ZEPHYR: #define WIFI_SSID_MAX_LEN 32
        memcpy(z_result.ssid, r_result->ssid, MIN(RSI_SSID_LEN, WIFI_SSID_MAX_LEN));
        z_result.ssid[MIN(RSI_SSID_LEN, WIFI_SSID_MAX_LEN) - 1] = '\0';

        // SSID length
        z_result.ssid_length = strlen(z_result.ssid);

        // channel
        z_result.channel = r_result->rf_channel;

        // security
        // typedef enum rsi_security_mode_e {
        // // open mode
        // RSI_OPEN = 0,
        // // WPA security with PSK
        // RSI_WPA,
        // // WPA2 security with PSK
        // RSI_WPA2,
        // // WEP security
        // RSI_WEP,
        // // Enterprise WPA security
        // RSI_WPA_EAP,
        // // Enterprise WPA2 security
        // RSI_WPA2_EAP,
        // // Enterprise WPA2/WPA security
        // RSI_WPA_WPA2_MIXED,
        // // WPA security with PMK
        // RSI_WPA_PMK,
        // // WPA2 security with PMK
        // RSI_WPA2_PMK,
        // // WPS pin method
        // RSI_WPS_PIN,
        // // WPS generated pin method
        // RSI_USE_GENERATED_WPSPIN,
        // // WPS push button method
        // RSI_WPS_PUSH_BUTTON,
        //
        // } rsi_security_mode_t;
        //
        if (r_result->security_mode == RSI_OPEN) {
            z_result.security = WIFI_SECURITY_TYPE_NONE;
        } else if (r_result->security_mode == RSI_WPA2) {
            z_result.security = WIFI_SECURITY_TYPE_PSK;
        } else {
            printk("SSID: %s with security %u not supported",
                    z_result.ssid, r_result->security_mode);
            LOG_DBG("SSID: %s with security %u not supported",
                    z_result.ssid, r_result->security_mode);
            continue;
        }

        // rssi
        z_result.rssi = r_result->rssi_val;

        // Inform Zephyr about the AP
        cb(rs9116w_dev->net_iface, 0, &z_result);
    }
    // Inform Zephyr there are no more APs, should generate a SCAN COMPLETE message
    cb(rs9116w_dev->net_iface, 0, NULL);

    return ret;
}
#define Z_PF_INET         1          /**< IP protocol family version 4. */
#define Z_PF_INET6        2          /**< IP protocol family version 6. */
#define Z_AF_INET        Z_PF_INET     /**< IP protocol family version 4. */
#define Z_AF_INET6       Z_PF_INET6    /**< IP protocol family version 6. */

/****************************************************************************/
static int rs9116w_mgmt_connect(const struct device *dev, struct wifi_connect_req_params *params)
{
    // RSI security modes:
    // 0: RSI_OPEN,
    // 1: RSI_WPA,
    // 2: RSI_WPA2,
    // 3: RSI_WEP,
    // 4: RSI_WPA_EAP,
    // 5: RSI_WPA2_EAP,
    // 6: RSI_WPA_WPA2_MIXED,
    // 7: RSI_WPA_PMK,
    // 8: RSI_WPA2_PMK,
    // 9: RSI_WPS_PIN,
    // 10: RSI_USE_GENERATED_WPSPIN,
    // 11: RSI_WPS_PUSH_BUTTON
    //
    // Zephyr security modes
    // 0: WIFI_SECURITY_TYPE_NONE,
    // 1: WIFI_SECURITY_TYPE_PSK,

    struct rs9116w_device *rs9116w_dev = dev->data;
    rsi_security_mode_t rsi_security;
    void *rsi_psk;
    int ret;

    // Check if already connected?

    // Connect to an access point
    if (params->security == WIFI_SECURITY_TYPE_NONE) {
        rsi_security = RSI_OPEN;
        rsi_psk = NULL;
    }
    else if (params->security == WIFI_SECURITY_TYPE_PSK) {
        rsi_security = RSI_WPA2;
        rsi_psk = params->psk;
    }
    else {
        return -EINVAL;
    }

    /*
     * 9.1.5 int32_t rsi_wlan_connect(int8_t *ssid, rsi_security_mode_t sec_type, void *secret_key)
     */
    ret = rsi_wlan_connect(params->ssid, rsi_security, rsi_psk);

    wifi_mgmt_raise_connect_result_event(rs9116w_dev->net_iface, ret);

    if (ret) {
        return ret;
    }
#if IS_ENABLED(CONFIG_NET_IPV4)
    struct in_addr addr;
    uint8_t ipv4_mode = RSI_DHCP;
    uint8_t *ipv4_addr = NULL, *ipv4_mask = NULL, *ipv4_gw = NULL;
#if defined(CONFIG_NET_CONFIG_MY_IPV4_ADDR)
    uint32_t ipv4_addr_d = 0, ipv4_mask_d = 0, ipv4_gw_d = 0;
    if (strcmp(CONFIG_NET_CONFIG_MY_IPV4_ADDR, "") != 0) {
        ipv4_mode = RSI_STATIC;
        if (net_addr_pton(Z_AF_INET, CONFIG_NET_CONFIG_MY_IPV4_ADDR, &addr)
                < 0) {
            LOG_ERR("Invalid CONFIG_NET_CONFIG_MY_IPV4_ADDR");
            return -1;
        }
        ipv4_addr_d = addr.s_addr;
        ipv4_addr = (uint8_t*)&ipv4_addr_d;
	}

#if defined(CONFIG_NET_CONFIG_MY_IPV4_GW)
    if (strcmp(CONFIG_NET_CONFIG_MY_IPV4_GW, "") != 0) {
		if (net_addr_pton(Z_AF_INET, CONFIG_NET_CONFIG_MY_IPV4_GW,
				  &addr) < 0) {
			LOG_ERR("Invalid CONFIG_NET_CONFIG_MY_IPV4_GW");
			return -1;
		}
		ipv4_gw_d = addr.s_addr;
        ipv4_gw = (uint8_t*)&ipv4_gw_d;
	}
#endif

#if defined(CONFIG_NET_CONFIG_MY_IPV4_NETMASK)
	if (strcmp(CONFIG_NET_CONFIG_MY_IPV4_NETMASK, "") != 0) {
		if (net_addr_pton(Z_AF_INET, CONFIG_NET_CONFIG_MY_IPV4_NETMASK,
				  &addr) < 0) {
			LOG_ERR("Invalid CONFIG_NET_CONFIG_MY_IPV4_NETMASK");
			return -1;
		}
		ipv4_mask_d = addr.s_addr;
        ipv4_mask = (uint8_t*)&ipv4_mask_d;
	}
#endif
#endif
    // Configure IPv4 (DHCP)
    rsi_rsp_ipv4_parmas_t rsi_rsp_ipv4_parmas;
    ret = rsi_config_ipaddress(RSI_IP_VERSION_4, ipv4_mode, ipv4_addr, ipv4_mask, ipv4_gw, (uint8_t *) &rsi_rsp_ipv4_parmas, sizeof(rsi_rsp_ipv4_parmas), 0);
    if (ret != 0)
    {
        LOG_ERR("rsi_config_ipaddress error: %d", ret);
        return ret;
    }


    memcpy(addr.s4_addr, rsi_rsp_ipv4_parmas.gateway, 4);
#if IS_ENABLED(CONFIG_NET_NATIVE_IPV4)
    net_if_ipv4_set_gw(rs9116w_dev->net_iface, &addr);
#endif

    memcpy(addr.s4_addr, rsi_rsp_ipv4_parmas.netmask, 4);
#if IS_ENABLED(CONFIG_NET_NATIVE_IPV4)
    net_if_ipv4_set_netmask(rs9116w_dev->net_iface, &addr);
#endif
    memcpy(addr.s4_addr, rsi_rsp_ipv4_parmas.ipaddr, 4);

    LOG_DBG("ip = %d.%d.%d.%d", addr.s4_addr[0], addr.s4_addr[1],
            addr.s4_addr[2], addr.s4_addr[3]);

    // net_if_ipv4_addr_rm()?
#if IS_ENABLED(CONFIG_NET_NATIVE_IPV4)
    net_if_ipv4_addr_add(rs9116w_dev->net_iface, &addr, NET_ADDR_DHCP, 0);
#endif
#endif
#if IS_ENABLED(CONFIG_NET_IPV6)
#undef s6_addr
    struct in6_addr addr6;
    uint8_t ipv6_mode = RSI_DHCP;
    uint8_t *ipv6_addr = NULL;
#if defined(CONFIG_NET_CONFIG_MY_IPV6_ADDR)
    ipv6_mode = RSI_STATIC;
    if (net_addr_pton(Z_AF_INET6, CONFIG_NET_CONFIG_MY_IPV6_ADDR,
				  &addr6) < 0) {
			LOG_ERR("Invalid CONFIG_NET_CONFIG_MY_IPV6_ADDR");
			return -1;
    }
    ipv6_addr = addr6.s6_addr;
#endif
    rsi_rsp_ipv6_parmas_t rsi_rsp_ipv6_parmas;
    ret = rsi_config_ipaddress(RSI_IP_VERSION_6, ipv6_mode, ipv6_addr, NULL, NULL, (uint8_t *) &rsi_rsp_ipv6_parmas, sizeof(rsi_rsp_ipv6_parmas), 0);
    if (ret != 0)
    {
        LOG_ERR("rsi_config_ipaddress error: %x", ret);
        return ret;
    }

    memcpy(addr6.s6_addr, rsi_rsp_ipv6_parmas.ipaddr6, 16);
    // net_if_ipv6_prefix_add(rs9116w_dev->net_iface, &addr6, rsi_rsp_ipv6_parmas.prefixLength, 0);

    LOG_DBG("ip6 = %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
            sys_be16_to_cpu(addr6.s6_addr16[0]), sys_be16_to_cpu(addr6.s6_addr16[1]),
            sys_be16_to_cpu(addr6.s6_addr16[2]), sys_be16_to_cpu(addr6.s6_addr16[3]),
            sys_be16_to_cpu(addr6.s6_addr16[4]), sys_be16_to_cpu(addr6.s6_addr16[5]),
            sys_be16_to_cpu(addr6.s6_addr16[6]), sys_be16_to_cpu(addr6.s6_addr16[7])
    );
#if IS_ENABLED(CONFIG_NET_NATIVE_IPV6)
    net_if_ipv6_addr_add(rs9116w_dev->net_iface, &addr6, NET_ADDR_DHCP, 0);
#endif

#endif

    LOG_DBG("Connected!");

    net_if_up(rs9116w_dev->net_iface);

    return ret;
}

/****************************************************************************/
static int rs9116w_mgmt_disconnect(const struct device *dev)
{
    int ret;

    /*
     * 9.1.9 int32_t rsi_wlan_disconnect(void);
     */
    ret = rsi_wlan_disconnect();
    // net_if_ipv4_addr_rm(dev->net_iface, &dev->ip);
    struct rs9116w_device *rs9116w_dev = dev->data;
    wifi_mgmt_raise_disconnect_result_event(rs9116w_dev->net_iface, ret);

    net_if_down(rs9116w_dev->net_iface);

    return ret;
}

// called after device init fcn
static void rs9116w_iface_init(struct net_if *iface)
{
    s_rs9116w_dev[0].iface_idx = 0;
    s_rs9116w_dev[0].net_iface = iface;

    net_if_set_link_addr(iface, s_rs9116w_dev[0].mac, sizeof(s_rs9116w_dev[0].mac), NET_LINK_ETHERNET);
    net_if_flag_set(iface, NET_IF_NO_AUTO_START);

    // Initialize the offload engine
    rs9116w_offload_init(&s_rs9116w_dev[0]);
}

#if IS_ENABLED(CONFIG_WISECONNECT_USE_OS_BINDINGS)
K_THREAD_STACK_DEFINE(driver_task_stack, 2048);
struct k_thread driver_task;

void driver_task_entry(void* p1, void* p2, void* p3)
{
    rsi_wireless_driver_task();
}
#endif

// offload device init fcn (called before rs9116w_iface_init)
static int rs9116w_init(const struct device *dev)
{
    int32_t status;
    struct rs9116w_device *rs9116w_dev = dev->data;
    uint8_t mac[6];


    // Initialize SPI bus
    //
    // config
    // TBD should these constant values be configuration settings?
    // rs9116w_dev->spi = SPI_DT_SPEC_INST_GET(0, SPI_OP_MODE_MASTER | SPI_WORD_SET(8), 2);
    rs9116w_dev->spi = rs9116w_conf.spi;

    // data
    if(!spi_is_ready(&rs9116w_dev->spi)) {
        LOG_ERR("spi bus %s not ready", rs9116w_dev->spi.bus->name);
        return -ENODEV;
    }

    // Initialize the RSI driver
    /*
     * 8.1 int32_t *rsi_driver_init(uint8_t *buffer, uint32_t length);
     */
    status = rsi_driver_init(global_buf, GLOBAL_BUFF_LEN);
    printk("rs9116w_init: rsi_driver_init returned %d\n", status);

    if (status >= 0 && status <= GLOBAL_BUFF_LEN)
    {
        printk("rs9116w_init: rsi_driver_init using %d of %d bytes\n", status, GLOBAL_BUFF_LEN);
    }
    else if (status > GLOBAL_BUFF_LEN) {
        printk("rs9116w_init: rsi_driver_init error: not enough memory, driver needs %d\n", status);
        return -ENOMEM;
    }
    else if (status < 0)
    {
        printk("rs9116w_init: rsi_driver_init error: %d\n", status);
        return status;
    }


    // Initialize the device
    /*
     * 8.3 int32_t rsi_device_init(uint8_t select_option);
     */
    status = rsi_device_init(LOAD_NWP_FW);

    printk("rs9116w_init: rsi_device_init returned %d\n", status);

#if IS_ENABLED(CONFIG_WISECONNECT_USE_OS_BINDINGS)
    k_thread_create(&driver_task, driver_task_stack,
         K_THREAD_STACK_SIZEOF(driver_task_stack),
         driver_task_entry,
         NULL, NULL, NULL,
         K_PRIO_COOP(8), K_INHERIT_PERMS, K_NO_WAIT
         );
#endif

    // Initialize WiseConnect features (Configure simultaneous WiFi and BLE)
    /*
     * 8.6 int32_t rsi_wireless_init(uint16_t opermode, uint16_t coex_mode);
     */
    if (!status) {
        status = rsi_wireless_init(RSI_WLAN_CLIENT_MODE, RSI_OPERMODE_WLAN_BLE);
        printk("rs9116w_init: rsi_wireless_init returned %d\n", status);
    }

    rsi_wlan_radio_init();

    // Get the MAC (must be after rsi_wlan_radio_init())
    status = rsi_wlan_get(RSI_MAC_ADDRESS, mac, sizeof(mac));
    printk("rsi_wlan_get after rsi_wireless_init returned %d, mac: %02x:%02x:%02x:%02x:%02x:%02x\n", status, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    memcpy(rs9116w_dev->mac, mac, sizeof(mac));

    if (status)
        LOG_DBG("RS9116W WiFi driver failed to initialize, status = %d", status);
    else
        LOG_DBG("RS9116W WiFi driver Initialized");


    // Get the FW version
    status = rsi_get_fw_version(rs9116w_dev->fw_version, sizeof(rs9116w_dev->fw_version));
    if (status != 0)
        printk("rsi_get_fw_version returned %d\n", status);
    else
    {
        printk("FW version: %s\n", rs9116w_dev->fw_version);
    }

    int state = rsi_wlan_get_state();
    printk("state: %d\n", state);
    /*Don't know that this is necessary, but it doesn't hurt*/
    status = rsi_send_feature_frame();

    return status;
}

static const struct net_wifi_mgmt_offload rs9116w_api = {
    .iface_api.init = rs9116w_iface_init, // called after device init fcn
    .scan           = rs9116w_mgmt_scan,
    .connect        = rs9116w_mgmt_connect,
    .disconnect     = rs9116w_mgmt_disconnect,
};

NET_DEVICE_DT_INST_OFFLOAD_DEFINE(
        0,                          // instance number
        rs9116w_init,               // offload device init fcn (called before .iface_api.init)
        NULL,                       // pm_control function?
        &s_rs9116w_dev,             // private data
        &rs9116w_conf,              // config info
        CONFIG_WIFI_INIT_PRIORITY,  // priority
        &rs9116w_api,               // api fcn table
        MAX_PER_PACKET_SIZE);       // MTU


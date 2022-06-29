/*
 * Copyright (c) 2022 T-Mobile USA, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <net/buf.h>

#define GSM_MODEM_DEVICE_NAME "murata 1sc"

#define MDM_UART_DEV_NAME		  DT_INST_BUS_LABEL(0)
#define MDM_CMD_TIMEOUT			  K_SECONDS(5)
#define MDM_REGISTRATION_TIMEOUT	  K_SECONDS(10)
#define MDM_SENDMSG_SLEEP		  K_MSEC(1)
#define MDM_MAX_DATA_LENGTH		  1500
#define MDM_RECV_MAX_BUF		  20
#define MDM_RECV_BUF_SIZE		  1500
#define MDM_BASE_SOCKET_NUM		  0
#define MDM_NETWORK_RETRY_COUNT		  10
#define MDM_INIT_RETRY_COUNT		  10
#define MDM_PDP_ACT_RETRY_COUNT		  3
#define MDM_WAIT_FOR_RSSI_COUNT		  10
#define MDM_WAIT_FOR_RSSI_DELAY		  K_SECONDS(2)
#define BUF_ALLOC_TIMEOUT		  K_SECONDS(1)
#define MDM_MAX_BOOT_TIME		  K_SECONDS(50)

/* Default lengths of certain things. */
#define MDM_MANUFACTURER_LENGTH		  40
#define MDM_MODEL_LENGTH		  16
#define MDM_REVISION_LENGTH		  32
#define MDM_SIM_INFO_LENGTH		  64
#define MDM_IMEI_LENGTH			  16
#define MDM_IMSI_LENGTH			  16
#define MDM_ICCID_LENGTH		  32
#define MDM_APN_LENGTH			  64
#define RSSI_TIMEOUT_SECS		  30
#define MDM_IP_LENGTH                     16
#define MDM_GW_LENGTH                     16
#define MDM_MASK_LENGTH                   16
#define MDM_PHN_LENGTH                    16
#define MDM_CARRIER_LENGTH                16
#define CHKSUM_ABILITY_MAX_LEN            64
#define CMD_FULL_ACCESS_MAX_LEN           64
#define MAX_CARRIER_RESP_SIZE	          64
#define MAX_SIGSTR_RESP_SIZE              32
#define MAX_IP_RESP_SIZE                  256


/**
 * this is for tmo_shell to call for overriding the wifi dns_offload
 */
int murata_socket_offload_init(void);


/* pin settings */
enum mdm_control_pins {
	MDM_WAKE_HOST = 0,
	MDM_WAKE_MDM,
	MDM_RESET,
};

/* Socket read callback data */ //might need to remove pointer to use full implementation of address
struct socket_read_data {
	char		 *recv_buf;
	size_t		 recv_buf_len;
	struct sockaddr	 *recv_addr;
	uint16_t	 recv_read_len;
};

struct init_fw_data_t {
        char *imagename;
        uint32_t imagesize;
        uint32_t imagecrc;
};

struct send_fw_data_t {
	char *data;
	int more;
	size_t len;
};

enum murata_1sc_io_ctl {
	GET_IPV4_CONF = 0x10,
	GET_ATCMD_RESP,
	INIT_FW_XFER,
	SEND_FW_HEADER,
	SEND_FW_DATA,
	INIT_FW_UPGRADE,
	GET_CHKSUM_ABILITY,
	GET_FILE_MODE,
	RESET_MODEM,
};

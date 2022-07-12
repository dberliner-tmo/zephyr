/*
 * Copyright (c) 2022 T-Mobile USA, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT murata_1sc

#include <logging/log.h>
LOG_MODULE_REGISTER(modem_murata_1sc, CONFIG_MODEM_LOG_LEVEL);

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <kernel.h>
#include <device.h>
#include <net/net_offload.h>
#include <net/socket_offload.h>
#include <fcntl.h>
#include "drivers/modem/murata-1sc.h"
#include "modem_context.h"
#include "modem_receiver.h"
#include "modem_iface_uart.h"
#include "modem_socket.h"
#include "modem_cmd_handler.h"
#include "modem_sms.h"
#include "strnstr.h"

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#include <net/tls_credentials.h>
#include <sys/base64.h>
#include "tls_internal.h"
#endif

#define MDM_MAX_SOCKETS CONFIG_MODEM_MURATA_1SC_SOCKET_COUNT

#define MAX_FILENAME_LEN         32
#define MDM_BOOT_DELAY           6      // seconds
#define MDM_WAKE_DELAY           5000    // milliseconds
#define MDM_CMD_RSP_TIME         K_SECONDS(2)
#define MDM_CMD_LONG_RSP_TIME    K_SECONDS(6)

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)

#ifdef CONFIG_USER_CA_DER_ENABLED
static const unsigned char ca_certificate[] = {
#include CONFIG_USER_CA_DER_FILE
};
#endif

#define CERTCMD_WRITE_SIZE 32+MAX_FILENAME_LEN // assume filename maxlen = 32
#define PEM_BUFF_SIZE      6145	               // terminate with \" & 0

/**
 * following struct may not have packed memory if it has something like
 * int follow by char then int,
 * since array of uchar plus array of uchar will be packed
 */
struct cert_cmd_t {
	uint8_t cert_cmd_write[CERTCMD_WRITE_SIZE];
	uint8_t pem_buf[PEM_BUFF_SIZE];
};

static struct cert_cmd_t cert_cmd_buf = {0};

struct hostname_s {
	char host[MAX_FILENAME_LEN + 1];
	bool sni_valid;
} servername_desc[MDM_MAX_SOCKETS] = {{{0}, false}};

char sni_hostname[MAX_FILENAME_LEN+1] = {0};

static int find_valid_sni()
{
	for (int i = 0; i < MDM_MAX_SOCKETS; i++) {
		if (servername_desc[i].sni_valid) {
			return i;
		}
	}
	return -1;
}
#endif

static size_t data_to_hex_str(const void* input_buf, size_t input_len,
                              char* output_buf, size_t output_len)
{
	size_t i;

	for (i = 0; (i < (output_len - 1) / 2) && (i < input_len); i++) {
		snprintk(&output_buf[(i * 2)], output_len, "%02X", ((uint8_t*)input_buf)[i]);
	}

	return i * 2;
}

static uint8_t nibble_to_data(char nibble)
{
	if (nibble >= '0' && nibble <= '9')
		return nibble - '0';
	else if (nibble >= 'A' && nibble <= 'F')
		return nibble - 'A' + 10;
	else if (nibble >= 'a' && nibble <= 'f')
		return nibble - 'a' + 10;

	return 0;
}

static uint8_t hex_byte_to_data(const char *hex_bytes)
{
	return nibble_to_data(*hex_bytes) * 0x10 + nibble_to_data(*(hex_bytes+1));
}

static size_t hex_str_to_data(const char* input_buf, uint8_t* output_buf, size_t output_len)
{
	size_t str_len = strlen(input_buf);
	size_t i = 0;

	for (i = 0; (i < output_len) && (i * 2 < str_len); i++) {
		output_buf[i] = hex_byte_to_data(&input_buf[i * 2]);
	}
	return i;
}

#define ATOI(s_, value_, desc_) murata_1sc_atoi(s_, value_, desc_, __func__)

/* driver data */
struct murata_1sc_data {
	struct net_if *net_iface;
	uint8_t mac_addr[6];

	/* modem interface */
	struct modem_iface_uart_data iface_data;
	uint8_t iface_rb_buf[MDM_MAX_DATA_LENGTH];

	/* modem cmds */
	struct modem_cmd_handler_data cmd_handler_data;
	uint8_t cmd_match_buf[MDM_RECV_BUF_SIZE + 1];

	/* socket data */
	struct modem_socket_config socket_config;
	struct modem_socket sockets[MDM_MAX_SOCKETS];

	/* RSSI work */
	struct k_work_delayable rssi_query_work;

	/* modem data */
	char mdm_manufacturer[MDM_MANUFACTURER_LENGTH];
	char mdm_model[MDM_MODEL_LENGTH];
	char mdm_revision[MDM_REVISION_LENGTH];
	char mdm_sim_info[MDM_SIM_INFO_LENGTH];
	char mdm_imei[MDM_IMEI_LENGTH];
#if defined(CONFIG_MODEM_SIM_NUMBERS)
	char mdm_imsi[MDM_IMSI_LENGTH];
	char mdm_iccid[MDM_ICCID_LENGTH];
#endif /* #if defined(CONFIG_MODEM_SIM_NUMBERS) */
	char mdm_ip[MDM_IP_LENGTH];
	char mdm_gw[MDM_GW_LENGTH];
	char mdm_nmask[MDM_MASK_LENGTH];
	char mdm_phn[MDM_PHN_LENGTH];
	char mdm_carrier[MDM_CARRIER_LENGTH];
	char mdm_apn[MDM_APN_LENGTH];
	bool is_awake;

	/* Socket from which we are currently reading data. */
	int sock_fd;

	/* This buffer is shared by all sockets for rx and tx
	 * Therefore it must be semaphore protected.
	 *
	 * The size is 2x the max data length since binary data
	 * is being translated into byte-wise hex representation,
	 * plus extra for the SOCKETDATA command and params
	 */
	char xlate_buf[MDM_MAX_DATA_LENGTH * 2 + 50];

	/* Semaphores */
	struct k_sem sem_response;
	struct k_sem sem_sock_conn;
	struct k_sem sem_xlate_buf;
	struct k_sem sem_sms;

	/* SMS message support */
	int sms_index;
	struct sms_in *sms;
	recv_sms_func_t recv_sms;
}; 

/* Modem pins - Wake Host, Wake Modem, Reset, and Reset Done */
static const struct gpio_dt_spec wake_host_gpio = GPIO_DT_SPEC_INST_GET(0, mdm_wake_host_gpios);
static const struct gpio_dt_spec wake_mdm_gpio = GPIO_DT_SPEC_INST_GET(0, mdm_wake_mdm_gpios);
static const struct gpio_dt_spec reset_gpio = GPIO_DT_SPEC_INST_GET(0, mdm_reset_gpios);
static const struct gpio_dt_spec rst_done_gpio = GPIO_DT_SPEC_INST_GET(0, mdm_rst_done_gpios);
static const struct gpio_dt_spec mdm_rx_gpio = GPIO_DT_SPEC_INST_GET(0, mdm_rx_gpios);
static const struct gpio_dt_spec mdm_tx_gpio = GPIO_DT_SPEC_INST_GET(0, mdm_tx_gpios);

static struct k_thread	       modem_rx_thread;
static struct murata_1sc_data  mdata;
static struct modem_context    mctx;
static const struct socket_op_vtable offload_socket_fd_op_vtable;

static void socket_close(struct modem_socket *sock);

/* RX thread structures */
static K_KERNEL_STACK_DEFINE(modem_rx_stack, CONFIG_MODEM_MURATA_1SC_RX_STACK_SIZE);
NET_BUF_POOL_DEFINE(mdm_recv_pool, MDM_RECV_MAX_BUF, MDM_RECV_BUF_SIZE, 0, NULL);

/**
 * @brief Thread to process all messages received from the Modem.
 */
static void murata_1sc_rx(void)
{
	while (true) {
		/* Wait for incoming data */
		k_sem_take(&mdata.iface_data.rx_sem, K_FOREVER);

		mctx.cmd_handler.process(&mctx.cmd_handler, &mctx.iface);
	}
}

/**
 * @brief Convert string to long integer, but handle errors
 */
static int murata_1sc_atoi(const char *s, const int err_value,
		const char *desc, const char *func)
{
	int   ret;
	char  *endptr;

	ret = (int)strtol(s, &endptr, 10);
	if (!endptr || *endptr != '\0') {
		LOG_ERR("bad %s '%s' in %s", s, desc, func);
		return err_value;
	}

	return ret;
}

static inline uint8_t hex_char_to_int(char ch)
{
	uint8_t ret;

	if (ch >= '0' && ch <= '9') {
		ret = ch - '0';
	}
	else if (ch > 'a' && ch < 'f') {
		ret = 0xa + ch - 'a';
	}
	else if (ch > 'A' && ch < 'F') {
		ret = 0xa + ch - 'A';
	}
	else {
		ret = 0;
	}
	return ret;
}

/**
 * @brief Derive a MAC address from the IMEI
 */
static inline uint8_t *murata_1sc_get_mac(const struct device *dev)
{
	struct murata_1sc_data *data = dev->data;

	/* We will use the least significant 12 digits of the IMEI as
	 * the MAC address. To explain further...
	 * IMEI is always 15 digits long. The constant, MDM_IMEI_LENGTH
	 * is 16 (bytes long) to hold the 15-digit IMEI plus terminator.
	 * MAC address is always 6 bytes long (ie, 12 hex characters).
	 * The loop below is calculating each of the MAC's 6 bytes
	 */
	for (int i=0;i<6;i++) {
		int imei_idx = (MDM_IMEI_LENGTH - 1) - 12 + (i * 2);
		data->mac_addr[i] = (hex_char_to_int(mdata.mdm_imei[imei_idx]) << 4) |
			            (hex_char_to_int(mdata.mdm_imei[imei_idx + 1]));
	}
	return data->mac_addr;
}

/**
 * @brief Handler for OK
 */
MODEM_CMD_DEFINE(on_cmd_ok)
{
	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&mdata.sem_response);
	return 0;
}

/**
 * @brief Handler for ERROR
 */
MODEM_CMD_DEFINE(on_cmd_error)
{
	modem_cmd_handler_set_error(data, -EIO);
	k_sem_give(&mdata.sem_response);
	return 0;
}

MODEM_CMD_DEFINE(on_cmd_sock_sentdata)
{
	if (argc < 2) {
		return -EAGAIN;
	}

	int data_len = (int)strtol(argv[1], NULL, 10);
	return data_len;
}

/**
 * @brief Send data over the given socket
 */
static ssize_t send_socket_data(struct modem_socket *sock,
		const struct sockaddr *dst_addr,
		const char *buf, const size_t buf_len,
		k_timeout_t timeout)
{
	int ret = -1;

	k_sem_take(&mdata.sem_xlate_buf, K_FOREVER);

	int len;
	int written;

	/* Modem command to read the data. */
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
		MODEM_CMD("%SOCKETDATA:", on_cmd_sock_sentdata, 2U, ",")
	};

	len = MIN(buf_len, MDM_MAX_DATA_LENGTH);

	/* Create the command prefix */
	written = snprintk(mdata.xlate_buf, sizeof(mdata.xlate_buf), "AT%%SOCKETDATA=\"SEND\",%d,%zu,\"", sock->sock_fd, len);

	/* Add the hex string */
	data_to_hex_str(buf, len, &mdata.xlate_buf[written], sizeof(mdata.xlate_buf) - written);

	/* Finish the command */
	snprintk(&mdata.xlate_buf[written + len * 2], sizeof(mdata.xlate_buf), "\"");

	/* Send the command */
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), mdata.xlate_buf,
			&mdata.sem_response, MDM_CMD_LONG_RSP_TIME);

	k_sem_give(&mdata.sem_xlate_buf);

	/* unset handler commands and ignore any errors */
	(void)modem_cmd_handler_update_cmds(&mdata.cmd_handler_data,
			NULL, 0U, false);

	/* Return the amount of data written on the socket. */
	if (ret < 0) {
		errno = -ret;
		ret = -1;
	} else {
		errno = 0;
		ret = len;
	}
	return ret;
}

/**
 * @brief Read data on a given socket
 */
static int on_cmd_sockread_common(int socket_fd,
		struct modem_cmd_handler_data *data,
		int socket_data_length, uint16_t len)
{
	struct modem_socket	 *sock = NULL;
	struct socket_read_data	 *sock_data;
	int ret = 0;

	sock = modem_socket_from_fd(&mdata.socket_config, socket_fd);
	if (!sock) {
		LOG_ERR("Socket not found! (%d)", socket_fd);
		ret = -EINVAL;
		goto exit;
	}

	/* Make sure we still have buf data */
	if (!data->rx_buf) {
		LOG_ERR("Incorrect format! Ignoring data!");
		return -EINVAL;
	}

	/* check to make sure we have all of the data (minus quotes)
	   if ((net_buf_frags_len(data->rx_buf) - 2) < socket_data_length) {
	   LOG_DBG("Not enough data -- wait!");
	   return -EAGAIN;
	   }
	   */

	/* skip quote /" */
	len -= 1;
	net_buf_pull_u8(data->rx_buf);
	if (!data->rx_buf->len) {
		data->rx_buf = net_buf_frag_del(NULL, data->rx_buf);
	}

	sock_data = (struct socket_read_data *)sock->data;
	if (!sock_data) {
		LOG_ERR("Socket data not found! Skip handling (%d)", socket_fd);
		ret = -EINVAL;
		goto exit;
	}

	ret = net_buf_linearize(sock_data->recv_buf, sock_data->recv_buf_len,
			data->rx_buf, 0, (uint16_t)(socket_data_length * 2));
	// LOG_INF("net_buf_linearize returned %d", ret);

	data->rx_buf = net_buf_skip(data->rx_buf, ret);
	sock_data->recv_read_len = socket_data_length;

	ret /= 2;
	if ((ret) != socket_data_length) {
		LOG_ERR("Total copied data is different then received data!"
				" copied:%d vs. received:%d", ret, socket_data_length);
		ret = -EINVAL;
	}

exit:
	/* remove packet from list (ignore errors) */
	(void)modem_socket_packet_size_update(&mdata.socket_config, sock,
			-socket_data_length);

	/* don't give back semaphore -- OK to follow */
	// LOG_INF("on_cmd_sockread_common returning %d", ret);

	return ret;
}

/**
 * @brief Handler for receiving unsolicited SMS messages
 */
MODEM_CMD_DEFINE(on_cmd_unsol_sms)
{
	k_sem_give(&mdata.sem_sms);

	return 0;
}

/**
 * @brief Handler for unsolicited events ( SOCKETEV)
 */
MODEM_CMD_DEFINE(on_cmd_unsol_SEV)
{
	struct modem_socket *sock;
	int		sock_fd;
	int 	evt_id;

	LOG_DBG("got unsolicit socketev, evt: %s, sockfd: %s", argv[0], argv[1]);
	evt_id = ATOI(argv[0], 0, "event_id");
	sock_fd = ATOI(argv[1], 0, "sock_fd");
	//TODO - handle optional connected fd
	sock = modem_socket_from_fd(&mdata.socket_config, sock_fd);
	if (!sock) {
		return 0;
	}

	/* Data ready indication. */
	switch(evt_id) {
		case 0:		//in execution
			break;
		case 1:		//Rx Rdy
			LOG_DBG("Data Receive Indication for socket: %d", sock_fd);

			modem_socket_packet_size_update(&mdata.socket_config, sock, 1);
			modem_socket_data_ready(&mdata.socket_config, sock);

			break;
			// TODO: need to save the indication that the socket has been terminated
			//       remotely and treat properly in send and recv functions
		case 2:	//socket deact
		case 3:	//socket terminated
			LOG_WRN("Remote peer closed for socket: %d", sock_fd);
			break;
		case 4:	//socket accepted
			break;
		case 6:	//socket activation done
			break;
		default:
			break;
	}

	return 0;
}

/**
 * @brief Handler for manufacturer
 */
MODEM_CMD_DEFINE(on_cmd_get_manufacturer)
{
	modem_cmd_handler_set_error(data, 0);

	size_t out_len = net_buf_linearize(mdata.mdm_manufacturer,
			sizeof(mdata.mdm_manufacturer) - 1,
			data->rx_buf, 0, len);
	mdata.mdm_manufacturer[out_len] = '\0';
	LOG_DBG("Manufacturer: %s", mdata.mdm_manufacturer);
	return 0;
}

/**
 * @brief Handler for model
 */
MODEM_CMD_DEFINE(on_cmd_get_model)
{
	size_t out_len = net_buf_linearize(mdata.mdm_model,
			sizeof(mdata.mdm_model) - 1,
			data->rx_buf, 0, len);
	mdata.mdm_model[out_len] = '\0';

	/* Log the received information. */
	LOG_DBG("Model: %s", mdata.mdm_model);
	return 0;
}

/**
 * @brief Handler for IMEI
 */
MODEM_CMD_DEFINE(on_cmd_get_imei)
{
	size_t out_len = net_buf_linearize(mdata.mdm_imei,
			sizeof(mdata.mdm_imei) - 1,
			data->rx_buf, 0, len);
	mdata.mdm_imei[out_len] = '\0';

	/* Log the received information. */
	LOG_DBG("IMEI: %s", mdata.mdm_imei);
	return 0;
}

#if defined(CONFIG_MODEM_SIM_NUMBERS)
/**
 * @brief Handler for IMSI
 */
MODEM_CMD_DEFINE(on_cmd_get_imsi)
{
	size_t out_len = net_buf_linearize(mdata.mdm_imsi,
			sizeof(mdata.mdm_imsi) - 1,
			data->rx_buf, 0, len);
	mdata.mdm_imsi[out_len] = '\0';

	/* Log the received information. */
	LOG_DBG("IMSI: %s", mdata.mdm_imsi);
	return 0;
}

/**
 * @brief Handler for ICCID
 */
MODEM_CMD_DEFINE(on_cmd_get_iccid)
{
	size_t out_len = net_buf_linearize(mdata.mdm_iccid,
			sizeof(mdata.mdm_iccid) - 1,
			data->rx_buf, 0, len);
	mdata.mdm_iccid[out_len] = '\0';

	/* Log the received information. */
	LOG_DBG("ICCID: %s", mdata.mdm_iccid);
	return 0;
}
#endif //defined(CONFIG_MODEM_SIM_NUMBERS)

/**
 * @brief Handler for BAND info
 */
MODEM_CMD_DEFINE(on_cmd_get_bands)
{
#define MAX_BANDS_STR_SZ	64
	char bandstr[MAX_BANDS_STR_SZ];
	size_t out_len = net_buf_linearize(bandstr,
			sizeof(bandstr) - 1,
			data->rx_buf, 0, len);
	bandstr[out_len] = '\0';

	/* Log the received information. */
	LOG_DBG("BANDS - %s", bandstr);

	return 0;
}

/**
 * @brief Handler for GETACFG (auto-connect)
 */
static bool needto_set_autoconn_to_true = false;
MODEM_CMD_DEFINE(on_cmd_get_acfg)
{
#define MAX_AUTOCONN_STR_SZ	16
	char autoconnmode_str[MAX_AUTOCONN_STR_SZ];
	size_t out_len = net_buf_linearize(autoconnmode_str,
			sizeof(autoconnmode_str) - 1,
			data->rx_buf, 0, len);
	autoconnmode_str[out_len] = '\0';

	/* Log the received information. */
	if (strncmp(autoconnmode_str, "false", strlen("false")) == 0) {
		needto_set_autoconn_to_true = true;
	} else {
		needto_set_autoconn_to_true = false;
		LOG_DBG("Auto Conn Mode: %s", autoconnmode_str);
	}
	return 0;
}

#ifdef VERIFY_INIT_MODEM_STATE
/**
 * @brief Handler for CFUN
 */
MODEM_CMD_DEFINE(on_cmd_get_cfun)
{
#define MAX_CFUN_STR_SZ	16
	char cfun_resp_str[MAX_CFUN_STR_SZ];
	size_t out_len = net_buf_linearize(cfun_resp_str,
			sizeof(cfun_resp_str) - 1,
			data->rx_buf, 0, len);
	cfun_resp_str[out_len] = '\0';

	/* Log the received information. */
	LOG_DBG("CFUN: %s", cfun_resp_str);
	return 0;
}

/**
 * @brief Handler for CEREG
 */
MODEM_CMD_DEFINE(on_cmd_get_cereg)
{
#define MAX_CEREG_STR_SZ	16
	char cereg_resp_str[MAX_CEREG_STR_SZ];
	size_t out_len = net_buf_linearize(cereg_resp_str,
			sizeof(cereg_resp_str) - 1,
			data->rx_buf, 0, len);
	cereg_resp_str[out_len] = '\0';

	/* Log the received information. */
	LOG_DBG("CEREG: %s", cereg_resp_str);
	return 0;
}
#endif

static char *get_4_octet(char *buf)
{
	char *ptr = buf;
	uint16_t octCnt = 0;
	for (; octCnt < 4; octCnt++) {
		if (ptr) {
			ptr = strchr(ptr, '.');
			++ptr;
		}

	}
	return ptr-1;
}

/**
 * @brief Set auto-connection mode on
 */
static int set_autoconn_on(void)
{
	const char at_cmd[] = "AT\%SETACFG=modem_apps.Mode.AutoConnectMode,\"true\"";
	// struct modem_socket *sock = (struct modem_socket *)obj;

	LOG_WRN("autoconnect is set to false, will now set to true");
	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			NULL, 0, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
	}
	return ret;
}

/**
 * @brief Set BANDs to 2,4, 12 (T-Mobile)
 */
static int set_bands(void)
{
	const char at_cmd[] = "AT\%SETCFG=\"BAND\",\"2\",\"4\",\"12\"";
	LOG_INF("Setting bands to 2, 4, 12");
	modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
		NULL, 0, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);

	// Setting bands is disabled in golden images,
	// but still needed for sample images, so
	// ignore error returned from modem_cmd_send

	return 0;
}

/**
 * @brief Set boot delay to 0
 */
static int set_boot_delay(void)
{
	const char at_cmd[] = "AT\%SETBDELAY=0";
	LOG_INF("Setting boot delay to 0");
	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
		NULL, 0, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);

	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
	}
	return ret;
}


/**
 * @brief Set CFUN to 1 (on) or 0 (off)
 *
 * @param on Value of 1 sets CFUN=1 (turns modem on)
 *           Value of 0 sets CFUN=0 (turns modem off)
 */
static int set_cfun(int on)
{
	char at_cmd[32];
	// struct modem_socket *sock = (struct modem_socket *)obj;

	if (on && mdata.is_awake) {
		LOG_WRN("Modem is already awake");
	} else if (!on && !mdata.is_awake) {
		LOG_WRN("Modem is already asleep");
	}

#if 0
	if (on) {
		LOG_WRN("TURNING MODEM ON");
		// HIFC A Host Resume Handshake
		gpio_pin_set_dt(&wake_mdm_gpio, 1);
		gpio_pin_set_dt(&mdm_tx_gpio, 1);

		k_sleep(K_MSEC(20));

		gpio_pin_set_dt(&wake_mdm_gpio, 0);

		int i = 0;
		for (int i=0;i<50;i++) {
			if (gpio_pin_get_dt(&mdm_rx_gpio) == 0) {
				break;
			}
			k_sleep(K_MSEC(100));
		}
		if (i== 50) {
			LOG_ERR("Modem rx did not go high");
		}

		gpio_pin_set_dt(&mdm_tx_gpio, 0);

		for (int i=0;i<50;i++) {
			if (gpio_pin_get_dt(&wake_host_gpio) == 0) {
				break;
			}
			k_sleep(K_MSEC(100));
		}
		if (i== 50) {
			LOG_ERR("Modem host did not go high!");
		}
	}
#endif
	snprintk(at_cmd, sizeof(at_cmd), "AT+CFUN=%d", on);
	LOG_DBG("%s",at_cmd);
	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			NULL, 0, at_cmd, &mdata.sem_response, MDM_CMD_LONG_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
	} else {
		mdata.is_awake = on;
	}

#if 0
	if (!on) {
		LOG_WRN("TURNING MODEM OFF!");

		// HIFC A Host Resume Handshake
		gpio_pin_set_dt(&wake_mdm_gpio, 0);
		gpio_pin_set_dt(&mdm_tx_gpio, 0);

		k_sleep(K_MSEC(20));

		gpio_pin_set_dt(&wake_mdm_gpio, 1);

		int i = 0;
		for (int i=0;i<50;i++) {
			if (gpio_pin_get_dt(&mdm_rx_gpio)) {
				break;
			}
			k_sleep(K_MSEC(100));
		}
		if (i== 50) {
			LOG_ERR("Modem rx did not go low");
		}

		gpio_pin_set_dt(&mdm_tx_gpio, 1);

		for (int i=0;i<50;i++) {
			if (gpio_pin_get_dt(&wake_host_gpio)) {
				break;
			}
			k_sleep(K_MSEC(100));
		}
		if (i== 50) {
			LOG_ERR("Modem host did not go low!");
		}
	}
#endif
	return ret;
}

/**
 * @brief Use the PDNSET command to set APN and IP type
 */
static int set_pdnset(void)
{
	int ret = 0;

	// Use CONFIG_MODEM_MURATA_1SC_APN if defined and not blank
#if defined(CONFIG_MODEM_MURATA_1SC_APN)
	if (strlen(CONFIG_MODEM_MURATA_1SC_APN)) {
		char at_cmd[128];
#if defined(CONFIG_NET_IPV6)
		LOG_INF("Setting APN to %s and IPV4V6", CONFIG_MODEM_MURATA_1SC_APN);
		snprintk(at_cmd, sizeof(at_cmd), "AT%%PDNSET=1,\"%s\",\"IPV4V6\",\"\",\"\"", CONFIG_MODEM_MURATA_1SC_APN);
#else
		LOG_INF("Setting APN to %s and IPV4", CONFIG_MODEM_MURATA_1SC_APN);
		snprintk(at_cmd, sizeof(at_cmd), "AT%%PDNSET=1,\"%s\",\"IP\",\"\",\"\"", CONFIG_MODEM_MURATA_1SC_APN);
#endif
		LOG_DBG("%s",at_cmd);
		int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
				NULL, 0, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
		if (ret < 0) {
			LOG_ERR("%s ret:%d", at_cmd, ret);
		}
	}
	else {
		LOG_DBG("No APN configuration found");
	}
#else
		LOG_DBG("No CONFIG_MODEM_MURATA_1SC_APN setting found");
#endif
	return ret;
}

/**
 * @brief Enable or disable sleep mode
 */
static int enable_sleep_mode(bool enable)
{
	char at_cmd[256];
	snprintk(at_cmd, sizeof(at_cmd), "AT%%SETACFG=pm.conf.sleep_mode,%s", enable ? "enable" : "disable");
	LOG_INF("%s sleep mode", enable ? "Enabling" : "Disabling");
	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			NULL, 0, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
	}
	return ret;
}

/**
 * @brief Set max allowed (low) power mode
 *
 * @param pm_mode is string representing lowest power mode
 *
 * Supported modes are dh0, dh1, dh2, ds, and ls
 */
static int set_max_allowed_pm_mode(const char *pm_mode)
{
	char at_cmd[256];
	snprintk(at_cmd, sizeof(at_cmd), "AT%%SETACFG=pm.conf.max_allowed_pm_mode,%s", pm_mode);
	LOG_INF("Setting max allowed PM mode to %s", pm_mode);
	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			NULL, 0, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
	}
	return ret;
}

/**
 * @brief Parse the response of AT%PDNRDP=1 to get IP, mask, and gateway
 *
 * @param p1 is the ip addr pointer
 * @param p2 is the mask pointer
 * @param p3 is the gateway pointer
 */
static int parse_ipgwmask(const char *buf, char *p1, char *p2, char *p3)
{
	char *pstr, *pend = NULL;
	size_t len;
	int ret = -1;
	pstr = strchr(buf, ',');	        //session id
	if (pstr) pstr = strchr (pstr+1, ',');	//bearer id
	if (pstr) pstr = strchr (pstr+1, ',');	//apn
	if (pstr) {
		pend = get_4_octet(pstr+1);
	}
	if (pend) {
		*pend = 0;
		len = pend - pstr - 1;
		len = MIN(len, MDM_IP_LENGTH-1);
		memset(p1, 0, MDM_IP_LENGTH);
		strncpy(p1, pstr+1, len);
		pstr = pend+1;
		pend = strchr(pstr, ',');
		if (pend) {
			*pend = 0;
			len = pend - pstr;
			len = MIN(len, MDM_GW_LENGTH-1);
			memset(p2, 0, MDM_GW_LENGTH);
			strncpy(p2, pstr, len);
			pstr = pend+1;
			pend = strchr(pstr, ',');
			if (pend) {
				*pend = 0;
				len = pend - pstr;
				len = MIN(len, MDM_MASK_LENGTH-1);
				memset(p3, 0, MDM_MASK_LENGTH);
				strncpy(p3, pstr, len);
				LOG_DBG("IP: %s, MASK: %s, GW: %s\n", p1, p2, p3);
				ret = 0;
			}
		}
	}
	return ret;
}

#define PDN_QUERY_RESPONSE_LEN 256
static bool first_pdn_rcved = false;

/**
 * @brief Handler for PDNRDP
 *
 * Sample output:
 * AT at%pdnrdp=1
 * %PDNRDP: 1,5,"iot.catm.mnc882.mcc311.gprs",25.181.129.55.255.255.255.240,
 * 25.181.129.49,10.177.0.34,10.177.0.210,,,,,,,,,
 */
MODEM_CMD_DEFINE(on_cmd_ipgwmask)
{
	char buf[PDN_QUERY_RESPONSE_LEN];
	int ret = 0;
	size_t read_cnt;
	LOG_DBG("Got PDNRDP, len = %d", len);
	if (!first_pdn_rcved) {
		first_pdn_rcved = true;
		read_cnt = net_buf_linearize(buf,
				PDN_QUERY_RESPONSE_LEN - 1,
				data->rx_buf, 0, len);
		if (strnstr(buf, "\r\n", read_cnt)) {
			LOG_WRN("Not enough octets!!");
			ret = -EAGAIN;
			first_pdn_rcved = false;
		} else {
			buf[read_cnt] = 0;
			ret = parse_ipgwmask(buf, mdata.mdm_ip, mdata.mdm_nmask, mdata.mdm_gw);

			/* Log the received information. */
			LOG_DBG("IP: %s, GW: %s, NMASK: %s", mdata.mdm_ip, mdata.mdm_gw, mdata.mdm_nmask);
		}
	}
	return ret;
}

/**
 * @brief Use AT%PDNRDP=1 to get IP settings from modem
 */
static int get_ipv4_config(void)
{
	const char at_cmd[] = "AT\%PDNRDP=1";

	struct modem_cmd data_cmd[] = {
		MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
		MODEM_CMD("%PDNRDP", on_cmd_ipgwmask, 0U, ":")
	};

	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
	}
	return ret;
}

/**
 * @brief Return the first string between double quotes
 */
static int get_str_in_quotes(const char *buf, char *pdest, size_t dest_size)
{
	char delim = '"';
	char *pstart, *pend;
	int strlen = 0;

	pstart = strchr(buf, delim);
	if (pstart) {
		++pstart;
		pend = strchr(pstart, delim);
		if (pend) {
			strlen = pend - pstart;
			strlen = MIN(strlen, dest_size - 1);
			strncpy(pdest, pstart, strlen);
			pdest[strlen] = '\0';
		}
	}
	return strlen;
}

struct mdm_dns_resp_t {
	struct sockaddr_in ipv4;
	struct sockaddr_in6 ipv6;
};

struct mdm_dns_resp_t mdm_dns_ip;

/**
 * @brief Parse the DNS response
 */
static int parse_dnsresp(char *buf, struct mdm_dns_resp_t *dns_resp)
{
#define IP_STR_LEN 100
	int len;	//len of the string in ""
	char ip[IP_STR_LEN];
	if ('0' == buf[0]) {
		len = get_str_in_quotes(buf, ip, IP_STR_LEN);
		ip[len] = 0;
		dns_resp->ipv4.sin_family = AF_INET;
		inet_pton(AF_INET, ip, &dns_resp->ipv4.sin_addr.s_addr);
		LOG_DBG("dns-ipv4: %s\n", ip);
	}
#if defined(CONFIG_NET_IPV6)
	else if ('1' == buf[0]) {
		len = get_str_in_quotes(buf, ip, IP_STR_LEN);
		ip[len] = 0;
		dns_resp->ipv6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, ip, &dns_resp->ipv6.sin6_addr.s6_addr);
		LOG_DBG("dns-ipv6: %s\n", ip);
	}
#endif
	else {
		return -1;
	}
	return 0;
}

/**
 * @brief Handler for DNSRSLV
 */
MODEM_CMD_DEFINE(on_cmd_dnsrslv)
{
#define DNS_QUERY_RESPONSE_LEN 128
	char buf[DNS_QUERY_RESPONSE_LEN];
	int ret = 0;
	size_t read_cnt;
	read_cnt = net_buf_linearize(buf,
			DNS_QUERY_RESPONSE_LEN - 1,
			data->rx_buf, 0, len);
	if (strnstr(buf, "\r\n", read_cnt)) {
		LOG_WRN("NOT enough octets!!");
		ret = -EAGAIN;
		first_pdn_rcved = false;
	} else {
		buf[read_cnt] = 0;
		parse_dnsresp(buf, &mdm_dns_ip);

		/* Log the received information. */
		//LOG_INF("GOt DNSRSLV, len = %d, read_cnt = %d", len, read_cnt);
	}
	return ret;
}

/**
 * @brief get ipv4/6 DNS info from modem
 * @param: domain name in string
 */
static int get_dns_ip(const char *dn)
{
	char at_cmd[64];
	int  ret;
	// struct modem_socket *sock = (struct modem_socket *)obj;

	struct modem_cmd data_cmd[] = {
		MODEM_CMD("%DNSRSLV:", on_cmd_dnsrslv, 0U, ""),
	};

	snprintk(at_cmd, sizeof(at_cmd), "AT%%DNSRSLV=0,\"%s\"", dn);
	LOG_DBG("%s", at_cmd);
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, 1, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
	}
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	if (strncmp(dn, CONFIG_TLS_SNI_HOSTNAME, sizeof(CONFIG_TLS_SNI_HOSTNAME)) == 0) {
		strcpy(sni_hostname, dn);
	} else {
		memset(sni_hostname, 0, sizeof(sni_hostname));
	}
#endif
	return ret;
}

/**
 * @brief Handler to read data from socket
 * @param argv[0] sock_id
 * @param argv[1] data_len length of data
 * @param argv[2] more indicates whether more data is available
 * @param argv[3] data (but not necessarily contiguous)
 *
 * %SOCKETDATA:<socket_id>[0],<length>[1],<moreData>[2],
 * "<data>", <src_ip>, <src_port>
 *
 * prototype for this function:
 * static int name_(struct modem_cmd_handler_data *data, uint16_t len, \
 * uint8_t **argv, uint16_t argc)
 */
MODEM_CMD_DEFINE(on_cmd_sock_readdata)
{
	// We need at least 3 parameters. Less than 3 causes an error like this:
	// <err> modem_cmd_handler: process cmd [%SOCKETDATA:] (len:16, ret:-22)
	// Returning 0 here prevents the error
	if (argc < 3) {
		return 0;
	}

	// int sock_id = (int)strtol(argv[0], NULL, 10);
	// int data_len = (int)strtol(argv[1], NULL, 10);
	int more = (int)strtol(argv[2], NULL, 10);

	int ret = on_cmd_sockread_common(mdata.sock_fd, data, ATOI(argv[1], 0, "length"), len);
	LOG_DBG("on_cmd_sockread_common returned %d", ret);

	if (more) {
		struct modem_socket *sock = modem_socket_from_fd(&mdata.socket_config, mdata.sock_fd);
		modem_socket_packet_size_update(&mdata.socket_config, sock, 1);
		modem_socket_data_ready(&mdata.socket_config, sock);
	}

	return ret;
}

static const struct modem_cmd response_cmds[] = {
	MODEM_CMD("OK", on_cmd_ok, 0U, ""),
	MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
};

static const struct modem_cmd unsol_cmds[] = {
	MODEM_CMD("%SOCKETEV:",	   on_cmd_unsol_SEV, 2U, ","),
	MODEM_CMD("+CMTI:", on_cmd_unsol_sms, 2U, ","),
};

/**
 * @brief Handler for %SOCKETCMD:<socket_id> OK
 */
MODEM_CMD_DEFINE(on_cmd_sockopen)
{

	int sock_id = data->rx_buf->data[0] - '0';
	mdata.sock_fd = sock_id;
	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&mdata.sem_sock_conn);

	return 0;
}


static bool got_pdn_flg;

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#define CLIENT_CA_CERTIFICATE_TAG	1
static int offload_setsockopt(void *obj, int level, int optname,
		const void *optval, socklen_t optlen);
sec_tag_t sec_tag_list[] = {
	CLIENT_CA_CERTIFICATE_TAG,
};

MODEM_CMD_DEFINE(on_cmd_atcmd_file_read)
{
	size_t out_len;

	uint8_t *pbuf = mdata.xlate_buf;
	out_len = net_buf_linearize(pbuf,
			127,				//read partial
			data->rx_buf, 0, len);
	pbuf[out_len] = '\0';

	LOG_DBG("received cert file: %s", pbuf);

	return 0;
}

/**
 * @brief check whether filename exists in modem's D:CERTS/USER/ folder
 * @return 0 if file exists on modem; -1 if not
 */
static int check_mdm_store_file(char *filename)
{
	int ret = 0;
	char at_cmd[60];
	got_pdn_flg = false;
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("%CERTCMD:", on_cmd_atcmd_file_read, 0U, ""),
	};

	snprintk(at_cmd, sizeof(at_cmd), "AT%%CERTCMD=\"READ\",\"%s\"", filename);
	LOG_DBG("%s", at_cmd);
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, 1, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
		ret = -1;
	}

	return ret;

}

#ifdef CONFIG_USER_CA_DER_ENABLED
/**
 * @brief Hard-code slot 10 for public CA
 */
static int set_cert_profile(void)
{
	int ret;
	snprintk(cert_cmd_buf.cert_cmd_write, sizeof(cert_cmd_buf.cert_cmd_write),
			"AT%%CERTCFG=\"ADD\",10,\"%s\",\"~\"", CONFIG_USER_ROOT_CA_FILE);

	LOG_DBG("certcfg: %s", cert_cmd_buf.cert_cmd_write);
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			NULL, 0U, cert_cmd_buf.cert_cmd_write,
			&mdata.sem_response, MDM_CMD_LONG_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("sendmdmcmd,ret = %d", ret);
	}
	return ret;
}
#endif

/**
 * @brief Misc init after normal mdm init
 */
static int post_mdm_init(void)
{

	int ret = 0;
#ifdef CONFIG_USER_CA_DER_ENABLED
	struct modem_socket sock;
	ret = check_mdm_store_file(CONFIG_USER_CA_FILE);
	if (ret != 0) {
		ret = tls_credential_add(CLIENT_CA_CERTIFICATE_TAG,
				TLS_CREDENTIAL_CA_CERTIFICATE,
				ca_certificate,
				sizeof(ca_certificate));
		if (ret < 0) {
			LOG_ERR("<<< Failed to add CA certificate: %d >>>", ret);
			return ret;
		}
		ret = offload_setsockopt(&sock, SOL_TLS, TLS_SEC_TAG_LIST, (void *)sec_tag_list, sizeof(sec_tag_list));
		if (ret < 0) {
			LOG_ERR("failed to setsockopt in post_mdm_init, ret = %d", ret);
			return ret;
		}
	}
	ret = set_cert_profile();
	if (ret < 0) {
		LOG_ERR("failed to setsockopt in post_mdm_init, ret = %d", ret);
	}
#endif
	return ret;
}
#endif

/**
 * @brief Handler for AT+COPS?
 */
MODEM_CMD_DEFINE(on_cmd_cops)
{
	char buf[32];
	int sz;
	size_t out_len = net_buf_linearize(buf, sizeof(buf) - 1,
			data->rx_buf, 0, len);
	buf[out_len] = '\0';

	LOG_DBG("full cops: %s", buf);
	sz = get_str_in_quotes(buf, mdata.mdm_carrier, sizeof(mdata.mdm_carrier));

	/* Log the received information. */
	LOG_DBG("Carrier: %s", mdata.mdm_carrier);

	sz ? (errno = 0) : (errno = EINVAL);
	return sz ? 0 : -1;
}

/**
 * @brief Get connection status
 */
static int get_carrier(char *rbuf)
{
	int ret;
	const char at_cmd[] = "AT+COPS?";
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("+COPS:", on_cmd_cops, 0U, ","),
	};

	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), at_cmd, &mdata.sem_response, MDM_CMD_LONG_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
		ret = -1;
	}
	snprintk(rbuf, MAX_CARRIER_RESP_SIZE, "%s", mdata.mdm_carrier);
	return ret;
}

/**
 * @brief Reset the modem
 */
static int reset_modem()
{
	const char at_cmd[] = "ATZ";
	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
		NULL, 0, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("error rebooting modem");
	} else {
		LOG_INF("Waiting %d secs for modem to boot...", MDM_BOOT_DELAY);
		k_sleep(K_SECONDS(MDM_BOOT_DELAY));
	}
	return ret;
}

/**
 * @brief Close the given socket
 */
static void socket_close(struct modem_socket *sock)
{
	char at_cmd[40];
	int  ret;

	if (sock->is_connected) {

		/* Tell the modem to close the socket. */
		snprintk(at_cmd, sizeof(at_cmd), "AT%%SOCKETCMD=\"DEACTIVATE\",%d", sock->sock_fd);
		ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
				NULL, 0U, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);

		if (ret < 0) {
			LOG_ERR("%s ret:%d", at_cmd, ret);
		}

		/* Tell the modem to delete the socket. */
		snprintk(at_cmd, sizeof(at_cmd), "AT%%SOCKETCMD=\"DELETE\",%d", sock->sock_fd);
		ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
				NULL, 0U, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
		if (ret < 0) {
			LOG_ERR("%s ret:%d", at_cmd, ret);
		}
	}

	modem_socket_put(&mdata.socket_config, sock->sock_fd);
}

/**
 * @brief Send an sms message
 */
static int send_sms_msg(void *obj, const struct sms_out *sms)
{
	/* The "+ 20" is to account for AT+CMGS plus a bit extra */
	char at_cmd[sizeof(struct sms_out) + 20];
	int  ret;
	// struct modem_socket *sock = (struct modem_socket *)obj;

	snprintk(at_cmd, sizeof(at_cmd), "AT+CMGF=1");
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			NULL, 0U, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
	}

	snprintk(at_cmd, sizeof(at_cmd), "AT+CMGS=\"%s\"\r%s\x1a", sms->phone, sms->msg);
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			NULL, 0U, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
	}

	return ret;
}

/* @brief Handler to read SMS message from modem
 *
 * Below is an example of AT+CMGL response format:
 * <<<<<
 * AT at+cmgl="ALL"
 * 
 * +CMGL: 1,"REC UNREAD","+12817725818",,"21/11/01,06:22:13-28"
 * First sms msg
 * +CMGL: 2,"REC UNREAD","+12817725818",,"21/11/01,06:22:22-28"
 * Second test msg
 * 
 * OK
 * >>>>>
 *
 * At entry, the 6 args prior to the message have been parsed:
 * argv[0] = message index
 * argv[1] = message status
 * argv[2] = address (phone number)
 * argv[3] = address text
 * argv[4] = date in format \"yy/mm/dd,
 * argv[5] = time in format hh:mm:ss[+/-][tz offset]\"
 *
 * data is pointing at argv[5]
 **/
MODEM_CMD_DEFINE(on_cmd_readsms)
{
	struct sms_in *sms = mdata.sms;
	char *str1;
	char *str2;
	char *str3;

	/*
	printk("In on_cmd_readsms\n");
	for (int i=0;i<argc;i++)
	printk("   argv[%i]='%s'\n", i, argv[i]);

	printk("data (len=%d, strlen=%d: '", data->rx_buf->len, strlen(data->rx_buf->data));
	for (int i=0;i<data->rx_buf->len;i++)
	printk("%c", data->rx_buf->data[i]);
	printk("'\n");
	*/

	// Verify that the entire response has arrived
	str1 = strnstr(data->rx_buf->data, "\r\nOK\r\n", data->rx_buf->len);
	if (str1 == NULL)
		return -EAGAIN;

	// Find the beginning of the message (first crlf after argv[5])
	str1 = strnstr(data->rx_buf->data, "\r\n", data->rx_buf->len);
	if (str1) {
		// Find the end of the message (next crlf after str1 + 2)
		str2 = strnstr(str1 + 2, "\r\n", data->rx_buf->len - (size_t) (str1 + 2 - (char *) data->rx_buf->data));
		if (str2) {
			*str2 = '\0';
			LOG_DBG("SMS msg: '%s'\n", str1 + 2);

			// Prepare the return struct
			snprintk(sms->phone, sizeof(sms->phone), "%s", argv[2]);
			snprintk(sms->time, sizeof(sms->time), "%.8s,%.11s", argv[4]+1, argv[5]);
			snprintk(sms->msg, sizeof(sms->msg), "%s", str1 + 2);

			// Set sms_index so we can delete the message from recv_sms_msg
			// TBD: should we just delete it here
			mdata.sms_index = atoi(argv[0]);

			// Check for "\r\nOK\r\n" at the end of CMGL response
			// Skip ahead to the found string if present since
			// we need to let the command handler know we're done.
			str3 = strnstr(str2 + 2, "\r\nOK\r\n", data->rx_buf->len - (size_t) (str2 + 2 - (char *) data->rx_buf->data));
			if (str3) {
				data->rx_buf = net_buf_skip(data->rx_buf, (size_t) ((uint8_t *) str3 - data->rx_buf->data));
			}
		}
		else {
			LOG_DBG("Warning, SMS bad format 2\n");
			return -EAGAIN;
		}
	}
	else {
		LOG_WRN("Warning, SMS bad format 1\n");
		return -EAGAIN;
	}

	return 0;
}

/**
 * @brief Recieve sms message
 */
static int recv_sms_msg(void *obj, struct sms_in *sms)
{
	char at_cmd[64];
	int  ret;
	// struct modem_socket *sock = (struct modem_socket *)obj;
	int count = 0;

	k_sem_reset(&mdata.sem_sms);

	/* Modem command response to sms receive the data. */
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
		MODEM_CMD("+CMGL:", on_cmd_readsms, 6U, ",")
	};

	snprintk(at_cmd, sizeof(at_cmd), "AT+CMGF=1");
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			NULL, 0U, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_DBG("recv_sms_msg error 1\n");
		LOG_ERR("%s ret:%d", at_cmd, ret);
	}

	// Set pointer to struct which is populated in on_cmd_sockreadsms
	mdata.sms = sms;

	while (count <= 1) {
		snprintk(at_cmd, sizeof(at_cmd), "AT+CMGL=\"ALL\"");
		ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
				data_cmd, ARRAY_SIZE(data_cmd), at_cmd, &mdata.sem_response, MDM_CMD_LONG_RSP_TIME);
		if (ret < 0) {
			LOG_ERR("recv_sms_msg error 2, %s ret = %d\n", at_cmd, ret);
		}

		else {
			if (mdata.sms_index)
			{
				LOG_DBG("Received SMS from %s dated %s: %s\n", mdata.sms->phone, mdata.sms->time, mdata.sms->msg);

				// Delete the message from the modem
				snprintk(at_cmd, sizeof(at_cmd), "AT+CMGD=%d", mdata.sms_index);
				ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
						NULL, 0U, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
				if (ret < 0) {
					LOG_DBG("recv_sms_msg error 3\n");
					LOG_ERR("%s ret:%d", at_cmd, ret);
				}

				ret = mdata.sms_index;
				mdata.sms_index = 0;
				break;
			}
		}

		// if no message was returned, wait for an SMS message for the requested time
		if (ret == 0 && count == 0) {
			ret = k_sem_take(&mdata.sem_sms, sms->timeout);
			if (ret < 0) {
				// timed out waiting for semaphore, set ret code to 0 (no msg available)
				ret = 0;
				break;
			}
		}
		count++;
	}
	return ret;
}

/**
 * @brief Receive data on a socket
 */
static ssize_t offload_recvfrom(void *obj, void *buf, size_t len,
		int flags, struct sockaddr *from,
		socklen_t *fromlen)
{
	struct modem_socket *sock = (struct modem_socket *)obj;
	char   sendbuf[100];
	int    ret = 0;
	struct socket_read_data sock_data;

	/* Modem command to read the data. */
	struct modem_cmd data_cmd[] = { 
		MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
		MODEM_CMD("%SOCKETDATA:", on_cmd_sock_readdata, 3U, ",")
	};

	LOG_DBG("IN offload_recvfrom, flags = 0x%x", flags);
	LOG_DBG("buf = 0x%x, len = %d\n", (unsigned int) buf, len);

	if (!buf || len == 0) {
		errno = EINVAL;
		return -1;
	}

	if (flags & ZSOCK_MSG_PEEK) {
		errno = ENOTSUP;
		return -1;
	}

	if (len > MDM_MAX_DATA_LENGTH) {
		len = MDM_MAX_DATA_LENGTH;
	}

	int packet_size = modem_socket_next_packet_size(&mdata.socket_config,
							 sock);
	if (!packet_size) {
		if (flags & ZSOCK_MSG_DONTWAIT) {
			errno = EAGAIN;
			return -1;
		}

		if (!sock->is_connected && sock->ip_proto != IPPROTO_UDP) {
			errno = 0;
			return 0;
		}

		modem_socket_wait_data(&mdata.socket_config, sock);
		packet_size = modem_socket_next_packet_size(
			&mdata.socket_config, sock);
	}

	/* Socket read settings */
	(void) memset(&sock_data, 0, sizeof(sock_data));
	sock_data.recv_buf     = mdata.xlate_buf;
	sock_data.recv_buf_len = sizeof(mdata.xlate_buf);
	sock_data.recv_addr    = from;
	sock->data	       = &sock_data;
	mdata.sock_fd          = sock->sock_fd;

	/* use dst address as from */
	if (from && fromlen) {
		*fromlen = sizeof(sock->dst);
		memcpy(from, &sock->dst, *fromlen);
	}

	snprintk(sendbuf, sizeof(sendbuf), "AT%%SOCKETDATA=\"RECEIVE\",%u,%u",
			sock->sock_fd, len);

	LOG_DBG("%s", sendbuf);

	// Lock the xlate buffer
	k_sem_take(&mdata.sem_xlate_buf, K_FOREVER);

	/* Tell the modem to give us data (%SOCKETDATA:socket_id,len,0,data). */
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, data_cmd,
			ARRAY_SIZE(data_cmd), sendbuf, &mdata.sem_response,
			MDM_CMD_LONG_RSP_TIME);

	LOG_DBG("Returned from modem_cmd_send with ret=%d", ret);
	LOG_DBG("rec_len = %d", sock_data.recv_read_len);

	if (ret < 0) {
		k_sem_give(&mdata.sem_xlate_buf);
		errno = -ret;
		goto exit;
	}

	/* return length of received data */
	hex_str_to_data(mdata.xlate_buf, (uint8_t *) buf, sock_data.recv_read_len);
	k_sem_give(&mdata.sem_xlate_buf);
	errno = 0;

	/* HACK: use dst address as from */
	if (from && fromlen) {
		*fromlen = sizeof(sock->dst);
		memcpy(from, &sock->dst, *fromlen);
	}

	/* return length of received data */
	errno = 0;
	ret = sock_data.recv_read_len;

exit:
	/* clear socket data */
	sock->data = NULL;
	return ret;
}

/**
 * @brief Implement the socket function for the modem
 */
static int offload_socket(int family, int type, int proto)
{
	int ret;

	/* defer modem's socket create call to bind() */
	ret = modem_socket_get(&mdata.socket_config, family, type, proto);

	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	errno = 0;
	return ret;
}

/**
 * @brief Connect with a TCP or UDP peer
 */
static int offload_connect(void *obj, const struct sockaddr *addr,
		socklen_t addrlen)
{
	struct modem_socket *sock     = (struct modem_socket *) obj;
	uint16_t dst_port  = 0;
	char protocol[5];
	char at_cmd[100];
	int  ret;
	int sd = -1;

	LOG_DBG("In offload_connect, sock->id: %d, sock->sock_fd: %d", sock->id, sock->sock_fd);

	struct modem_cmd cmd[] = {
		MODEM_CMD("ERROR", on_cmd_error, 0, ","),
		MODEM_CMD("%SOCKETCMD:", on_cmd_sockopen, 0U, ""),
	};

	if (addrlen > sizeof(struct sockaddr)) {
		errno = EINVAL;
		return -1;
	}

	if (sock->id < mdata.socket_config.base_socket_num - 1) {
		LOG_ERR("Invalid socket_id(%d) from fd:%d",
				sock->id, sock->sock_fd);
		errno = EINVAL;
		return -1;
	}

	if (sock->is_connected == true) {
		LOG_ERR("Socket is already connected!! socket_id(%d), socket_fd:%d",
				sock->id, sock->sock_fd);
		errno = EINVAL;
		return -1;
	}

	switch (sock->ip_proto) {
		case IPPROTO_UDP:
			snprintk(protocol, sizeof(protocol), "UDP");
			break;
		case IPPROTO_TCP:
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
		case IPPROTO_TLS_1_2:
#endif
			snprintk(protocol, sizeof(protocol), "TCP");
			break;
		default:
			LOG_ERR("INVALID PROTOCOL %d", sock->ip_proto);
			socket_close(sock);
			return -1;
	}

	/* Find the correct destination port. */
	if (addr->sa_family == AF_INET6) {
		dst_port = ntohs(net_sin6(addr)->sin6_port);
	} else if (addr->sa_family == AF_INET) {
		dst_port = ntohs(net_sin(addr)->sin_port);
	}

	k_sem_reset(&mdata.sem_sock_conn);

	// get IP and save to buffer
	char ip_addr[30];
	modem_context_sprint_ip_addr(addr, ip_addr, sizeof(ip_addr));

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	if (sock->ip_proto == IPPROTO_TLS_1_2) {
		sd = strncmp(sni_hostname, CONFIG_TLS_SNI_HOSTNAME, sizeof(CONFIG_TLS_SNI_HOSTNAME));
	} else {
		sd = -1;
	}
#else
	sd = -1;
#endif
	/* Formulate the string to allocate socket. */
	if (sd != 0) {
		snprintk(at_cmd, sizeof(at_cmd), "AT%%SOCKETCMD=\"ALLOCATE\",0,\"%s\",\"OPEN\",\"%s\",%d",
				protocol, ip_addr, dst_port);
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	} else {
		snprintk(at_cmd, sizeof(at_cmd), "AT%%SOCKETCMD=\"ALLOCATE\",0,\"%s\",\"OPEN\",\"%s\",%d",
				protocol, sni_hostname, dst_port);
#endif
	}

	/* Send out the command. */
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			cmd, ARRAY_SIZE(cmd), at_cmd,
			&mdata.sem_response, MDM_CMD_RSP_TIME);

	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
		LOG_ERR("Closing the socket!!!");
		socket_close(sock);
		errno = -ret;
		return -1;
	}

	ret = k_sem_take(&mdata.sem_sock_conn, K_SECONDS(1));
	if (ret < 0) {
		LOG_ERR("Timeout for waiting for sockconn; closing socket!");
		socket_close(sock);
		errno = -ret;
		return -1;
	}

	LOG_DBG("store %d into sock: %p", mdata.sock_fd, sock);
	sock->sock_fd = mdata.sock_fd;

	if (sock->ip_proto == IPPROTO_TLS_1_2) {
		int profileID;
		if (sd == 0) {
			profileID = CONFIG_AMAZON_CA_ROOT_SLOT;
		} else
			profileID = CONFIG_SNI_SLOT;

		snprintk(at_cmd, sizeof(at_cmd), "AT%%SOCKETCMD=\"SSLALLOC\",%d,1,%d", sock->sock_fd, profileID);

		ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
				NULL, 0U, at_cmd,
				&mdata.sem_response, MDM_CMD_LONG_RSP_TIME);
		LOG_DBG("%s", at_cmd);
		if (ret < 0) {
			LOG_ERR("%s ret: %d", at_cmd, ret);
			LOG_ERR("Closing the socket!!!");
			socket_close(sock);
			errno = -ret;
			return -1;
		}
	}

	snprintk(at_cmd, sizeof(at_cmd), "AT%%SOCKETCMD=\"ACTIVATE\",%d", sock->sock_fd);
	LOG_DBG("%s", at_cmd);
	/* Send out the command. */
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			NULL, 0U, at_cmd,
			&mdata.sem_response, MDM_CMD_RSP_TIME);

	if (ret < 0) {
		LOG_ERR("%s ret: %d", at_cmd, ret);
		LOG_ERR("Closing the socket!!!");
		socket_close(sock);
		errno = -ret;
		return -1;
	}

	/* set command handlers */
	ret = modem_cmd_handler_update_cmds(&mdata.cmd_handler_data,
			cmd, ARRAY_SIZE(cmd), true);
	if (ret < 0) {
		LOG_ERR("Failed to update cmds, ret= %d", ret);
		goto exit;
	}

	/* Connected successfully. */
	sock->is_connected = true;
	errno = 0;
	memcpy(&sock->dst, addr, addrlen);
	return 0;

exit:
	(void) modem_cmd_handler_update_cmds(&mdata.cmd_handler_data,
			NULL, 0U, false);
	errno = -ret;
	return -1;
}

/**
 * @brief Send data on the socket object
 */
static ssize_t offload_sendto(void *obj, const void *buf, size_t len,
		int flags, const struct sockaddr *to,
		socklen_t tolen)
{
	int ret;
	struct modem_socket *sock = (struct modem_socket *) obj;
	/* Ensure that valid parameters are passed. */
	if (!buf || len <= 0) {
		errno = EINVAL;
		return -1;
	}

	if (!sock->is_connected) {
		if (sock->type == SOCK_DGRAM) {
			/* for unconnected udp, try to connect */
			ret = offload_connect(obj, to, tolen);
			if (ret < 0) {
				errno = ret;
				return -1;
			}
		} else {
			errno = ENOTCONN;
			return -1;
		}
	} else {
		/* if already connected, to should be NULL and tolen should be 0 */
		/* or if not, check whether it is the same as the connected socket */
		if (to != NULL || tolen != 0) {
			if ((to == NULL && tolen) ||
			    ((to != NULL) && !tolen) ||
			    (memcmp(to, &sock->dst, tolen) != 0)) {
				errno = EISCONN;
				return -1;
			}
		}
	}
	return send_socket_data(sock, to, buf, len, MDM_CMD_TIMEOUT);
}

/**
 * Implement the bind function for the modem
 */
static int offload_bind(void *obj, const struct sockaddr *addr,
		socklen_t addrlen)
{
	struct modem_socket *sock = (struct modem_socket *)obj;

	/* save bind address information */
	memcpy(&sock->src, addr, sizeof(*addr));

	/* make sure we've created the socket */
	if (sock->id == mdata.socket_config.sockets_len + 1) {
		if (offload_connect(obj, addr, addrlen) < 0) {
			return -1;
		}
	}

	return 0;
}

/**
 * @brief Read data from the given socket object
 */
static ssize_t offload_read(void *obj, void *buffer, size_t count)
{
	return offload_recvfrom(obj, buffer, count, 0, NULL, 0);
}

/**
 * @brief Write data to the given socket object
 */
static ssize_t offload_write(void *obj, const void *buffer, size_t count)
{
	return offload_sendto(obj, buffer, count, 0, NULL, 0);
}

/**
 * @brief Close the connection with the remote client and free the socket
 */
static int offload_close(void *obj)
{
	struct modem_socket *sock = (struct modem_socket *) obj;

	/* Make sure we assigned an id */
	if (sock->id < mdata.socket_config.base_socket_num) {
		return 0;
	}

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	int sd = find_valid_sni();
	if (sd != -1) {
		servername_desc[sd].sni_valid = false;
	}
#endif
	/* Close the socket only if it is connected. */
	socket_close(sock);

	return 0;
}

/**
 * @brief Send messages to the modem
 */
static ssize_t offload_sendmsg(void *obj, const struct msghdr *msg, int flags)
{
	ssize_t sent = 0;
	int rc;

	LOG_DBG("msg_iovlen:%zd flags:%d", msg->msg_iovlen, flags);

	for (int i = 0; i < msg->msg_iovlen; i++) {
		const char *buf = msg->msg_iov[i].iov_base;
		size_t len	= msg->msg_iov[i].iov_len;

		while (len > 0) {
			rc = offload_sendto(obj, buf, len, flags,
					msg->msg_name, msg->msg_namelen);
			if (rc < 0) {
				if (rc == -EAGAIN) {
					k_sleep(MDM_SENDMSG_SLEEP);
				} else {
					sent = rc;
					break;
				}
			} else {
				sent += rc;
				buf += rc;
				len -= rc;
			}
		}
	}

	return (ssize_t) sent;
}

static struct zsock_addrinfo zsai[2] = {0};
static struct sockaddr_in6 zai_addr[2] = {0};

static void murata_1sc_freeaddrinfo(struct zsock_addrinfo *res)
{
	/* No need to free static memory. */
	res = NULL;
}

static inline uint32_t qtupletouint(uint8_t *ia) {return *(uint32_t*)ia;}

static int set_addr_info(uint8_t *addr, bool ipv6, uint8_t socktype, uint16_t port,
		struct zsock_addrinfo **res)
{
	struct zsock_addrinfo *ai;
	struct sockaddr *ai_addr;
	int retval = 0;

	int ai_idx = 0;
	memset(zsai, 0, sizeof(zsai));
	memset(zai_addr, 0, sizeof(zai_addr));

	ai = &zsai[ai_idx];
	ai_addr = (struct sockaddr *)&zai_addr[ai_idx];
	ai_idx++;

	ai->ai_family = (ipv6 ? AF_INET6 : AF_INET);
	ai->ai_socktype = socktype;
	ai->ai_protocol = ai->ai_socktype == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;

	/* Fill sockaddr struct fields based on family: */
	if (ai->ai_family == AF_INET) {
		net_sin(ai_addr)->sin_family = ai->ai_family;
		net_sin(ai_addr)->sin_addr.s_addr = qtupletouint(addr);
		net_sin(ai_addr)->sin_port = htons(port);
		ai->ai_addrlen = sizeof(struct sockaddr_in);
	} else {
		net_sin6(ai_addr)->sin6_family = ai->ai_family;
		net_sin6(ai_addr)->sin6_addr.s6_addr32[0] =
			qtupletouint(&addr[0]);
		net_sin6(ai_addr)->sin6_addr.s6_addr32[1] =
			qtupletouint(&addr[4]);
		net_sin6(ai_addr)->sin6_addr.s6_addr32[2] =
			qtupletouint(&addr[8]);
		net_sin6(ai_addr)->sin6_addr.s6_addr32[3] =
			qtupletouint(&addr[12]);
		net_sin6(ai_addr)->sin6_port = htons(port);
		ai->ai_addrlen = sizeof(struct sockaddr_in6);
	}
	ai->ai_addr = ai_addr;
	ai->ai_next = *res;
	*res = ai;
	return retval;
}

static int murata_1sc_getaddrinfo(const char *node, const char *service,
		const struct zsock_addrinfo *hints,
		struct zsock_addrinfo **res)
{
	int32_t retval = -1, retval4 = -1, retval6 = -1;
	uint32_t port = 0;
	uint8_t type = SOCK_STREAM;
	if (service) {
		port = (uint32_t)strtol(service, NULL, 10);
		if (port < 1 || port > USHRT_MAX) {
			return DNS_EAI_SERVICE;
		}
	}

	/* Check args: */
	if (!res) {
		retval = DNS_EAI_NONAME;
		goto exit;
	}

	bool v4 = true, v6 = true;

	if (hints) {
		if (hints->ai_family == AF_INET){
			v6 = false;
		} else if (hints->ai_family == AF_INET6){
			v4 = false;
		}
		type = hints->ai_socktype;
	}

#if IS_ENABLED(CONFIG_NET_IPV4)
	if (v4) {
		retval4 = get_dns_ip(node);
	}
#endif

	if (retval4 < 0 && retval6 < 0) {
		LOG_ERR("Could not resolve name: %s, retval: %d", node, retval);
		retval = DNS_EAI_NONAME;
		goto exit;
	}

	*res = NULL;

	retval = set_addr_info((uint8_t *)&mdm_dns_ip.ipv4.sin_addr.s_addr, false, type, (uint16_t)port, res);
	if (retval < 0) {
		murata_1sc_freeaddrinfo(*res);
		LOG_ERR("Unable to set address info, retval: %d", retval);
		goto exit;
	}
#if defined(CONFIG_NET_IPV6)
	retval = set_addr_info(mdm_dns_ip.ipv6.sin6_addr.s6_addr, true, type, (uint16_t)port, res);
	if (retval < 0) {
		murata_1sc_freeaddrinfo(*res);
		LOG_ERR("Unable to set address info, retval: %d", retval);
		goto exit;
	}
#endif

exit:
	return retval;
}

static int sigStrength;
#define MIN_SS	-113
/**
 * @brief Handle the response to AT%CSQ
 *
 * Response format:
 * <RSSI (-113 + 2*n>,<BER>,<RSRQ>
 */
MODEM_CMD_DEFINE(on_cmd_csq)
{
	char buf[MAX_SIGSTR_RESP_SIZE];
	char *endp;
	int ret;
	size_t out_len = net_buf_linearize(buf, MAX_SIGSTR_RESP_SIZE-1,
			data->rx_buf, 0, len);
	buf[out_len] = '\0';

	for (int i = 0; i < MAX_SIGSTR_RESP_SIZE-1; i++) {
		if (buf[i] == ',') {
			buf[i] = 0;
			break;
		}
	}
	ret = (int)strtol(buf, &endp, 10);
	sigStrength = MIN_SS + 2 * ret;
	/* Log the received information. */
	LOG_DBG("signal strength: %d dBm", ret);
	return 0;
}

/**
 * @brief Get signal strength
 */
static int get_sigstrength(char *rbuf)
{
	const char at_cmd[] = "AT\%CSQ";
	int  ret;

	struct modem_cmd data_cmd[] = {
		MODEM_CMD("%CSQ:", on_cmd_csq, 0U, ""),
	};

	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, 1, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
		ret = -1;
	}
	snprintk(rbuf, MAX_SIGSTR_RESP_SIZE, "%d dBm", sigStrength);

	return ret;
}

/**
 * @brief Handle response to AT+CNUM
 *
 * +CNUM: ,"16186961148",129
 */
MODEM_CMD_DEFINE(on_cmd_cnum)
{
	char buf[32];
	int strlen = 0;
	size_t out_len = net_buf_linearize(buf, 31,
			data->rx_buf, 0, len);
	buf[out_len] = '\0';

	strlen = get_str_in_quotes(buf, mdata.mdm_phn, sizeof(mdata.mdm_phn));

	/* Log the received information. */
	//LOG_INF("got cnum: %s, str_len = %d", mdata.mdm_phn, strlen);
	return 0;
}

/**
 * @brief Get phone number
 */
static int get_cnum(char *rbuf)
{
	int ret;
	const char at_cmd[] = "AT+CNUM";
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("+CNUM:", on_cmd_cnum, 0U, ","),
	};

	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
		ret = -1;
	}
	memcpy(rbuf, mdata.mdm_phn, sizeof(mdata.mdm_phn));
	return ret;
}

/**
 * @brief Handler for CGCONTRDP
 *
 * Sample response:
 *
 * AT at%pdnrdp=1
 * %PDNRDP: 1,5,"iot.catm.mnc882.mcc311.gprs",25.181.129.55.255.255.255.240,25.181.129.49,10.177.0.34,10.177.0.210,,,,,,,,,
 */
MODEM_CMD_DEFINE(on_cmd_get_cgcontrdp)
{
#define PDN_BUF_SZ	256
	char pdn_buf[PDN_BUF_SZ];
	size_t out_len;
	int ret = 0;

	if (!got_pdn_flg) {
		got_pdn_flg = true;
		out_len = net_buf_linearize(pdn_buf, PDN_BUF_SZ-1, data->rx_buf, 0, len);
		pdn_buf[out_len] = '\0';
		LOG_DBG("PDNRDP-data (len=%d, strlen=%d, dat: %s\n", len, out_len, pdn_buf);
		ret = parse_ipgwmask(pdn_buf, mdata.mdm_ip, mdata.mdm_nmask, mdata.mdm_gw);
		/* Log the received information. */
		LOG_DBG("IP: %s, GW: %s, NMASK: %s", mdata.mdm_ip, mdata.mdm_gw, mdata.mdm_nmask);
	}
	return ret;
}

/**
 * @brief Get ip/mask/gw
 */
static int get_ip(char *rbuf)
{
	int ret;
	const char at_cmd[] = "AT+CGCONTRDP";
	got_pdn_flg = false;
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("+CGCONTRDP:", on_cmd_get_cgcontrdp, 0U, ","),
	};

	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
		data_cmd, ARRAY_SIZE(data_cmd), at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
		ret = -1;
	}
	snprintk(rbuf, MAX_IP_RESP_SIZE, "IP: %s, GW: %s, NMASK: %s", mdata.mdm_ip, mdata.mdm_gw, mdata.mdm_nmask);

	return ret;
}

/**
 * @brief Handler for modem firmware version
 */
MODEM_CMD_DEFINE(on_cmd_get_revision)
{
	size_t out_len = net_buf_linearize(mdata.mdm_revision,
			sizeof(mdata.mdm_revision) - 1,
			data->rx_buf, 0, len);
	mdata.mdm_revision[out_len] = '\0';

	/* Log the received information. */
	LOG_DBG("Revision: RK_%s", mdata.mdm_revision);
	return 0;
}

/**
 * @brief Get modem firmware version
 */
static int get_version(char *rbuf)
{
	int ret;
	const char at_cmd[] = "AT+CGMR";

	struct modem_cmd data_cmd[] = {
		MODEM_CMD("RK_", on_cmd_get_revision, 0U, ""),
	};

	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
		ret = -1;
	}
	memcpy(rbuf,"RK_", 3);
	memcpy(rbuf+3, mdata.mdm_revision, sizeof(mdata.mdm_revision)-3);
	return ret;
}

/**
 * @brief Handler for USIM info
 */
MODEM_CMD_DEFINE(on_cmd_get_usim)
{
	size_t out_len = net_buf_linearize(mdata.mdm_sim_info,
			sizeof(mdata.mdm_sim_info) - 1,
			data->rx_buf, 0, len);
	mdata.mdm_sim_info[out_len] = '\0';

	/* Log the received information. */
	LOG_DBG("USIM: %s", mdata.mdm_sim_info);
	return 0;
}

/**
 * @brief Get SIM info
 */
static int get_sim_info(char *rbuf)
{
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("USIM:", on_cmd_get_usim, 0U, ""),
	};

	const char at_cmd[] = "AT\%STATUS=\"USIM\"";
	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
		ret = -1;
	}
	memcpy(rbuf, mdata.mdm_sim_info, sizeof(mdata.mdm_sim_info));
	return ret;
}

/**
 * @brief Handler for "%PDNSET?"
 *
 * expected format (for IPv4):
 * %PDNSET: 1,CATM.T-MOBILE.COM,IP,,,,,0,0,0
 * for both IPv4 and IPv6:
 * %PDNSET: 1,CATM.T-MOBILE.COM,IPV4V6,,,,,0,0,0
 */
MODEM_CMD_DEFINE(on_cmd_pdnset)
{
	int ret = -1;

#define MAX_PDNSET_STR_SZ	128
	char resp_str[MAX_PDNSET_STR_SZ];
	size_t out_len = net_buf_linearize(resp_str, sizeof(resp_str) - 1,
			data->rx_buf, 0, len);
	resp_str[out_len] = '\0';

	/* Log the received information. */
	LOG_DBG("PDNSET: %s", resp_str);

	char *p1 = strchr(resp_str, ',');
	if (p1) {
		char *p2 = strchr(++p1, ',');
		if (p2) {
			len = MIN(p2 - p1, MDM_APN_LENGTH - 1);
			memcpy(mdata.mdm_apn, p1, len);
			mdata.mdm_apn[len] = '\0';
			ret = 0;
		}
	}
	return ret;
}

/**
 * @brief Get APN
 */
static int get_apn(char *rbuf)
{
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("%PDNSET:", on_cmd_pdnset, 0U, ""),
	};

	const char at_cmd[] = "AT\%PDNSET?";
	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
		ret = -1;
	} else {
		memcpy(rbuf, mdata.mdm_apn, sizeof(mdata.mdm_apn));
	}
	return ret;
}

/**
 * @brief Check whether modem is awake
 */
static int murata_1sc_is_awake(char *rbuf)
{
	/* TBD: Sample an input pin depending on current lowest-power mode
	 * For now, just return most recent action
	 * int ret = gpio_pin_get_dt(&wake_host_gpio);
	 */
	int ret = mdata.is_awake;
	if (ret) {
		strcpy(rbuf, "AWAKE");
	} else {
		strcpy(rbuf, "ASLEEP");
	}
	return ret;
}

/**
 * @brief Handler for AT%SETCFG="SC_STATE","1"
 */
MODEM_CMD_DEFINE(on_cmd_sc_state)
{
	return 0;
}

/**
 * @brief check whether current FW image is golden
 */
static int is_golden(char *rbuf)
{
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
		MODEM_CMD("%GETSYSCFG:", on_cmd_sc_state, 1U, "")
	};

	char at_cmd[] = "AT\%SETCFG=\"SC_STATE\",\"1\"";

	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), at_cmd,
			&mdata.sem_response, MDM_CMD_RSP_TIME);

	if (ret == -EIO) {
		strcpy(rbuf, "GOLDEN");
		return 0;
	} else if (ret >= 0) {
		strcpy(rbuf, "SAMPLE");
		return 1;
	} else {
		LOG_WRN("is_golden returned %d", ret);
	}
	return ret;
}

const struct socket_dns_offload murata_dns_ops = {
	.getaddrinfo = murata_1sc_getaddrinfo,
	.freeaddrinfo = murata_1sc_freeaddrinfo,
};

int murata_socket_offload_init(void)
{
	socket_offload_dns_register(&murata_dns_ops);
	return 0;
}

enum mdmdata_e {
	apn_e,
	awake_e,
	connsts_e,
	golden_e,
	iccid_e,
	imei_e,
	imsi_e,
	ip_e,
	msisdn_e,
	sim_info_e,
	sleep_e,
	ssi_e,
	version_e,
	wake_e,
	invalid
} mdmdata_e;

static int ioctl_query(enum mdmdata_e idx, void *buf)
{
	int ret = 0;

	if (buf == NULL) {
		errno = EINVAL;
		return -1;
	}

	switch(idx) {
		case imei_e:
		strcpy(buf, mdata.mdm_imei);
		break;
#if defined(CONFIG_MODEM_SIM_NUMBERS)
		case imsi_e:
		strcpy(buf, mdata.mdm_imsi);
		break;
		case iccid_e:
		strcpy(buf, mdata.mdm_iccid);
		break;
#endif
		case ssi_e:
		ret = get_sigstrength(buf);
		break;

		case msisdn_e:
		ret = get_cnum(buf);
		break;

		case connsts_e:
		ret = get_carrier(buf);
		break;

		case ip_e:
		ret = get_ip(buf);
		break;

		case version_e:
		ret = get_version(buf);
		break;

		case sim_info_e:
		ret = get_sim_info(buf);
		break;

		case apn_e:
		ret = get_apn(buf);
		break;

		case sleep_e:
		ret = set_cfun(0);
		break;

		case wake_e:
		ret = set_cfun(1);
		break;

		case awake_e:
		ret = murata_1sc_is_awake(buf);
		break;

		case golden_e:
		ret = is_golden(buf);
		break;

		default:
		LOG_ERR("invalid request");
		ret = -1;
		break;
	}
	return ret;
}

typedef int (*mdmdata_cb_t)(enum mdmdata_e atcmd, void *user_data);

struct mdmdata_cmd_t{
	char *str;
	enum mdmdata_e atcmd;
};

/**
 * using in_out_str as key to query modem data
 * response will be in in-out-str
 */
struct mdmdata_cmd_t cmd_pool[] = {
	{"APN",      apn_e},
	{"AWAKE",    awake_e},
	{"CONN_STS", connsts_e},
	{"CONN",     connsts_e},
	{"GOLD",     golden_e},
	{"GOLDEN",   golden_e},
	{"ICCID",    iccid_e},
	{"IMEI",     imei_e},
	{"IMSI",     imsi_e},
	{"IP",       ip_e},
	{"MSISDN",   msisdn_e},
	{"SLEEP",    sleep_e},
	{"SSI",      ssi_e},
	{"STAT",     connsts_e},
	{"SIM",      sim_info_e},
	{"VERSION",  version_e},
	{"VER",      version_e},
	{"WAKE",     wake_e},
	{}
};

static int get_mdmdata_resp(char* io_str)
{
	int ret = -1;
	int idx = 0;
	char *cmdStr;
	while (cmd_pool[idx].str != NULL) {
		cmdStr = cmd_pool[idx].str;
		if (strncmp(io_str, cmdStr, strlen(cmdStr)) == 0)
			break;
		++idx;
	}
	if (idx < (sizeof(cmd_pool)/sizeof(cmd_pool[0]) - 1)) {
		struct mdmdata_cmd_t cmd_entry = cmd_pool[idx];
		LOG_DBG("found cmd in pool, idx = %d\n", idx);
		ret = ioctl_query(cmd_entry.atcmd, io_str);
	} else {
		LOG_WRN("cmd (%s) not supported", io_str);
		idx = -1;
	}
	return ret;
}

struct aggr_ipv4_addr {	//for testing
	struct in_addr ip;
	struct in_addr gw;
	struct in_addr nmask;
};

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
/**
 * do not change order
 */
enum {
	SSL_CERTIFICATE_TYPE = 0,
	SSL_PRIVATE_KEY_TYPE,
	SSL_CA_CERTIFICATE_TYPE,
};

/* send binary data via the AT commands */
static ssize_t send_cert(struct modem_socket *sock,
		struct modem_cmd *handler_cmds,
		size_t handler_cmds_len,
		const char *cert_data,
		int cert_type,
		char* filename)
{
	int ret = 0;
	static int certfile_exist = -1;	//0 means yes
	int filename_len = strlen(filename);
	static char *certfile = NULL;
	static char *keyfile = NULL;
	int offset = CERTCMD_WRITE_SIZE - filename_len - 25;	//overhead of "WRITE",,, & 2.5 pairs of "" & 1 digit
	uint8_t *sptr = &cert_cmd_buf.cert_cmd_write[offset];

	if (!sock) {
		return -EINVAL;
	}

	/* TODO support other cert types as well */
	switch(cert_type) {
		case SSL_CERTIFICATE_TYPE:
		case SSL_CA_CERTIFICATE_TYPE:
			certfile = filename;
			if (SSL_CERTIFICATE_TYPE == cert_type) {
				certfile_exist = check_mdm_store_file(filename);
			}
			break;
		case SSL_PRIVATE_KEY_TYPE:
			keyfile = filename;
			break;
		default:
			LOG_WRN("Bad cert_type %d", cert_type);
			goto exit;
	}

	__ASSERT_NO_MSG(cert_len <= MDM_MAX_CERT_LENGTH);

	if (certfile_exist != 0) {
		snprintk(sptr, sizeof(cert_cmd_buf),
				"AT%%CERTCMD=\"WRITE\",\"%s\",%d,\"", filename, cert_type%2);
		cert_cmd_buf.pem_buf[0] = '-';	//amend the pem[0] overwritten by snprintk
		LOG_DBG("sptr: %s", sptr);
		ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, NULL, 0U,
				sptr, &mdata.sem_response, MDM_CMD_LONG_RSP_TIME);
		if (ret < 0) {
			if (ret == -116) {
				ret = 0;	//fake good ret
			} else {
				goto exit;
			}
		}
	}

	if (cert_type == SSL_PRIVATE_KEY_TYPE) {
		k_sleep(K_MSEC(20));	//brief brake?
		snprintk(cert_cmd_buf.cert_cmd_write, sizeof(cert_cmd_buf.cert_cmd_write),
				"AT%%CERTCFG=\"ADD\",8,,,\"%s\",\"%s\"", certfile, keyfile);

		LOG_DBG("certcfg: %s", cert_cmd_buf.cert_cmd_write);
		ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
				NULL, 0U, cert_cmd_buf.cert_cmd_write,
				&mdata.sem_response, MDM_CMD_LONG_RSP_TIME);
		if (ret < 0) {
			LOG_ERR("failure, sendmdmcmd,ret = %d", ret);
			goto exit;
		}
	} else if (cert_type == SSL_CA_CERTIFICATE_TYPE) {
		k_sleep(K_MSEC(20));	//brief brake?
		snprintk(cert_cmd_buf.cert_cmd_write, sizeof(cert_cmd_buf.cert_cmd_write),
				"AT%%CERTCFG=\"ADD\",8,\"%s\",\".\"", certfile);

		LOG_DBG("certcfg: %s", cert_cmd_buf.cert_cmd_write);
		ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
				NULL, 0U, cert_cmd_buf.cert_cmd_write,
				&mdata.sem_response, MDM_CMD_LONG_RSP_TIME);
		if (ret < 0) {
			LOG_ERR("sendmdmcmd,ret = %d", ret);
			goto exit;
		}
	}

exit:
	/* unset handler commands and ignore any errors */
	(void)modem_cmd_handler_update_cmds(&mdata.cmd_handler_data,
			NULL, 0U, false);
	return ret;
}

static int map_credentials(struct modem_socket *sock, const void *optval, socklen_t optlen)
{
	sec_tag_t *sec_tags = (sec_tag_t *)optval;
	int retval = 0;
	int tags_len;
	sec_tag_t tag;
	int cert_type;
	int i;
	struct tls_credential *cert;

	if ((optlen % sizeof(sec_tag_t)) != 0 || (optlen == 0)) {
		return -EINVAL;
	}

	tags_len = optlen / sizeof(sec_tag_t);
	/* For each tag, retrieve the credentials value and type: */
	for (i = 0; i < tags_len; i++) {
		char *filename = NULL;
		uint8_t cert_idx;
		int offset;
		char *header, *footer;
		tag = sec_tags[i];
		cert = credential_next_get(tag, NULL);
		while (cert != NULL) {
			switch (cert->type) {
				case TLS_CREDENTIAL_SERVER_CERTIFICATE:
					cert_type = SSL_CERTIFICATE_TYPE;
					header = "-----BEGIN CERTIFICATE-----\n";
					footer = "\n-----END CERTIFICATE-----\"\n";
					filename = CONFIG_USER_CERT_FILE;
					break;
				case TLS_CREDENTIAL_PRIVATE_KEY:
					cert_type = SSL_PRIVATE_KEY_TYPE;
					header = "-----BEGIN RSA PRIVATE KEY-----\n";
					footer = "\n-----END RSA PRIVATE KEY-----\"\n";
					filename = CONFIG_USER_PRIVATEKEY_FILE;
					break;
				case TLS_CREDENTIAL_CA_CERTIFICATE:
					cert_type = SSL_CA_CERTIFICATE_TYPE;
					header = "-----BEGIN CERTIFICATE-----\n";
					footer = "\n-----END CERTIFICATE-----\"\n";
					cert_idx = 0;
					filename = CONFIG_USER_CA_FILE;
					break;
				case TLS_CREDENTIAL_NONE:
				case TLS_CREDENTIAL_PSK:
				case TLS_CREDENTIAL_PSK_ID:
				default:
					retval = -EINVAL;
					goto exit;
			}

			strcpy(cert_cmd_buf.pem_buf, header);
			offset = strlen(header);
			size_t written;
			base64_encode(cert_cmd_buf.pem_buf + offset, PEM_BUFF_SIZE - offset - strlen(footer), &written, cert->buf, cert->len);
			memcpy(cert_cmd_buf.pem_buf + offset + written, footer, strlen(footer));
			cert_cmd_buf.pem_buf[offset + written + strlen(footer)] = 0;	//null terminate

			LOG_DBG("offset= %d; written = %d\n", offset, written);

			{	//write cert to murata with filename
				retval = send_cert(sock, NULL, 0, cert_cmd_buf.pem_buf, cert_type, filename);
				if (retval < 0) {
					LOG_ERR("Failed to send cert to modem, ret = %d", retval);
					return retval;
				}
			}

			cert = credential_next_get(tag, cert);	//should be key
		}
	}
exit:
	return retval;
}
#else
static int map_credentials(struct modem_socket *sock, const void *optval, socklen_t optlen)
{
	return -EINVAL;
}
#endif

static int offload_setsockopt(void *obj, int level, int optname,
		const void *optval, socklen_t optlen)
{
	int retval = -1;

#if !defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	errno = -ENOTSUP;
	return retval;
#else
	int sd;
	struct modem_socket *sock = (struct modem_socket *) obj;

	if (level == SOL_TLS) {
		/* Handle Zephyr's SOL_TLS secure socket options: */
		switch (optname) {
			case TLS_SEC_TAG_LIST:
				/* Bind credential filenames to this socket: */
				retval = map_credentials(obj, optval, optlen);
				break;
			case TLS_PEER_VERIFY:
				if (optval) {
					/*
					 * Not currently supported. Verification
					 * is automatically performed if a CA
					 * certificate is set. We are returning
					 * success here to allow
					 * mqtt_client_tls_connect()
					 * to proceed, given it requires
					 * verification and it is indeed
					 * performed when the cert is set.
					 */
					if (*(uint32_t *)optval != 2U) {
						errno = ENOTSUP;
						return -1;
					} else {
						retval = 0;
					}
				} else {
					errno = EINVAL;
					return -1;
				}
				break;
			case TLS_HOSTNAME:
				sd = sock->sock_fd;
				LOG_DBG("set SNI - name %s with len %d, for sock# %d", (char *)optval, optlen, sd);
				servername_desc[sd].sni_valid = true;
				servername_desc[sd].host[0] = 0;
				strncat(servername_desc[sd].host, optval, MIN(optlen, MAX_FILENAME_LEN));
				retval = 0;
				break;
			case TLS_CIPHERSUITE_LIST: //?SO_SSL_V_1_2_ENABLE...
			case TLS_DTLS_ROLE:
				errno = ENOTSUP;
				return -1;
			default:
				errno = EINVAL;
				return -1;
		}
	} else {
		return -1;
	}
	return retval;
#endif
}

/**
 * Direct FW update support functions (not via LwM2M)
 *
 * FW updates basically work like this:
 * 1. Get the FW file into the host device FLASH or memory
 * 2. Xfer the FW file to the modem
 * 2a. Xfer the header (first 256 bytes)
 * 2b. Xfer remaining chunks of the FW file
 * 3. Tell the modem to perform the update
 * 4. Reset the modem and wait for update to complete
 */

/**
 * @brief Initiate FW transfer from host to device
 *
 * @param file is the filename of the FW file
 *
 * @return OK or ERROR
 *
 * send_buf = 'AT%FILECMD="PUT","' + str(rfile) + '",1,' + str(len(csbuffer)) + ',"' + str(cksum) + '"'
 */
static int init_fw_xfer(struct init_fw_data_t *ifd)
{
	char at_cmd[64];

	snprintk(at_cmd, sizeof(at_cmd), "AT%%FILECMD=\"PUT\",\"%s\",1, %u, \"%u\"",
		ifd->imagename, (uint32_t)ifd->imagesize, (uint32_t)ifd->imagecrc);

	LOG_WRN("\tinit_fw_xfer: at cmd = %s", at_cmd);
	printk("\tinit_fw_xfer: at cmd = %s\n", at_cmd);

	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			NULL, 0U, at_cmd, &mdata.sem_response, MDM_CMD_RSP_TIME);

	LOG_DBG("\tinit_fw_xfer: ret = %d", ret);

	if (ret < 0) {
		LOG_ERR("%s ret:%d", at_cmd, ret);
	}
	return ret;
}

MODEM_CMD_DEFINE(on_cmd_upgcmd)
{
	return ATOI(argv[1], 0, "diu_result");
}

#define FW_HEADER_SIZE 256

/**
 * @brief send first chunk of FW file data to the modem (256 bytes)
 *
 * @param data is ptr to chunk of binary data
 *
 * @return diu_result:
 *    0 - successfully finished software upgrade step (image pre-check, update, etc.)
 *    1 - general upgrade errors
 *    2 - failed to the pre-checking of delta image
 *    3 - image validation failure
 *    4 - failed to update
 *    5 - delta update Agent was not found
 *    6 - no upgrade result is found
 *
 * send_buf = 'AT%UPGCMD="CFGPART","' + interim_map_str + '"'
 */
static int send_fw_header(const char *data)
{
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
		MODEM_CMD("%UPGCMD:", on_cmd_upgcmd, 1U, "")
	};

	k_sem_take(&mdata.sem_xlate_buf, K_FOREVER);

	/* Create the command prefix */
	int i = snprintk(mdata.xlate_buf, sizeof(mdata.xlate_buf), "AT%%UPGCMD=\"CFGPART\",\"");

	/* Add the hex string */
	data_to_hex_str(data, FW_HEADER_SIZE, &mdata.xlate_buf[i], sizeof(mdata.xlate_buf) - i);

	/* Finish the command */
	snprintk(&mdata.xlate_buf[i + FW_HEADER_SIZE * 2], sizeof(mdata.xlate_buf), "\"");

	LOG_DBG("Header => %s\n", (char*) mdata.xlate_buf);

	/* Send the command */
	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), mdata.xlate_buf,
			&mdata.sem_response, MDM_CMD_RSP_TIME);

	k_sem_give(&mdata.sem_xlate_buf);

	return ret;
}

MODEM_CMD_DEFINE(on_cmd_filedata)
{
	return ATOI(argv[1], 0, "written") / 2;
}

/**
 * @brief Send a chunk of FW file data to the modem
 *
 * @param data is ptr to raw data
 * @param more is 0 if this is the last chunk, 1 otherwise
 * @param len is len of raw data, must be <= MDM_MAX_DATA_LENGTH (1500)
 *
 * @return bytes written, or ERROR
 *
 * send_buf = 'AT%FILEDATA="WRITE",0' + ',' + str(display_sz) + ',"' + (out_hexstr) + '"'
 */
static int send_fw_data(const struct send_fw_data_t *sfd)
{
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
		MODEM_CMD("%FILEDATA:", on_cmd_filedata, 1U, "")
	};

	if (sfd->len <= 0 || sfd->len > MDM_MAX_DATA_LENGTH) {
                return -1;
	}

	k_sem_take(&mdata.sem_xlate_buf, K_FOREVER);

	/* Create the command prefix */
	int i = snprintk(mdata.xlate_buf, sizeof(mdata.xlate_buf), "AT%%FILEDATA=\"WRITE\",%d,%d,\"", sfd->more, sfd->len * 2);

	/* Add the hex string */
	data_to_hex_str(sfd->data, sfd->len, &mdata.xlate_buf[i], sizeof(mdata.xlate_buf) - i);

	/* Finish the command */
	snprintk(&mdata.xlate_buf[i + sfd->len * 2], sizeof(mdata.xlate_buf), "\"");

	LOG_DBG("Cmd %s\n", (char*) mdata.xlate_buf);
	if (sfd->more == 0) {
		LOG_DBG("Done Cmd %s\n", (char*) mdata.xlate_buf);
	} else {
		LOG_DBG("Cmd %s\n", (char*) mdata.xlate_buf);
	}

	/* Send the command */
	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), mdata.xlate_buf,
			&mdata.sem_response, MDM_CMD_LONG_RSP_TIME);

	k_sem_give(&mdata.sem_xlate_buf);

	if (sfd->more == 0) {
		LOG_DBG("Done Cmd results %d\n", ret);
	} else {
		LOG_DBG("Cmd results %d\n", ret);
	}

	return ret;
}

/**
 * @brief Initiate FW upgrade after FW file has been xfer'ed to modem
 *
 * @param file is the filename of the FW file to use for upgrading
 *
 * @return diu_result:
 *    0 - successfully finished software upgrade step (image pre-check, update, etc.)
 *    1 - general upgrade errors
 *    2 - failed to the pre-checking of delta image
 *    3 - image validation failure
 *    4 - failed to update
 *    5 - delta update Agent was not found
 *    6 - no upgrade result is found
 *
 * send_buf = 'AT%UPGCMD="UPGVRM","' + lfile + '"'
 */
static int init_fw_upgrade(const char *file)
{
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
		MODEM_CMD("%UPGCMD:", on_cmd_upgcmd, 1U, "")
	};

	char at_cmd[64];
	snprintk(at_cmd, sizeof(at_cmd), "AT%%UPGCMD=\"UPGVRM\",\"%s\"", file);

        LOG_DBG("init_fw_upgrade: at cmd = %s", at_cmd);

	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), at_cmd,
			&mdata.sem_response, MDM_CMD_RSP_TIME);

	LOG_DBG("Ret %d", ret);

	if (ret < 0) {
		LOG_ERR("%s ret: %d", at_cmd, ret);
	}
	return ret;
}

static char chksum[CHKSUM_ABILITY_MAX_LEN];

MODEM_CMD_DEFINE(on_cmd_chksum)
{
	size_t out_len = net_buf_linearize(chksum, sizeof(chksum) - 1,
			data->rx_buf, 0, len);
	chksum[out_len] = '\0';
	return 0;
}

/**
 * @brief check whether file checksum is supported
 *
 * @param response is the response received from the request
 * @return OK or ERROR
 *
 * send_buf = 'AT%GETACFG=filemgr.file.put_fcksum'
 */
static int get_file_chksum_ability(char *response)
{
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
		MODEM_CMD("", on_cmd_chksum, 1U, "")
	};

	const char at_cmd[] = "AT\%GETACFG=filemgr.file.put_fcksum";

	chksum[0] = '\0';
	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), at_cmd,
			&mdata.sem_response, MDM_CMD_RSP_TIME);

	if (ret < 0) {
		LOG_ERR("%s ret: %d", at_cmd, ret);
	}
	else {
		snprintk(response, CHKSUM_ABILITY_MAX_LEN, "%s", chksum);
	}
	return ret;
}

static char file_cmd_full_access[CMD_FULL_ACCESS_MAX_LEN];

MODEM_CMD_DEFINE(on_cmd_file_cmd_full_access)
{
	size_t out_len = net_buf_linearize(file_cmd_full_access, sizeof(file_cmd_full_access) - 1,
			data->rx_buf, 0, len);
	file_cmd_full_access[out_len] = '\0';
	return 0;
}

/**
 * @brief check setting of admin.services.file_cmd_full_access
 *
 * @param response is the response received from the request
 * @return OK or ERROR
 *
 * send_buf = 'AT%GETACFG=admin.services.file_cmd_full_access'
 */
static int get_file_mode(char *response)
{
	struct modem_cmd data_cmd[] = {
		MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
		MODEM_CMD("", on_cmd_file_cmd_full_access, 1U, "")
	};

	char at_cmd[] = "AT\%GETACFG=admin.services.file_cmd_full_access";

	file_cmd_full_access[0] = '\0';
	int ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			data_cmd, ARRAY_SIZE(data_cmd), at_cmd,
			&mdata.sem_response, MDM_CMD_RSP_TIME);

	if (ret < 0) {
		LOG_ERR("%s ret: %d", at_cmd, ret);
	} else {
		snprintk(response, CMD_FULL_ACCESS_MAX_LEN, "%s", file_cmd_full_access);
	}
	return ret;
}

/**
 * @brief Initial setup of the modem
 */
static int murata_1sc_setup(void)
{
	gpio_pin_set_dt(&reset_gpio, 1);
	k_sleep(K_MSEC(20));
	gpio_pin_set_dt(&reset_gpio, 0);

	gpio_pin_set_dt(&wake_mdm_gpio, 1);
	LOG_INF("Waiting %d secs for modem to boot...", MDM_BOOT_DELAY);
	k_sleep(K_SECONDS(MDM_BOOT_DELAY));

	const struct setup_cmd setup_cmds[] = {
		SETUP_CMD_NOHANDLE("ATQ0"),
		SETUP_CMD_NOHANDLE("ATE0"),
		SETUP_CMD_NOHANDLE("ATV1"),
		SETUP_CMD_NOHANDLE("AT%CSDH=1"),
		SETUP_CMD_NOHANDLE("AT+CNMI=2,1,2,1,0"),
		// SETUP_CMD_NOHANDLE("AT+COPS=3,1"),
		SETUP_CMD("AT+CGMI", "", on_cmd_get_manufacturer, 0U, ""),
		SETUP_CMD("AT+CGMM", "", on_cmd_get_model, 0U, ""),
		SETUP_CMD("AT+CGMR", "RK_", on_cmd_get_revision, 0U, ""),
		SETUP_CMD("AT+CGSN", "", on_cmd_get_imei, 0U, ""),
#if defined(CONFIG_MODEM_SIM_NUMBERS)
		SETUP_CMD("AT+CIMI", "", on_cmd_get_imsi, 0U, ""),
		SETUP_CMD("AT%CCID", "%CCID:", on_cmd_get_iccid, 0U, " "),
#endif
		SETUP_CMD("AT%GETACFG=modem_apps.Mode.AutoConnectMode", "", on_cmd_get_acfg, 0U, ""),
		SETUP_CMD("AT%GETCFG=\"BAND\"", "Bands:", on_cmd_get_bands, 0U, ""),
#ifdef VERIFY_INIT_MODEM_STATE
		SETUP_CMD("AT%STATUS=\"USIM\"", "USIM:", on_cmd_get_usim, 0U, ""),
		SETUP_CMD("AT+CFUN?", "+CFUN:", on_cmd_get_cfun, 0U, ""),
		SETUP_CMD("AT+CEREG?", "+CEREG:", on_cmd_get_cereg, 0U, ""),
		SETUP_CMD("AT+CGCONTRDP", "+CGCONTRDP:", on_cmd_get_cgcontrdp, 0U, ""),
#endif
#if defined(CONFIG_MODEM_DEMO_LOW_POWERMODE)
		SETUP_CMD_NOHANDLE("AT+CFUN=0"),
#endif
	};

top: ;
	/* Run setup commands on the modem. */
	int ret = modem_cmd_handler_setup_cmds(&mctx.iface, &mctx.cmd_handler,
			setup_cmds, ARRAY_SIZE(setup_cmds),
			&mdata.sem_response, MDM_REGISTRATION_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("modem_cmd_handler_setup_cmds error");
	}

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	ret = post_mdm_init();
	if (ret < 0) {
		LOG_ERR("post modem_cmd_init error");
	}
#endif
	set_pdnset();
	set_bands();
	set_boot_delay();
	enable_sleep_mode(false);
	set_max_allowed_pm_mode("dh2");
		
	bool needto_reset_modem = false;
	if (needto_set_autoconn_to_true) {
		set_autoconn_on();
		needto_reset_modem = true;
	}

	if (needto_reset_modem) {
		reset_modem();
		goto top;
	}

#if !defined(CONFIG_MODEM_DEMO_LOW_POWERMODE)
	k_sleep(K_MSEC(CONFIG_MODEM_ON_DELAY));
	set_cfun(1);
#endif

	return ret;
}

/**
 * @brief ioctl handler to handle various requests
 * 
 * @param obj ptr to socket
 * @param request type
 * @param args parameter
 */
static int offload_ioctl(void *obj, unsigned int request, va_list args)
{
	int ret;
	struct aggr_ipv4_addr *a_ipv4_addr;
	char *cmd_str;

	// TBD: cast obj to socket, find the right instance of the murata_1sc_data etc
	// assuming one instance for now

	switch (request) {
		case F_GETFL:
			return 0; //Always report that we're a blocking socket
		case ZFD_IOCTL_POLL_PREPARE: {
			struct zsock_pollfd *pfd;
			struct k_poll_event **pev;
			struct k_poll_event *pev_end;

			pfd = va_arg(args, struct zsock_pollfd *);
			pev = va_arg(args, struct k_poll_event **);
			pev_end = va_arg(args, struct k_poll_event *);

			return modem_socket_poll_prepare(&mdata.socket_config, obj, pfd, pev, pev_end);
		}

		case ZFD_IOCTL_POLL_UPDATE: {
			struct zsock_pollfd *pfd;
			struct k_poll_event **pev;

			pfd = va_arg(args, struct zsock_pollfd *);
			pev = va_arg(args, struct k_poll_event **);

			return modem_socket_poll_update(obj, pfd, pev);
		}

		case SMS_SEND:
			ret = send_sms_msg(obj, (struct sms_out *)va_arg(args, struct sms_out *));
			va_end(args);
			break;

		case SMS_RECV:
			ret = recv_sms_msg(obj, (struct sms_in *)va_arg(args, struct sms_in *));
			va_end(args);
			break;

		case GET_IPV4_CONF:
			a_ipv4_addr = va_arg(args, struct aggr_ipv4_addr*);
			va_end(args);
			get_ipv4_config();
			inet_pton(AF_INET, mdata.mdm_ip, &a_ipv4_addr->ip);
			inet_pton(AF_INET, mdata.mdm_gw, &a_ipv4_addr->gw);
			inet_pton(AF_INET, mdata.mdm_nmask, &a_ipv4_addr->nmask);
			ret = 0;
			break;

		case GET_ATCMD_RESP:
			cmd_str = (char *)va_arg(args, char *);
			va_end(args);
			ret = get_mdmdata_resp(cmd_str);
			break;

		case INIT_FW_XFER:
			ret = init_fw_xfer((struct init_fw_data_t *)va_arg(args, struct init_fw_data_t *));
			va_end(args);
			break;

		case SEND_FW_HEADER:
			ret = send_fw_header((char *)va_arg(args, char *));
			va_end(args);
			break;

		case SEND_FW_DATA:
			ret = send_fw_data((struct send_fw_data_t *)va_arg(args, struct send_fw_data_t *));
			va_end(args);
			break;

		case INIT_FW_UPGRADE:
			ret = init_fw_upgrade((char *)va_arg(args, char *));
			va_end(args);
			break;

		case GET_CHKSUM_ABILITY:
			ret = get_file_chksum_ability((char *)va_arg(args, char *));
			va_end(args);
			break;

		case GET_FILE_MODE:
			ret = get_file_mode((char *)va_arg(args, char *));
			va_end(args);
			break;

		case RESET_MODEM:
			ret = reset_modem();
			break;

		default:
			errno = EINVAL;
			ret = -1;
			break;
	}
	return ret;
}

static const struct socket_op_vtable offload_socket_fd_op_vtable = {
	.fd_vtable = {
		.read = offload_read,
		.write = offload_write,
		.close = offload_close,
		.ioctl = offload_ioctl,
	},
	.bind = offload_bind,
	.connect = offload_connect,
	.sendto = offload_sendto,
	.recvfrom = offload_recvfrom,
	.listen = NULL,
	.accept = NULL,
	.sendmsg = offload_sendmsg,
	.getsockopt = NULL,
	.setsockopt = offload_setsockopt,
};

/*
 * @brief Initialize the driver
 */
static int murata_1sc_init(const struct device *dev)
{
	int ret = 0;

	ARG_UNUSED(dev);

	k_sem_init(&mdata.sem_response,	 0, 1);
	k_sem_init(&mdata.sem_sock_conn, 0, 1);
	k_sem_init(&mdata.sem_xlate_buf, 1, 1);
	k_sem_init(&mdata.sem_sms,       0, 1);

	/* socket config */
	mdata.socket_config.sockets = &mdata.sockets[0];
	mdata.socket_config.sockets_len = ARRAY_SIZE(mdata.sockets);
	mdata.socket_config.base_socket_num = MDM_BASE_SOCKET_NUM;
	ret = modem_socket_init(&mdata.socket_config,
			&offload_socket_fd_op_vtable);
	if (ret < 0) {
		// goto error;
	}

	/* cmd handler */
	mdata.cmd_handler_data.cmds[CMD_RESP] = response_cmds;
	mdata.cmd_handler_data.cmds_len[CMD_RESP] = ARRAY_SIZE(response_cmds);
	mdata.cmd_handler_data.cmds[CMD_UNSOL] = unsol_cmds;
	mdata.cmd_handler_data.cmds_len[CMD_UNSOL] = ARRAY_SIZE(unsol_cmds);
	mdata.cmd_handler_data.match_buf = &mdata.cmd_match_buf[0];
	mdata.cmd_handler_data.match_buf_len = sizeof(mdata.cmd_match_buf);
	mdata.cmd_handler_data.buf_pool = &mdm_recv_pool;
	mdata.cmd_handler_data.alloc_timeout = K_NO_WAIT;
	mdata.cmd_handler_data.eol = "\r\n";
	ret = modem_cmd_handler_init(&mctx.cmd_handler,
			&mdata.cmd_handler_data);
	if (ret < 0) {
		// goto error;
	}

	/* modem interface */
	mdata.iface_data.rx_rb_buf     = &mdata.iface_rb_buf[0];
	mdata.iface_data.rx_rb_buf_len = sizeof(mdata.iface_rb_buf);
	ret = modem_iface_uart_init(&mctx.iface, &mdata.iface_data,
			DEVICE_DT_GET(DT_INST_BUS(0)));
	if (ret < 0) {
		// goto error;
	}

	/* modem data storage */
	mctx.data_manufacturer = mdata.mdm_manufacturer;
	mctx.data_model = mdata.mdm_model;
	mctx.data_revision = mdata.mdm_revision;
	mctx.data_imei = mdata.mdm_imei;

	/* SMS functions */
	mctx.send_sms = send_sms_msg;
	mctx.recv_sms = recv_sms_msg;
	mctx.driver_data = &mdata;

	/* pin setup */
	ret = gpio_pin_configure_dt(&wake_host_gpio, GPIO_INPUT);
	if (ret < 0) {
		LOG_ERR("Failed to configure %s pin", "wake_host");
		goto error;
	}

	ret = gpio_pin_configure_dt(&wake_mdm_gpio, GPIO_OUTPUT_LOW);
	if (ret < 0) {
		LOG_ERR("Failed to configure %s pin", "wake_mdm");
		goto error;
	}

	ret = gpio_pin_configure_dt(&reset_gpio, GPIO_OUTPUT_LOW);
	if (ret < 0) {
		LOG_ERR("Failed to configure %s pin", "reset");
		goto error;
	}

	ret = gpio_pin_configure_dt(&rst_done_gpio, GPIO_INPUT);
	if (ret < 0) {
		LOG_ERR("Failed to configure %s pin", "reset done");
		goto error;
	}

	ret = gpio_pin_configure_dt(&mdm_rx_gpio, GPIO_INPUT);
	if (ret < 0) {
		LOG_ERR("Failed to configure %s pin", "mdm_rx");
		goto error;
	}

	ret = gpio_pin_configure_dt(&mdm_tx_gpio, GPIO_OUTPUT_LOW);
	if (ret < 0) {
		LOG_ERR("Failed to configure %s pin", "reset");
		goto error;
	}

	ret = modem_context_register(&mctx);
	if (ret < 0) {
		LOG_ERR("Error registering modem context: %d", ret);
		goto error;
	}

	/* start RX thread */
	k_thread_create(&modem_rx_thread, modem_rx_stack,
			K_KERNEL_STACK_SIZEOF(modem_rx_stack),
			(k_thread_entry_t) murata_1sc_rx,
			NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);

	murata_1sc_setup();


error:
	return 0;
}

#if defined(CONFIG_NET_SOCKETS_OFFLOAD)
static int net_offload_dummy_get(sa_family_t family,
				 enum net_sock_type type,
				 enum net_ip_protocol ip_proto,
				 struct net_context **context)
{

	LOG_ERR("CONFIG_NET_SOCKETS_OFFLOAD must be enabled for this driver");
	return -ENOTSUP;
}

/* placeholders, until Zephyr IP stack updated to handle a NULL net_offload */
static struct net_offload modem_net_offload = {
	.get = net_offload_dummy_get,
};
#endif

/* @brief Setup the Modem NET Interface. */
static void murata_1sc_net_iface_init(struct net_if *iface)
{
	const struct device *dev = net_if_get_device(iface);
	struct murata_1sc_data *data	 = dev->data;

	/* Direct socket offload used instead of net offload: */
	net_if_set_link_addr(iface, murata_1sc_get_mac(dev),
			sizeof(data->mac_addr),
			NET_LINK_ETHERNET);
	data->net_iface = iface;
#if defined(CONFIG_NET_SOCKETS_OFFLOAD)
	iface->if_dev->offload = &modem_net_offload;
	iface->if_dev->socket_offload = offload_socket;
	murata_socket_offload_init();
#endif

}

static struct net_if_api api_funcs = {
	.init = murata_1sc_net_iface_init,
};

/**
 * @brief Used during registration to indicate that offload is supported
 */
static bool offload_is_supported(int family, int type, int proto)
{
	return true;
}

/**
 * @brief Register the device with the Networking stack
 */
NET_DEVICE_DT_INST_OFFLOAD_DEFINE(0, murata_1sc_init, NULL,
		&mdata, NULL,
		80,
		&api_funcs, MDM_MAX_DATA_LENGTH);

		/* Register NET sockets. */
		NET_SOCKET_REGISTER(murata_1sc, NET_SOCKET_DEFAULT_PRIO, AF_INET, offload_is_supported, offload_socket);

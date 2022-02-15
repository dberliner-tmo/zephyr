

#define DT_DRV_COMPAT murata_1sc

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#include <logging/log.h>
#include <stdlib.h>
#include <kernel.h>
#include <device.h>
#include <sys/ring_buffer.h>
#include <sys/util.h>
#include <net/ppp.h>
//#include <drivers/gsm_ppp.h>
#include <drivers/uart.h>
#include <drivers/console/uart_mux.h>

#include "murata-1sc.h"
#include "modem_context.h"
#include "modem_receiver.h"
#include "modem_iface_uart.h"
#include "modem_socket.h"
#include "modem_cmd_handler.h"
#include "../console/gsm_mux.h"
#include "modem_sms.h"
#include "strnstr.h"
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#include <net/tls_credentials.h>
#include <sys/base64.h>
#include "tls_internal.h"
#endif

#define NO_WAIT_FOR_DATA_READY

static size_t data_to_hex_str(const void* input_buf, size_t input_len, char* output_buf, size_t output_len) {
    size_t i;

    for (i = 0; (i < (output_len - 1) / 2) && (i < input_len); i++) {
        snprintf(&output_buf[(i * 2)], output_len, "%02X", ((uint8_t*)input_buf)[i]);
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

static size_t hex_str_to_data(const char* input_buf, uint8_t* output_buf, size_t output_len) {
    size_t str_len = strlen(input_buf);
    size_t i = 0;

    for (i = 0; (i < output_len) && (i * 2 < str_len); i++) {
        output_buf[i] = hex_byte_to_data(&input_buf[i * 2]);
    }
    return i;
}

//LOG_MODULE_REGISTER(murata_1sc, CONFIG_MODEM_LOG_LEVEL);
LOG_MODULE_REGISTER(murata_1sc);

#define LOG_LEVEL CONFIG_MODEM_LOG_LEVEL

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

	/* Semaphore(s) */
	struct k_sem sem_response;
	struct k_sem sem_sock_conn;
	struct k_sem sem_xlate_buf;
        struct k_sem sem_sms;

        /* SMS message support */
        int sms_index;
        struct sms_in *sms;
        recv_sms_func_t recv_sms;
}; 

/* Modem pins - Power, Reset & others. */
static struct modem_pin murata_1sc_pins[] = {
	/* MDM_WAKE_HOST */
	MODEM_PIN(DT_INST_GPIO_LABEL(0, mdm_wake_host_gpios),
		  DT_INST_GPIO_PIN(0, mdm_wake_host_gpios),
		  DT_INST_GPIO_FLAGS(0, mdm_wake_host_gpios) | GPIO_OUTPUT_LOW),

	/* MDM_WAKE_MODEM */
	MODEM_PIN(DT_INST_GPIO_LABEL(0, mdm_wake_mdm_gpios),
		  DT_INST_GPIO_PIN(0, mdm_wake_mdm_gpios),
		  DT_INST_GPIO_FLAGS(0, mdm_wake_mdm_gpios) | GPIO_OUTPUT_LOW),

	/* MDM_RESET */
	MODEM_PIN(DT_INST_GPIO_LABEL(0, mdm_reset_gpios),
		  DT_INST_GPIO_PIN(0, mdm_reset_gpios),
		  DT_INST_GPIO_FLAGS(0, mdm_reset_gpios) | GPIO_OUTPUT_LOW),
};

static struct k_thread	       modem_rx_thread;
//static struct k_work_q       modem_workq;
static struct murata_1sc_data  mdata;
static struct modem_context    mctx;
static const struct socket_op_vtable offload_socket_fd_op_vtable;

static void socket_close(struct modem_socket *sock);

/* RX thread structures */
static K_KERNEL_STACK_DEFINE(modem_rx_stack, CONFIG_MODEM_MURATA_1SC_RX_STACK_SIZE);
//static K_KERNEL_STACK_DEFINE(modem_workq_stack, CONFIG_MODEM_QUECTEL_BG9X_RX_WORKQ_STACK_SIZE);
NET_BUF_POOL_DEFINE(mdm_recv_pool, MDM_RECV_MAX_BUF, MDM_RECV_BUF_SIZE, 0, NULL);


/* Func: murata_1sc_rx
 * Desc: Thread to process all messages received from the Modem.
 */
static void murata_1sc_rx(void)
{
	while (true) {
		/* Wait for incoming data */
		k_sem_take(&mdata.iface_data.rx_sem, K_FOREVER);

		mctx.cmd_handler.process(&mctx.cmd_handler, &mctx.iface);
	}
}

/* Func: murata_1sc_atoi
 * Desc: Convert string to long integer, but handle errors
 */
static int murata_1sc_atoi(const char *s, const int err_value,
		           const char *desc, const char *func)
{
	int   ret;
	char  *endptr;

	ret = (int)strtol(s, &endptr, 10);
	if (!endptr || *endptr != '\0') {
		LOG_ERR("bad %s '%s' in %s", log_strdup(s), log_strdup(desc),
			log_strdup(func));
		return err_value;
	}

	return ret;
}

static inline uint32_t hash32(char *str, int len)
{
#define HASH_MULTIPLIER		37

	uint32_t h = 0;
	int i;

	for (i = 0; i < len; ++i) {
		h = (h * HASH_MULTIPLIER) + str[i];
	}

	return h;
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

static inline uint8_t *murata_1sc_get_mac(const struct device *dev)
{
	struct murata_1sc_data *data = dev->data;

    /* use the last 12 digits of the IMEI as the mac address */
    for (int i=0;i<6;i++) {
    	data->mac_addr[i] = (hex_char_to_int(mdata.mdm_imei[MDM_IMEI_LENGTH - 1 - 12 + (i * 2)    ]) << 4) |
                            (hex_char_to_int(mdata.mdm_imei[MDM_IMEI_LENGTH - 1 - 12 + (i * 2) + 1]));
    }

	return data->mac_addr;
}

/* Func: send_socket_data
 * Desc: This function will send data over the socket object.
 */
static ssize_t send_socket_data(struct modem_socket *sock,
				const struct sockaddr *dst_addr,
				const char *buf, const size_t buf_len,
				k_timeout_t timeout)
{
        int total = 0;
	int ret = -1;

        k_sem_take(&mdata.sem_xlate_buf, K_FOREVER);
        while (total < buf_len)
        {
            int len;
            int written;

            len = MIN(buf_len - total, MDM_MAX_DATA_LENGTH);

            /* Create the command prefix */
            written = snprintk(mdata.xlate_buf, sizeof(mdata.xlate_buf), "AT%%SOCKETDATA=\"SEND\",%d,%zu,\"", sock->sock_fd, len);

            /* Add the hex string */
            data_to_hex_str(&buf[total], len, &mdata.xlate_buf[written], sizeof(mdata.xlate_buf) - written);

            /* Finish the command */
            snprintk(&mdata.xlate_buf[written + len * 2], sizeof(mdata.xlate_buf), "\"");
             //printk("Sending to socket, len= %d, buf: %s\n", len, mdata.xlate_buf);

            /* Send the command */
            ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
               NULL, 0U, mdata.xlate_buf,
               &mdata.sem_response, K_MSEC(0));
            // printk("modem_cmd_send returned %d\n", ret);

            if (ret < 0) {
                    goto exit;
            }

            total += len;
	}
exit:
        k_sem_give(&mdata.sem_xlate_buf);

	/* unset handler commands and ignore any errors */
	(void)modem_cmd_handler_update_cmds(&mdata.cmd_handler_data,
					    NULL, 0U, false);
	if (ret < 0) {
		return ret;
	}

	/* Return the amount of data written on the socket. */
	return total;
}

/* Func: on_cmd_sockread_common
 * Desc: Function to read data on a given socket.
 */
static int on_cmd_sockread_common(int socket_fd,
				  struct modem_cmd_handler_data *data,
				  int socket_data_length, uint16_t len)
{
	struct modem_socket	 *sock = NULL;
	struct socket_read_data	 *sock_data;
	int ret;

	if (!len) {
		return -EAGAIN;
	}

	/* zero length */
	if (socket_data_length <= 0) {
		return -EAGAIN;
	}

	/* Make sure we still have buf data */
	if (!data->rx_buf) {
		LOG_ERR("Incorrect format! Ignoring data!");
		return -EINVAL;
	}

	/* check to make sure we have all of the data (minus quotes) */
	if ((net_buf_frags_len(data->rx_buf) - 2) < socket_data_length) {
		LOG_DBG("Not enough data -- wait!");
		return -EAGAIN;
	}

	/* skip quote /" */
	len -= 1;
	net_buf_pull_u8(data->rx_buf);
	if (!data->rx_buf->len) {
		data->rx_buf = net_buf_frag_del(NULL, data->rx_buf);
	}

	sock = modem_socket_from_fd(&mdata.socket_config, socket_fd);
	if (!sock) {
		LOG_ERR("Socket not found! (%d)", socket_fd);
		ret = -EINVAL;
		goto exit;
	}

	sock_data = (struct socket_read_data *)sock->data;
	if (!sock_data) {
		LOG_ERR("Socket data not found! Skip handling (%d)", socket_fd);
		ret = -EINVAL;
		goto exit;
	}
	
	ret = net_buf_linearize(sock_data->recv_buf, sock_data->recv_buf_len,
				data->rx_buf, 0, (uint16_t)(socket_data_length * 2));

	data->rx_buf = net_buf_skip(data->rx_buf, ret);
	sock_data->recv_read_len = socket_data_length;

	if ((ret/2) != socket_data_length) {
		LOG_ERR("Total copied data is different then received data!"
			" copied:%d vs. received:%d", ret, socket_data_length);
		ret = -EINVAL;
	}

exit:
	/* remove packet from list (ignore errors) */
	(void)modem_socket_packet_size_update(&mdata.socket_config, sock,
					      -socket_data_length);

	/* don't give back semaphore -- OK to follow */
	return ret;
}

/* Handler: OK */
MODEM_CMD_DEFINE(on_cmd_ok)
{
	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&mdata.sem_response);
	return 0;
}

/* Handler: ERROR */
MODEM_CMD_DEFINE(on_cmd_error)
{
	modem_cmd_handler_set_error(data, -EIO);
	k_sem_give(&mdata.sem_response);
	return 0;
}

MODEM_CMD_DEFINE(on_cmd_unsol_sms)
{
	// printk("got unsolicited sms, argc: %d, evt: %s, sockfd: %s\n", argc, argv[0], argv[1]);	//remove me

        k_sem_give(&mdata.sem_sms);

        return 0;
}

/* Handler of unsolicit SOCKETEV */
MODEM_CMD_DEFINE(on_cmd_unsol_SEV)
{
	struct modem_socket *sock;
	int		sock_fd;
	int 	evt_id;

	printk("got unsolicit socketev, evt: %s, sockfd: %s\n", argv[0], argv[1]);	//remove me
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
		LOG_INF("Data Receive Indication for socket: %d", sock_fd);
#ifdef MDM_SOCKWAIT
		modem_socket_data_ready(&mdata.socket_config, sock);
#else
#ifndef NO_WAIT_FOR_DATA_READY
		k_sem_give(&sock->sem_data_ready);
#endif
#endif
		break;
	//TODO handle later
	case 2:	//socket deact
	case 3:	//socket terminated
		LOG_WRN("wrong evt of Unsolicit!");
		//socket_close(sock);	//may not need DELETE, since modem terminated.
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

/* Handler: <manufacturer> */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_manufacturer)
{
  	modem_cmd_handler_set_error(data, 0);

	size_t out_len = net_buf_linearize(mdata.mdm_manufacturer,
					   sizeof(mdata.mdm_manufacturer) - 1,
					   data->rx_buf, 0, len);
	mdata.mdm_manufacturer[out_len] = '\0';
	LOG_INF("Manufacturer: %s", log_strdup(mdata.mdm_manufacturer));
	return 0;
}

/* Handler: <model> */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_model)
{
	size_t out_len = net_buf_linearize(mdata.mdm_model,
					   sizeof(mdata.mdm_model) - 1,
					   data->rx_buf, 0, len);
	mdata.mdm_model[out_len] = '\0';

	/* Log the received information. */
	LOG_INF("Model: %s", log_strdup(mdata.mdm_model));
	return 0;
}

/* Handler: <rev> */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_revision)
{
	size_t out_len = net_buf_linearize(mdata.mdm_revision,
					   sizeof(mdata.mdm_revision) - 1,
					   data->rx_buf, 0, len);
	mdata.mdm_revision[out_len] = '\0';

	/* Log the received information. */
	LOG_INF("Revision: %s", log_strdup(mdata.mdm_revision));
	return 0;
}

/* Handler: <IMEI> */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_imei)
{
	size_t out_len = net_buf_linearize(mdata.mdm_imei,
					   sizeof(mdata.mdm_imei) - 1,
					   data->rx_buf, 0, len);
	mdata.mdm_imei[out_len] = '\0';

	/* Log the received information. */
	LOG_INF("IMEI: %s", log_strdup(mdata.mdm_imei));
	return 0;
}

#if defined(CONFIG_MODEM_SIM_NUMBERS)
/* Handler: <IMSI> */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_imsi)
{
	size_t out_len = net_buf_linearize(mdata.mdm_imsi,
					   sizeof(mdata.mdm_imsi) - 1,
					   data->rx_buf, 0, len);
	mdata.mdm_imsi[out_len] = '\0';

	/* Log the received information. */
	LOG_INF("IMSI: %s", log_strdup(mdata.mdm_imsi));
	return 0;
}

/* Handler: <ICCID> */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_iccid)
{
	size_t out_len = net_buf_linearize(mdata.mdm_iccid,
					   sizeof(mdata.mdm_iccid) - 1,
					   data->rx_buf, 0, len);
	mdata.mdm_iccid[out_len] = '\0';

	/* Log the received information. */
	LOG_INF("ICCID: %s", log_strdup(mdata.mdm_iccid));
	return 0;
}
#endif //defined(CONFIG_MODEM_SIM_NUMBERS)


void parse_ipgwmask(char *buf, char *p1, char *p2, char *p3);
#define PDN_QUERY_RESPONSE_LEN 256
static bool first_pdn_rcved = false;
/* Handler: <PDNRDP> */
MODEM_CMD_DEFINE(on_cmd_ipgwmask)
{
	char buf[PDN_QUERY_RESPONSE_LEN];
	int ret = 0;
	size_t read_cnt;
	LOG_INF("GOt PDNRDP, len = %d", len);
	if (!first_pdn_rcved) {
		first_pdn_rcved = true;
		read_cnt = net_buf_linearize(buf,
						   PDN_QUERY_RESPONSE_LEN - 1,
						   data->rx_buf, 0, len);
		if (strnstr(buf, "\r\n", read_cnt)) {
			LOG_WRN("NOT enough octets!!");
			ret = -EAGAIN;
			first_pdn_rcved = false;
		} else {
			buf[read_cnt] = 0;
			parse_ipgwmask(buf, mdata.mdm_ip, mdata.mdm_nmask, mdata.mdm_gw);

			/* Log the received information. */
			LOG_INF("IP: %s, GW: %s, NMASK: %s", log_strdup(mdata.mdm_ip), log_strdup(mdata.mdm_gw), log_strdup(mdata.mdm_nmask));
		}
	}
	return ret;
}
char *get_4_octet(char *buf)
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
 * arg p1: ip addr pointer
 * arg p2: mask pointer
 * arg p3: gateway pointer
 */
void parse_ipgwmask(char *buf, char *p1, char *p2, char *p3)
{
	char *pstr, *pend = NULL;
	size_t len;
	pstr = strchr(buf, ',');	//session id
	if (pstr) pstr = strchr (pstr+1, ',');	//beaer id
	if (pstr) pstr = strchr (pstr+1, ',');	//apn
	if (pstr) {
		pend = get_4_octet(pstr+1);
	}
	if (pend) {
        *pend = 0;
        len = pend - pstr - 1;
        len = MIN(len, MDM_IP_LENGTH);
        strncpy(p1, pstr+1, len);
        pstr = pend+1;
        pend = strchr(pstr, ',');
		if (pend) {
			*pend = 0;
			len = pend - pstr;
			len = MIN(len, MDM_GW_LENGTH);
			strncpy(p2, pstr, len);
			pstr = pend+1;
			pend = strchr(pstr, ',');
			if (pend) {
				*pend = 0;
				len = pend - pstr;
				len = MIN(len, MDM_MASK_LENGTH);
				strncpy(p3, pstr, len);
				//printk("IP: %s, nmASK: %s, GW: %s\n", p1, p2, p3);
			}
		}
	}
}

/**
 * get ipv4 config info from modem
 */
int get_ipv4_config(void)
{
	char buf[64] = {0};
	int  ret;
	// struct modem_socket *sock = (struct modem_socket *)obj;

	/* Modem command response to sms receive the data. */
	struct modem_cmd data_cmd[] = {
	    MODEM_CMD("%PDNRDP", on_cmd_ipgwmask, 0U, ":"),
	    MODEM_CMD("ERROR", on_cmd_error, 0U, "")
	};

	snprintk(buf, sizeof(buf), "AT%%PDNRDP=1");
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     data_cmd, 1, buf, &mdata.sem_response, K_MSEC(200));
	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
	}
	return ret;
}

/* Handler to read data from socket
   %SOCKETDATA:<socket_id>[0],<length>[1],<moreData>[2],
           "<data>", <src_ip>, <src_port> */
MODEM_CMD_DEFINE(on_cmd_sock_readdata)
{
	return on_cmd_sockread_common(mdata.sock_fd, data, ATOI(argv[1], 0, "length"), len);
}

///
static const struct modem_cmd response_cmds[] = {
  	MODEM_CMD("OK", on_cmd_ok, 0U, ""),
	MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
};

static const struct modem_cmd unsol_cmds[] = {
	MODEM_CMD("%SOCKETEV:",	   on_cmd_unsol_SEV, 2U, ","),
        MODEM_CMD("+CMTI:", on_cmd_unsol_sms, 2U, ","),
};

/* Handler: %SOCKETCMD:<socket_id> OK */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_sockopen)
{

  int sock_id = data->rx_buf->data[0] - '0';
  mdata.sock_fd = sock_id;
  modem_cmd_handler_set_error(data, 0);
  k_sem_give(&mdata.sem_sock_conn);

	return 0;
}

static bool got_pdn_flg;
/* Handler: <PDNRDP> */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_pdnrdp)
{
#define PDN_BUF_SZ	256
	char pdn_buf[PDN_BUF_SZ];
	size_t out_len;

	if (!got_pdn_flg) {
		got_pdn_flg = true;
		out_len = net_buf_linearize(pdn_buf,
						   PDN_BUF_SZ-1,
						   data->rx_buf, 0, len);
		pdn_buf[out_len] = '\0';
		//printk("PDNRDP-data (len=%d, strlen=%d, dat: %s\n", len, out_len, pdn_buf);
		parse_ipgwmask(pdn_buf, mdata.mdm_ip, mdata.mdm_nmask, mdata.mdm_gw);
		/* Log the received information. */
		//LOG_INF("IP: %s, GW: %s, NMASK: %s", log_strdup(mdata.mdm_ip), log_strdup(mdata.mdm_gw), log_strdup(mdata.mdm_nmask));
	}

    return 0;
}

/* Func: murata_1sc_setup
 * Desc: This function is used to setup the modem from zero. 
 */
static int murata_1sc_setup(void)
{
	modem_pin_write(&mctx, MDM_WAKE_MDM, 1);
	k_sleep(K_SECONDS(3));

	/* Commands sent to the modem to set it up at boot time. */
	 const struct setup_cmd setup_cmds[] = {
		/* Commands to read info from the modem (things like IMEI, Model etc). */
		SETUP_CMD_NOHANDLE("ATQ0"),
		SETUP_CMD_NOHANDLE("ATE0"),
		SETUP_CMD_NOHANDLE("ATV1"),
                SETUP_CMD_NOHANDLE("AT%CSDH=1"),
                SETUP_CMD_NOHANDLE("AT+CNMI=2,1,2,1,0"),
		SETUP_CMD("AT+CGMI", "", on_cmd_atcmdinfo_manufacturer, 0U, ""),
		SETUP_CMD("AT+CGMM", "", on_cmd_atcmdinfo_model, 0U, ""),
		SETUP_CMD("AT+CGMR", "", on_cmd_atcmdinfo_revision, 0U, ""),
		SETUP_CMD("AT+CGSN", "", on_cmd_atcmdinfo_imei, 0U, ""),
#if defined(CONFIG_MODEM_SIM_NUMBERS)
		SETUP_CMD("AT+CIMI", "", on_cmd_atcmdinfo_imsi, 0U, ""),
		SETUP_CMD("AT%CCID", "%CCID:", on_cmd_atcmdinfo_iccid, 0U, " "),
#endif //(CONFIG_MODEM_SIM_NUMBERS)
		SETUP_CMD("AT+CGCONTRDP", "+CGDCONTRDP:", on_cmd_atcmdinfo_pdnrdp, 0U, ""),
	};

	int ret = 0, counter;

	counter = 0;

	/* Run setup commands on the modem. */
	ret = modem_cmd_handler_setup_cmds(&mctx.iface, &mctx.cmd_handler,
					   setup_cmds, ARRAY_SIZE(setup_cmds),
					   &mdata.sem_response, MDM_REGISTRATION_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("modem_cmd_handler_setup_cmds error");
	}

	// modem_pin_write(&mctx, MDM_WAKE_MDM, 0);

	return ret;
}

/* Func: socket_close
 * Desc: Function to close the given socket descriptor.
 */
static void socket_close(struct modem_socket *sock)
{
	char buf[40] = {0};
	int  ret;

	/* Tell the modem to close the socket. */
	snprintk(buf, sizeof(buf), "AT%%SOCKETCMD=\"DEACTIVATE\",%d", sock->sock_fd);
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     NULL, 0U, buf, &mdata.sem_response, K_MSEC(0));

	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
	}
	
	/* Tell the modem to delete the socket. */
	snprintk(buf, sizeof(buf), "AT%%SOCKETCMD=\"DELETE\",%d", sock->sock_fd);
	//printk("%s\n", buf);
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     NULL, 0U, buf,
			     &mdata.sem_response, K_MSEC(0));
	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
	}

	modem_socket_put(&mdata.socket_config, sock->sock_fd);
}

/* Func: send sms message
 * Desc: Send a sms message
 */
static int send_sms_msg(void *obj, const struct sms_out *sms)
{
	char buf[sizeof(struct sms_out) + 12] = {0};
	int  ret;
	// struct modem_socket *sock = (struct modem_socket *)obj;

	snprintk(buf, sizeof(buf), "AT+CMGF=1");
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     NULL, 0U, buf, &mdata.sem_response, K_MSEC(0));
	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
	}

	snprintk(buf, sizeof(buf), "AT+CMGS=\"%s\"\r%s\x1a", sms->phone, sms->msg);
        // printk("\n%s\n", buf);
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     NULL, 0U, buf, &mdata.sem_response, K_MSEC(0));
	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
	}

        return ret;
}

/* Handler to read SMS message from modem
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

        // Find the beginning of the message (first crlf after argv[5])
        str1 = strnstr(data->rx_buf->data, "\r\n", data->rx_buf->len);
        if (str1) {
            // Find the end of the message (next crlf after str1 + 2)
            str2 = strnstr(str1 + 2, "\r\n", data->rx_buf->len - (size_t) (str1 + 2 - (char *) data->rx_buf->data));
            if (str2) {
                *str2 = '\0';
                // printk("SMS msg: '%s'\n", str1 + 2);

                // Prepare the return struct
                snprintf(sms->phone, sizeof(sms->phone), "%s", argv[2]);
                snprintf(sms->time, sizeof(sms->time), "%.8s,%.11s", argv[4]+1, argv[5]);
                snprintf(sms->msg, sizeof(sms->msg), "%s", str1 + 2);

                // Set sms_index so we can delete the message from recv_sms_msg
                // TBD: should we just delete it here
                mdata.sms_index = atoi(argv[0]);

                // Check for "\r\n+CMGL:" or "\r\nOK\r\n" at the end of CMGL response
                // Skip ahead to the found string if present since
                // we need to let the command handler know we're done.
                str3 = strnstr(str2 + 2, "\r\n+CMGL:", data->rx_buf->len - (size_t) (str2 + 2 - (char *) data->rx_buf->data));
                if (str3) {
                    data->rx_buf = net_buf_skip(data->rx_buf, (size_t) ((uint8_t *) str3 - data->rx_buf->data));
                }
                else {
                    str3 = strnstr(str2 + 2, "\r\nOK\r\n", data->rx_buf->len - (size_t) (str2 + 2 - (char *) data->rx_buf->data));
                    if (str3) {
                        data->rx_buf = net_buf_skip(data->rx_buf, (size_t) ((uint8_t *) str3 - data->rx_buf->data));
                    }
                }

                // printk("In on_cmd_readsms AFTER net_buf_skip, len:%d, data: '", data->rx_buf->len);

                /*
                for (int i=0;i<data->rx_buf->len;i++)
                    printk("%c", data->rx_buf->data[i]);
                printk("'\n");
                */
            }
            else {
                // printk("Warning, SMS bad format 2\n");
                return -EAGAIN;
            }
        }
        else {
                // printk("Warning, SMS bad format 1\n");
                return -EAGAIN;
        }
                
        return 0;
}

/* Func: recieve sms messages
 * Desc: recieve sms messages 
 */
static int recv_sms_msg(void *obj, struct sms_in *sms)
{
	char buf[64] = {0};
	int  ret;
	// struct modem_socket *sock = (struct modem_socket *)obj;
        int count = 0;

        k_sem_reset(&mdata.sem_sms);

	/* Modem command response to sms receive the data. */
	struct modem_cmd data_cmd[] = {
	    MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
	    MODEM_CMD("+CMGL:", on_cmd_readsms, 6U, ",")
	};

	snprintk(buf, sizeof(buf), "AT+CMGF=1");
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     NULL, 0U, buf, &mdata.sem_response, K_MSEC(5000));
	if (ret < 0) {
            // printk("JML Error 1\n");
	    LOG_ERR("%s ret:%d", log_strdup(buf), ret);
	}

        // Set pointer to struct which is populated in on_cmd_sockreadsms
        mdata.sms = sms;

        while (count <= 1) {
            snprintk(buf, sizeof(buf), "AT+CMGL=\"ALL\"");
            ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
                                 data_cmd, ARRAY_SIZE(data_cmd), buf, &mdata.sem_response, K_MSEC(5000));
            if (ret < 0) {
                // printk("JML Error 2, ret = %d\n", ret);
                LOG_ERR("%s ret:%d", log_strdup(buf), ret);
            }

            else {
                if (mdata.sms_index)
                {
                    // printk("Received SMS from %s dated %s: %s\n", mdata.sms->phone, mdata.sms->time, mdata.sms->msg);

                    // Delete the message from the modem
                    snprintk(buf, sizeof(buf), "AT+CMGD=%d", mdata.sms_index);
                    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
                                         NULL, 0U, buf, &mdata.sem_response, K_MSEC(0));
                    if (ret < 0) {
                        // printk("JML Error 3\n");
                        LOG_ERR("%s ret:%d", log_strdup(buf), ret);
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

        // printk("JML returning %d\n", ret);
	return ret;
}

/* Func: offload_recvfrom
 * Desc: This function will receive data on the socket object.
 */
static ssize_t offload_recvfrom(void *obj, void *buf, size_t len,
				int flags, struct sockaddr *from,
				socklen_t *fromlen)
{
	struct modem_socket *sock = (struct modem_socket *)obj;
	char   sendbuf[100] = {0};
	int    ret;
	struct socket_read_data sock_data;
        int total = 0;

	/* Modem command to read the data. */
	struct modem_cmd data_cmd[] = { 
	    MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
		MODEM_CMD("%SOCKETDATA:", on_cmd_sock_readdata, 3U, ",")
	};

	if (!buf || len == 0) {
		errno = EINVAL;
		return -1;
	}

	if (flags & ZSOCK_MSG_PEEK) {
		errno = ENOTSUP;
		LOG_ERR("NO MSG_PEEK Support!");
		return -1;
	}

        /* Socket read settings */
        (void) memset(&sock_data, 0, sizeof(sock_data));
        (void) memset(mdata.xlate_buf, 0, sizeof(mdata.xlate_buf));
        sock_data.recv_buf     = mdata.xlate_buf;
        sock_data.recv_buf_len = sizeof(mdata.xlate_buf);
        sock_data.recv_addr    = from;
        sock->data	       = &sock_data;
        mdata.sock_fd	       = sock->sock_fd;

        /* use dst address as from */
        if (from && fromlen) {
                *fromlen = sizeof(sock->dst);
                memcpy(from, &sock->dst, *fromlen);
        }

        k_sem_take(&mdata.sem_xlate_buf, K_FOREVER);
        while (total < len)
        {
        	// printk("waiting for socket data!  sock: %p, sock->fd %d, req_len = %d, total= %d\n", sock, sock->sock_fd, len, total);	//remove me
#ifdef MDM_SOCKWAIT
        	modem_socket_wait_data(&mdata.socket_config, sock);	//wait for socketev
#else
#ifndef NO_WAIT_FOR_DATA_READY
        	ret = k_sem_take(&sock->sem_data_ready, K_NO_WAIT);
        	if (ret < 0) {
        		LOG_INF("no more data");
        		errno = EWOULDBLOCK;
        		break;
        	}
#endif
#endif
            snprintk(sendbuf, sizeof(sendbuf), "AT%%SOCKETDATA=\"RECEIVE\",%u,%u", sock->sock_fd,
                    MIN(MDM_RECV_BUF_SIZE, len - total));

            /* Tell the modem to give us data (%SOCKETDATA:socket_id,len,0,data). */
            ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
                                 data_cmd, ARRAY_SIZE(data_cmd), sendbuf, &mdata.sem_response,
                                 K_SECONDS(1));
            if (ret < 0) {
                    errno = -ret;
                    ret = -1;
                    break;
            }
            errno = 0;

            if (sock_data.recv_read_len == 0) {
            	printk("sock-recv no bytes, quit!\n");
                break;
            }

            /* return length of received data */
            hex_str_to_data(mdata.xlate_buf, (uint8_t *) buf + total, sock_data.recv_read_len);
            total += sock_data.recv_read_len;
        }
        k_sem_give(&mdata.sem_xlate_buf);


	/* clear socket data */
	sock->data = NULL;
        if (total == 0) {
            errno = EAGAIN;
            total = -1;
        }
	return total;
}

static bool offload_is_supported(int family, int type, int proto)
{
	return true;
}

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

/* Func: offload_connect
 * Desc: This function will connect with a provided TCP or UDP.
 */
static int offload_connect(void *obj, const struct sockaddr *addr,
						   socklen_t addrlen)
{
	struct modem_socket *sock     = (struct modem_socket *) obj;
	uint16_t dst_port  = 0;
	char protocol[5] = {0};
	char buf[100] = {0};
	int  ret;

  	struct modem_cmd cmd[] = {
      	MODEM_CMD("ERROR", on_cmd_error, 0, ","),
    	MODEM_CMD("%SOCKETCMD:", on_cmd_atcmdinfo_sockopen, 0U, ""),
  	};

	if (sock->id < mdata.socket_config.base_socket_num - 1) {
		LOG_ERR("Invalid socket_id(%d) from fd:%d",
			sock->id, sock->sock_fd);
		errno = EINVAL;
		return -1;
	}

	if (sock->is_connected == true) {
		LOG_ERR("Socket is already connected!! socket_id(%d), socket_fd:%d",
			sock->id, sock->sock_fd);
		errno = EISCONN;
		return -1;
	}

	switch (sock->ip_proto) {
	case IPPROTO_UDP:
		snprintf(protocol, sizeof(protocol), "UDP");
		break;
	case IPPROTO_TCP:
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	case IPPROTO_TLS_1_2:
#endif
		snprintf(protocol, sizeof(protocol), "TCP");
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
        char ip_add[30] = {0};
        modem_context_sprint_ip_addr(addr, ip_add, sizeof(ip_add));
	/* Formulate the string to allocate socket. */
	snprintk(buf, sizeof(buf), "AT%%SOCKETCMD=\"ALLOCATE\",0,\"%s\",\"OPEN\",\"%s\",%d", 
                 protocol, ip_add, dst_port);
	
	printk("\n%s\n", buf);
	/* Send out the command. */
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     cmd, ARRAY_SIZE(cmd), buf,
			     &mdata.sem_response, K_SECONDS(1));

	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
		LOG_ERR("Closing the socket!!!");
		socket_close(sock);
		errno = -ret;
		return -1;
	}

	ret = k_sem_take(&mdata.sem_sock_conn, K_SECONDS(1));
	if (ret < 0) {
		LOG_ERR("Timeout for waiting for sockconn; closing socket!\n");
		socket_close(sock);
		errno = -ret;
		return -1;
	}

	//printk("store %d into sock: %p\n", mdata.sock_fd, sock);	//remove me
	sock->sock_fd = mdata.sock_fd;

	if (sock->ip_proto == IPPROTO_TLS_1_2) {
		snprintk(buf, sizeof(buf), "AT%%SOCKETCMD=\"SSLALLOC\",%d,0,8", sock->sock_fd);
		ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
				     NULL, 0U, buf,
				     &mdata.sem_response, K_SECONDS(8));
		printk("%s\n", buf);
		if (ret < 0) {
			LOG_ERR("%s ret: %d", log_strdup(buf), ret);
			LOG_ERR("Closing the socket!!!");
			socket_close(sock);
			errno = -ret;
			return -1;
		}
	}

	snprintk(buf, sizeof(buf), "AT%%SOCKETCMD=\"ACTIVATE\",%d", sock->sock_fd);
	printk("\n%s\n", log_strdup(buf));
	/* Send out the command. */
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     NULL, 0U, buf,
			     &mdata.sem_response, K_SECONDS(8));

	if (ret < 0) {
		LOG_ERR("%s ret: %d", log_strdup(buf), ret);
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

	printk("sock conn GOOD!\n");	//remove me
	/* Connected successfully. */
	sock->is_connected = true;
	errno = 0;
	return 0;

exit:
	(void) modem_cmd_handler_update_cmds(&mdata.cmd_handler_data,
					     NULL, 0U, false);
	errno = -ret;
	return -1;
}

/* Func: offload_sendto
 * Desc: This function will send data on the socket object.
 */
static ssize_t offload_sendto(void *obj, const void *buf, size_t len,
			      int flags, const struct sockaddr *to,
			      socklen_t tolen)
{
	int ret;
	struct modem_socket *sock = (struct modem_socket *) obj;
	//printk("offld-snd2, soket: %p\n", sock);	//remove me
	/* Ensure that valid parameters are passed. */
	if (!buf || len <= 0) {
		errno = EINVAL;
		return -1;
	}

	if (!sock->is_connected) {
		errno = ENOTCONN;
		return -1;
	}
	ret = send_socket_data(sock, to, buf, len, MDM_CMD_TIMEOUT);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	/* Data was written successfully. */
	errno = 0;

	return ret;
}

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

/* Func: offload_read
 * Desc: This function reads data from the given socket object.
 */
static ssize_t offload_read(void *obj, void *buffer, size_t count)
{
	return offload_recvfrom(obj, buffer, count, 0, NULL, 0);
}

/* Func: offload_write
 * Desc: This function writes data to the given socket object.
 */
static ssize_t offload_write(void *obj, const void *buffer, size_t count)
{
	return offload_sendto(obj, buffer, count, 0, NULL, 0);
}

/* Func: offload_close
 * Desc: This function closes the connection with the remote client and
 * frees the socket.
 */
static int offload_close(void *obj)
{
	struct modem_socket *sock = (struct modem_socket *) obj;

	/* Make sure we assigned an id */
	if (sock->id < mdata.socket_config.base_socket_num) {
		return 0;
	}

	/* Close the socket only if it is connected. */
// 	if (sock->is_connected) {
		socket_close(sock);
//	}

	return 0;
}

/* Func: offload_sendmsg
 * Desc: This function sends messages to the modem.
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

typedef enum {
	imei_e,
	imsi_e,
	iccid_e,
	ssi_e,
	msisdn_e,
	connsts_e,
	ip_e,
	invalid
} atcmd_idx_e;

typedef void (*atcmd_cb_t)(atcmd_idx_e e, void *user_data);

typedef struct {
	char *str;
	atcmd_idx_e e;
	atcmd_cb_t fp;
} _cmd_t;

static void gen_query(atcmd_idx_e idx, void *buf)
{
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
	default:
		printk("not valid request\n");
		break;
	}
}

MODEM_CMD_DEFINE(on_cmd_csq)
{
#define MIN_SS	-113
	char buf[16];
	char *endp;
	int ret;
	size_t out_len = net_buf_linearize(buf,
					   15,
					   data->rx_buf, 0, len);
	buf[out_len] = '\0';

	for (int i = 0; i < 15; i++) {
		if (buf[i] == ',') {
			buf[i] = 0;
			break;
		}
	}
	ret = (int)strtol(buf, &endp, 10);
	ret = MIN_SS + 2 * ret;
	/* Log the received information. */
	LOG_INF("signal strength: %d dBm", ret);
	return 0;
}

int get_str_in_quote(char *buf, char *pdest, size_t dest_size)
{
	char delim = '"';
	char *pstart, *pend;
	int strlen = 0;

	pstart = strchr(buf, delim);
	if (pstart) {
		++pstart;
	} else {
		return 0;
	}
	pend = strchr(pstart, delim);
	if (pend) {
		strlen = pend - pstart;
		strlen = MIN(strlen, dest_size);
		strncpy(pdest, pstart, strlen);
	}
	return strlen;
}
MODEM_CMD_DEFINE(on_cmd_cnum)
{
	char buf[32];
	int strlen;
	size_t out_len = net_buf_linearize(buf,
					   31,
					   data->rx_buf, 0, len);
	buf[out_len] = '\0';

	strlen = get_str_in_quote(buf, mdata.mdm_phn, sizeof(mdata.mdm_phn));

	/* Log the received information. */
	//LOG_INF("got cnum: %s, str_len = %d", mdata.mdm_phn, strlen);
	return 0;
}

MODEM_CMD_DEFINE(on_cmd_cops)
{
	char buf[32];
	int sz;
	size_t out_len = net_buf_linearize(buf,
					   31,
					   data->rx_buf, 0, len);
	buf[out_len] = '\0';

	sz = get_str_in_quote(buf, mdata.mdm_carrier, sizeof(mdata.mdm_carrier));

	/* Log the received information. */
	//LOG_INF("got cops: %s, carr_len = %d", mdata.mdm_carrier, sz);
	return 0;
}

/**
 * get signal strength
 */
int get_sigstrength(void)
{
	char buf[64] = {0};
	int  ret;
	// struct modem_socket *sock = (struct modem_socket *)obj;

	/* Modem command response to sms receive the data. */
	struct modem_cmd data_cmd[] = {
	    MODEM_CMD("%CSQ:", on_cmd_csq, 0U, ""),
	};

	snprintk(buf, sizeof(buf), "AT%%CSQ");
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     data_cmd, 1, buf, &mdata.sem_response, K_MSEC(200));
	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
		ret = -1;
	}
	return ret;
}

#define MAX_RESP_SIZE	256
/**
 * get phone number
 */
int get_cnum(char *rbuf)
{
	int ret;
	char buf[16] = {0};
	/* Modem command response to sms receive the data. */
	struct modem_cmd data_cmd[] = {
	    MODEM_CMD("+CNUM:", on_cmd_cnum, 0U, ","),
	};

	snprintk(buf, sizeof(buf), "AT+CNUM");
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     data_cmd, 1, buf, &mdata.sem_response, K_MSEC(20));
	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
		ret = -1;
	}
	memcpy(rbuf, mdata.mdm_phn, sizeof(mdata.mdm_phn));
	return ret;
}

/**
 * get conn status
 */
int get_cops(char *rbuf)
{
	int ret;
	char buf[16] = {0};
	/* Modem command response to sms receive the data. */
	struct modem_cmd data_cmd[] = {
	    MODEM_CMD("+COPS:", on_cmd_cops, 0U, ","),
	};

	snprintk(buf, sizeof(buf), "AT+COPS?");
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     data_cmd, 1, buf, &mdata.sem_response, K_MSEC(20));
	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
		ret = -1;
	}
	snprintk(rbuf, MAX_RESP_SIZE, "%s", mdata.mdm_carrier);
	return ret;
}

/**
 * get ip/mask/gw
 */
int get_ip(char *rbuf)
{
	int ret;
	char buf[16] = {0};
	got_pdn_flg = false;
	/* Modem command response to sms receive the data. */
	struct modem_cmd data_cmd[] = {
	    MODEM_CMD("+CGCONTRDP:", on_cmd_atcmdinfo_pdnrdp, 0U, ","),
	};

	snprintk(buf, sizeof(buf), "AT+CGCONTRDP");
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     data_cmd, 1, buf, &mdata.sem_response, K_MSEC(200));
	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
		ret = -1;
	}
	//LOG_INF("IP: %s, GW: %s, NMASK: %s", log_strdup(mdata.mdm_ip), log_strdup(mdata.mdm_gw), log_strdup(mdata.mdm_nmask));
	snprintk(rbuf, MAX_RESP_SIZE, "IP: %s, GW: %s, NMASK: %s", mdata.mdm_ip, mdata.mdm_gw, mdata.mdm_nmask);

	return ret;
}

static void dyn_query(atcmd_idx_e idx, void *buf)
{
	switch(idx) {
	int ssi, sts;
	case ssi_e:
		ssi = get_sigstrength();
		break;
	case msisdn_e:
		sts = get_cnum(buf);
		break;
	case connsts_e:
		sts = get_cops(buf);
		break;
	case ip_e:
		sts = get_ip(buf);
		break;
	default:
		printk("not valid request\n");
		break;
	}
}

/**
 * using in_out_str as key to query modem at-cmd
 * response will be in in-out-str
 * current support string:
 * 		IMEI, IMSI ...
 */
_cmd_t cmd_pool[] = {
		{"IMEI", imei_e, gen_query},
		{"IMSI", imsi_e, gen_query},
		{"ICCID", iccid_e, gen_query},
		{"SSI", ssi_e, dyn_query},
		{"MSISDN", msisdn_e, dyn_query},
		{"CONN_STS", connsts_e, dyn_query},
		{"IP", ip_e, dyn_query},
		{}
};
int get_at_resp(char* io_str)
{
	int idx = 0;
	char *cmdStr;
	while (cmd_pool[idx].str != NULL) {
		cmdStr = cmd_pool[idx].str;
		if (strncmp(io_str, cmdStr, strlen(cmdStr)) == 0)
			break;
		++idx;
	}
	if (idx < (sizeof(cmd_pool)/sizeof(cmd_pool[0]) - 1)) {
		_cmd_t cmd_entry = cmd_pool[idx];
		//printk("found cmd in pool, idx = %d\n", idx);
		cmd_entry.fp(cmd_entry.e, io_str);
	} else {
		printk("cmd(%s) not suported\n", io_str);
		idx = -1;
	}
	return idx;
}

struct aggr_ipv4_addr {	//for testing
	struct in_addr ip;
	struct in_addr gw;
	struct in_addr nmask;
};
/* Func: offload_ioctl
 * Desc: Function call to handle various misc requests.
 */
static int offload_ioctl(void *obj, unsigned int request, va_list args)
{
        int ret;
		struct aggr_ipv4_addr *a_ipv4_addr;
		char *cmd_str;

        // TBD: cast obj to socket, find the right instance of the murata_1sc_data etc
        // assumming one instance for now

	switch (request) {
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
		printk("***** in driver ioctl *****\n");
		get_ipv4_config();
		ret = inet_pton(AF_INET, mdata.mdm_ip, &a_ipv4_addr->ip);
		ret = inet_pton(AF_INET, mdata.mdm_gw, &a_ipv4_addr->gw);
		ret = inet_pton(AF_INET, mdata.mdm_nmask, &a_ipv4_addr->nmask);
		ret = 0;
		break;
	case GET_ATCMD_RESP:
		cmd_str = (char *)va_arg(args, char *);
		ret = get_at_resp(cmd_str);
		//printk("app req: %s\n", cmd_str);
		break;

	default:
		errno = EINVAL;
                ret = -1;
                break;
	}
        return ret;
}

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#define CERTCMD_WRITE_SIZE	32+32	//assue filename maxlen = 32
#define PEM_BUFF_SIZE		6145	//terminate with \" & 0
/**
 * following struct may not have packed memory if it has something like
 * int follow by char then int,
 * since array of uchar plus array of uchar will be packed
 */
typedef struct {
	uint8_t cert_cmd_write[CERTCMD_WRITE_SIZE];
	uint8_t pem_buf[PEM_BUFF_SIZE];
} cert_cmd_s;
static cert_cmd_s cert_cmd_buf = {0};


/* send binary data via the AT commands */
static ssize_t send_cert(struct modem_socket *sock,
			 struct modem_cmd *handler_cmds,
			 size_t handler_cmds_len,
			 const char *cert_data,
			 int cert_type,
			 char* filename)
{
	int ret;
	int filename_len = strlen(filename);
	int offset = CERTCMD_WRITE_SIZE - filename_len - 14;	//overhead of "WRITE",,, & 2.5 pairs of "" & 1 digit
	uint8_t *sptr = &cert_cmd_buf.cert_cmd_write[offset];
	//int cert_write_len = filename_len + 14 + strlen(cert_data);

	/* TODO support other cert types as well */
	if (cert_type != 0) {
		return -EINVAL;
	}

	if (!sock) {
		return -EINVAL;
	}

	__ASSERT_NO_MSG(cert_len <= MDM_MAX_CERT_LENGTH);

	snprintk(sptr, sizeof(cert_cmd_buf),
		 "AT%%CERTCMD=\"WRITE\",\"%s\",%d,\"", filename, cert_type);
	cert_cmd_buf.pem_buf[0] = '-';	//amend the pem[0] overwritten by snprintf
	//printk("sptr: %s\n", sptr);
    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
       NULL, 0U, sptr,
       &mdata.sem_response, K_SECONDS(5));
	if (ret < 0) {
		if (ret == -116) {
			ret = 0;	//fake good ret
		} else {
			goto exit;
		}
	}

	k_sleep(K_MSEC(20));	//brief brake?
	snprintk(cert_cmd_buf.cert_cmd_write, sizeof(cert_cmd_buf.cert_cmd_write),
		 "AT%%CERTCFG=\"ADD\",8,,,\"%s\",\"\"", filename);

	//printk("certcfg: %s\n", cert_cmd_buf.cert_cmd_write);
    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
       NULL, 0U, cert_cmd_buf.cert_cmd_write,
       &mdata.sem_response, K_SECONDS(5));
	if (ret < 0) {
		printk("sendmdmcmd,ret = %d\n", ret);
		goto exit;
	}

exit:
	/* unset handler commands and ignore any errors */
	(void)modem_cmd_handler_update_cmds(&mdata.cmd_handler_data,
					    NULL, 0U, false);
	return ret;
}

static uint8_t cert_idx_ca = 0;

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
		uint8_t cert_idx;
		int offset;
		char *header, *footer;
		tag = sec_tags[i];
		cert = credential_next_get(tag, NULL);
		while (cert != NULL) {
			/* Map Zephyr cert types to WiSeConnect cert types: */
			switch (cert->type) {
			case TLS_CREDENTIAL_CA_CERTIFICATE:
				cert_type = 0;
				header = "-----BEGIN CERTIFICATE-----\n";
				footer = "\n-----END CERTIFICATE-----\"\n";
				cert_idx = cert_idx_ca;
				cert_idx_ca++;
				cert_idx_ca %= 2;
				break;
			case TLS_CREDENTIAL_SERVER_CERTIFICATE:
			case TLS_CREDENTIAL_PRIVATE_KEY:
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

			{	//write cert to murata with filename
				char *filename = "echo-apps-cert.pem";
				retval = send_cert(sock, NULL, 0, cert_cmd_buf.pem_buf, cert_idx, filename);
				if (retval < 0) {
					printk("Failed to send cert to modem, ret = %d\n", retval);
					return retval;
				}
			}

			cert = credential_next_get(tag, cert);
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
	int retval;

	//Todo, tls stuff
	if (IS_ENABLED(CONFIG_NET_SOCKETS_SOCKOPT_TLS) && level == SOL_TLS) {
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
			/**
			 * not sure how to implement, for now just return 0 for ecno_client
			 */
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
		switch (optname) {
			/* These sockopts do not map to the same values, but are still
			 * supported in WiSeConnect
			 */
//		case Z_SO_BROADCAST:
//		case Z_SO_REUSEADDR:
//		case Z_SO_SNDBUF:
//		case Z_IPV6_V6ONLY:
//			errno = EINVAL;
//			return -1;
		default:
			break;
		}
		return -1;
	}
	return retval;
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

static int murata_1sc_init(const struct device *dev)
{
	int ret = 0;
	gpio_flags_t gpflg;

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

	/* pin setup */
	mctx.pins = murata_1sc_pins;
	mctx.pins_len = ARRAY_SIZE(murata_1sc_pins);

        /* SMS functions */
        mctx.send_sms = send_sms_msg;
        mctx.recv_sms = recv_sms_msg;
	mctx.driver_data = &mdata;

	gpflg = mctx.pins[MDM_RESET].init_flags;
	gpflg &= ~(GPIO_OUTPUT_HIGH | GPIO_OUTPUT_LOW);
	mctx.pins[MDM_RESET].init_flags = gpflg | GPIO_OUTPUT_HIGH;
	mctx.pins[MDM_RESET].gpio_port_dev = device_get_binding(mctx.pins[MDM_RESET].dev_name);
	LOG_INF("MDM_RESET_PIN -> ASSERTED\n");
	modem_pin_config(&mctx, MDM_RESET, true);
	k_sleep(K_MSEC(20));

	mctx.pins[MDM_RESET].init_flags = gpflg | GPIO_OUTPUT_LOW;
	LOG_INF("MDM_RESET_PIN -> UNASSERTED\n");
	mctx.pins[MDM_RESET].gpio_port_dev = device_get_binding(mctx.pins[MDM_RESET].dev_name);
	ret = modem_context_register(&mctx);
	if (ret < 0) {
		LOG_ERR("Error registering modem context: %d", ret);
		// goto error;
	}

 	/* start RX thread */
	k_thread_create(&modem_rx_thread, modem_rx_stack,
			K_KERNEL_STACK_SIZEOF(modem_rx_stack),
			(k_thread_entry_t) murata_1sc_rx,
			NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);

	murata_1sc_setup();

  	return 0;
}

/* Setup the Modem NET Interface. */
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
    iface->if_dev->offloaded = true;
    iface->if_dev->socket = offload_socket;
#endif

}

static struct net_if_api api_funcs = {
	.init = murata_1sc_net_iface_init,
};

/* Register the device with the Networking stack. */
NET_DEVICE_DT_INST_OFFLOAD_DEFINE(0, murata_1sc_init, NULL,
				   &mdata, NULL,
				  80,
				//   NULL, MDM_MAX_DATA_LENGTH);
				  &api_funcs, MDM_MAX_DATA_LENGTH);

/* Register NET sockets. */
NET_SOCKET_REGISTER(murata_1sc, NET_SOCKET_DEFAULT_PRIO, AF_INET, offload_is_supported, offload_socket);

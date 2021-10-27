#ifndef MURATA_1SC_H_
#define MURATA_1SC_H_

#include <net/buf.h>

#define GSM_MODEM_DEVICE_NAME "murata 1sc"

#define MDM_UART_DEV_NAME		  DT_INST_BUS_LABEL(0)
#define MDM_CMD_TIMEOUT			  K_SECONDS(5)
#define MDM_REGISTRATION_TIMEOUT	  K_SECONDS(180)
#define MDM_SENDMSG_SLEEP		  K_MSEC(1)
#define MDM_MAX_DATA_LENGTH		  1500
#define MDM_RECV_MAX_BUF		  60
#define MDM_RECV_BUF_SIZE		  1500
#define MDM_MAX_SOCKETS			  5
#define MDM_BASE_SOCKET_NUM		  0
#define MDM_NETWORK_RETRY_COUNT		  10
#define MDM_INIT_RETRY_COUNT		  10
#define MDM_PDP_ACT_RETRY_COUNT		  3
#define MDM_WAIT_FOR_RSSI_COUNT		  10
#define MDM_WAIT_FOR_RSSI_DELAY		  K_SECONDS(2)
#define BUF_ALLOC_TIMEOUT		  K_SECONDS(1)
#define MDM_MAX_BOOT_TIME		  K_SECONDS(50)

/* Default lengths of certain things. */
#define MDM_MANUFACTURER_LENGTH		 40
#define MDM_MODEL_LENGTH		  16
#define MDM_REVISION_LENGTH		  64
#define MDM_IMEI_LENGTH			  16
#define MDM_IMSI_LENGTH			  16
#define MDM_ICCID_LENGTH		  32
#define MDM_APN_LENGTH			  32
#define RSSI_TIMEOUT_SECS		  30

#define MAX_IMEI_LEN     16     // IMEI   <= 15 digits
#define MAX_IMEISV_LEN   17     // IMEISV <= 16 digits
#define MAX_IMSI_LEN     16     // IMSI   <= 15 digits
#define MAX_ICCID_LEN    23     // ICCID  <= 22 digits
#define MAX_MSISDN_LEN   32     // MSISDN <= 15 digits, longer since returned as ',<msisdn>,123'
#define MAX_TIME_LEN     25

/** @cond INTERNAL_HIDDEN */
struct device;

/* pin settings */
enum mdm_control_pins {
	MDM_WAKE_HOST = 0,
	MDM_WAKE_MDM,
	MDM_RESET,
};

//enum io_ctl {
//	SMS_SEND,
//	SMS_RECV,
//};

/* Socket read callback data */ //might need to remove pointer to use full implementation of address
struct socket_read_data {
	char		 *recv_buf;
	size_t		 recv_buf_len;
	struct sockaddr	 *recv_addr;
	uint16_t	 recv_read_len;
};

#endif /* MURATA_1SC_H_ */

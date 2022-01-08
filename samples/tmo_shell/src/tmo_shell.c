/** @file
 * @brief tmo shell module
 *
 * Provide some tmo shell commands that can be useful to applications.
 */

/*
 * Copyright (c) 2021 t-mobile.com
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <net/socket.h>
#include <shell/shell.h>

#include "tmo_shell.h"

uint8_t mxfer_buf[XFER_SIZE+1];

struct sock_rec_s socks[MAX_SOCK_REC] = {0};

int tcp_create(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 2){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }
    int idx = strtol(argv[1], NULL, 10);
    struct net_if *iface = net_if_get_by_index(idx);
    if (iface == NULL) {
        shell_error(shell, "Interface %d not found", idx);
        return -EINVAL;
    }
    int sd = zsock_socket_ext(AF_INET, SOCK_STREAM, IPPROTO_TCP, iface);
    if (sd == -1) {
        shell_error(shell, "Socket creation failed, errno = %d", errno);
        return 0;
    }
    shell_print(shell, "Created socket %d", sd);
    for (int i = 0; i < MAX_SOCK_REC; i++) {
        if (!(socks[i].flags & BIT(sock_open))) {
            socks[i].dev = iface;
            socks[i].sd = sd;
            socks[i].flags = (BIT(sock_tcp) | BIT(sock_open));
            break;
        }
    }
    return 0;
}

int udp_create(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 2){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }
    int idx = strtol(argv[1], NULL, 10);
    struct net_if *iface = net_if_get_by_index(idx);
    if (iface == NULL) {
        shell_error(shell, "Interface %p not found", iface);
        return -EINVAL;
    }
    int sd = zsock_socket_ext(AF_INET, SOCK_DGRAM, IPPROTO_UDP, iface);
    if (sd == -1) {
        shell_error(shell, "Socket creation failed, errno = %d", errno);
        return 0;
    }
    shell_print(shell, "Created socket %d", sd);
    for (int i = 0; i < MAX_SOCK_REC; i++) {
        if (!(socks[i].flags & BIT(sock_open))) {
            socks[i].dev = iface;
            socks[i].sd = sd;
            socks[i].flags = (BIT(sock_udp) | BIT(sock_open));
            break;
        }
    }
    return 0;
}

int sock_connect(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 4){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }
    struct sockaddr_in target;
    // net_context_set_iface()
    // net_if_get_default
    // int sd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    // if (sd == -1) {
    //     shell_error(shell, "Socket creation failed, errno = %d", errno);
    //     return 0;
    // }
    // shell_print(shell, "Created socket %d", sd);
    int sd = strtol(argv[1], NULL, 10);
    int sock_idx;
    for (sock_idx = 0; sock_idx < MAX_SOCK_REC; sock_idx++) {
        if (socks[sock_idx].sd == sd && socks[sock_idx].flags & BIT(sock_open)) {
            break;
        }
    }
    if (sock_idx == MAX_SOCK_REC){
        shell_error(shell, "Socket %d not found", sd);
        return -EINVAL;
    }
    net_addr_pton(AF_INET, argv[2], &target.sin_addr);
    target.sin_family = AF_INET;
    uint16_t port = (uint16_t)strtol(argv[3], NULL, 10);
    target.sin_port = htons(port);
    int cstat = zsock_connect(sd, (struct sockaddr *)&target, sizeof(target));
    if (cstat == -1) {
        shell_error(shell, "Connection failed, errno = %d", errno);
        return 0;
    }
    socks[sock_idx].flags |= BIT(sock_connected);
    return 0;
}

int sock_bind(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 4){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }
    int sd = strtol(argv[1], NULL, 10);
    int sock_idx;
    for (sock_idx = 0; sock_idx < MAX_SOCK_REC; sock_idx++) {
        if (socks[sock_idx].sd == sd && socks[sock_idx].flags & BIT(sock_open)) {
            break;
        }
    }
    if (sock_idx == MAX_SOCK_REC){
        shell_error(shell, "Socket %d not found", sd);
        return -EINVAL;
    }
    struct sockaddr_in target;
    net_addr_pton(AF_INET, argv[2], &target.sin_addr);
    target.sin_family = AF_INET;
    uint16_t port = (uint16_t)strtol(argv[3], NULL, 10);
    target.sin_port = htons(port);
    int cstat = zsock_bind(sd, (struct sockaddr *)&target, sizeof(target));
    if (cstat == -1) {
        shell_error(shell, "Bind failed, errno = %d", errno);
        return 0;
    }
    socks[sock_idx].flags |= BIT(sock_bound);
    return 0;
}

int sock_send(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 3){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }

    int sd = strtol(argv[1], NULL, 10);
    int sock_idx;
    for (sock_idx = 0; sock_idx < MAX_SOCK_REC; sock_idx++) {
        if (socks[sock_idx].sd == sd && socks[sock_idx].flags & BIT(sock_open)) {
            break;
        }
    }
    if (sock_idx == MAX_SOCK_REC){
        shell_error(shell, "Socket %d not found", sd);
        return -EINVAL;
    }
    int stat = zsock_send(sd, argv[2], strlen(argv[2]), 0);
    if (stat == -1) {
        shell_error(shell, "Send failed, errno = %d", errno);
    }
    return 0;
}

int sock_sendto(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 5){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }

    int sd = strtol(argv[1], NULL, 10);
    int sock_idx;
    for (sock_idx = 0; sock_idx < MAX_SOCK_REC; sock_idx++) {
        if (socks[sock_idx].sd == sd && socks[sock_idx].flags & BIT(sock_open)) {
            break;
        }
    }
    if (sock_idx == MAX_SOCK_REC){
        shell_error(shell, "Socket %d not found", sd);
        return -EINVAL;
    }
    struct sockaddr_in target;
    net_addr_pton(AF_INET, argv[2], &target.sin_addr);
    target.sin_family = AF_INET;
    uint16_t port = (uint16_t)strtol(argv[3], NULL, 10);
    target.sin_port = htons(port);
    int stat = zsock_sendto(sd, argv[4], strlen(argv[4]), 0, (struct sockaddr*)&target, sizeof(target));
    if (stat == -1) {
        shell_error(shell, "Send failed, errno = %d", errno);
    }
    return 0;
}

/**
 * send auto-generated bulk data
 */
int sock_sendb(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 3){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }

    int sd = strtol(argv[1], NULL, 10);
    int sock_idx;
    for (sock_idx = 0; sock_idx < MAX_SOCK_REC; sock_idx++) {
        if (socks[sock_idx].sd == sd && socks[sock_idx].flags & BIT(sock_open)) {
            break;
        }
    }
    if (sock_idx == MAX_SOCK_REC){
        shell_error(shell, "Socket %d not found", sd);
        return -EINVAL;
    }
    int sendsize = strtol(argv[2], NULL, 10);
    sendsize = MIN(sendsize, XFER_SIZE);

    gen_payload(mxfer_buf, sendsize);
    int stat = zsock_send(sd, mxfer_buf, sendsize, 0);
    if (stat == -1) {
        shell_error(shell, "Send failed, errno = %d", errno);
    }
    return 0;
}

/**
 * recv bulk data
 */
int sock_recvb(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 3){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }

    int sd = strtol(argv[1], NULL, 10);
    int sock_idx;
    for (sock_idx = 0; sock_idx < MAX_SOCK_REC; sock_idx++) {
        if (socks[sock_idx].sd == sd && socks[sock_idx].flags & BIT(sock_open)) {
            break;
        }
    }
    if (sock_idx == MAX_SOCK_REC){
        shell_error(shell, "Socket %d not found", sd);
        return -EINVAL;
    }
    int recvsize = strtol(argv[2], NULL, 10);
    recvsize = MIN(recvsize, XFER_SIZE);

    memset(mxfer_buf, 0, recvsize+1);
    int stat = zsock_recv(sd, mxfer_buf, recvsize, 0);
    if (stat == -1) {
        shell_error(shell, "recv failed, errno = %d", errno);
    }
    shell_info(shell, "recv'ed %d", stat);
    return 0;
}


int sock_rcv(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 2){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }
    int sd = (int)strtol(argv[1], NULL, 10);
    int sock_idx;
    for (sock_idx = 0; sock_idx < MAX_SOCK_REC; sock_idx++) {
        if (socks[sock_idx].sd == sd && socks[sock_idx].flags & BIT(sock_open)) {
            break;
        }
    }
    if (sock_idx == MAX_SOCK_REC){
        shell_error(shell, "Socket %d not found", sd);
        return -EINVAL;
    }
    int stat = 0;
    memset(mxfer_buf, 0, XFER_SIZE);
    stat = zsock_recv(sd, mxfer_buf, XFER_SIZE, 0);
    if (stat > 0){
        shell_print(shell, "RECIEVED:\n%s ", (char*)mxfer_buf);
    }
    while (stat == XFER_SIZE) {
        memset(mxfer_buf,0,XFER_SIZE);
        stat = zsock_recv(sd, mxfer_buf, XFER_SIZE, ZSOCK_MSG_DONTWAIT);
        shell_print(shell, "%s", (char*)mxfer_buf);
    }
    if (stat == -1) {
        shell_error(shell, "Recieve failed, errno = %d", errno);
    }
    return 0;
}

int sock_rcvfrom(const struct shell *shell, size_t argc, char **argv)
{
	if (argc < 4){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }
    int sd = (int)strtol(argv[1], NULL, 10);
    int sock_idx;
    int recvlen = 0;
    for (sock_idx = 0; sock_idx < MAX_SOCK_REC; sock_idx++) {
        if (socks[sock_idx].sd == sd && socks[sock_idx].flags & BIT(sock_open)) {
            break;
        }
    }
    if (sock_idx == MAX_SOCK_REC){
        shell_error(shell, "Socket %d not found", sd);
        return -EINVAL;
    }
    struct sockaddr target_6;
    struct sockaddr_in *target = net_sin(&target_6);	//this is useless for "MODEM", the space has to be "struct sockaddr"
    													//otherwise will crash after return from offload_recvfrom
    int addrLen;
    net_addr_pton(AF_INET, argv[2], &target->sin_addr);
    //following code is not necessary for modem, may only required by WIFI?
    target->sin_family = AF_INET;
    uint16_t port = (uint16_t)strtol(argv[3], NULL, 10);
    target->sin_port = htons(port);
    int stat = 0;
    addrLen = sizeof(*target);
    stat = zsock_recvfrom(sd, mxfer_buf, XFER_SIZE, 0, (struct sockaddr*)target, &addrLen);
    if (stat > 0){
        shell_print(shell, "request-len = %d; RECIEVED:\n%s ", recvlen,  (char*)mxfer_buf);
    }
    if (stat == -1) {
        shell_error(shell, "Recieve failed, errno = %d", errno);
    }
    return 0;
}

int sock_close(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 2){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }
    int sd = strtol(argv[1], NULL, 10);
    int sock_idx;
    for (sock_idx = 0; sock_idx < MAX_SOCK_REC; sock_idx++) {
        if (socks[sock_idx].sd == sd && socks[sock_idx].flags & BIT(sock_open)) {
            break;
        }
    }
    if (sock_idx == MAX_SOCK_REC){
        shell_error(shell, "Socket %d not found", sd);
        return -EINVAL;
    }
    int stat = zsock_close(sd);
    if (stat < 0) {
        shell_error(shell, "Close failed, errno = %d", errno);
        return 0;
    }
    socks[sock_idx].flags &= ~BIT(sock_open);
    return 0;
}

int cmd_tmo_list_socks(const struct shell *shell, size_t argc, char **argv)
{
    shell_print(shell, "Open sockets: ");
    for (int i = 0; i < MAX_SOCK_REC; i++) {
        // SD: iface=%d proto=<TCP/UDP> <CONNECTED> <BOUND>
        if (socks[i].flags & BIT(sock_open)) {
            shell_print(shell, "%d: iface=%p proto=%s %s%s",
                socks[i].sd,
                socks[i].dev,
                (socks[i].flags & BIT(sock_tcp)) ? "TCP" : "UDP",
                (socks[i].flags & BIT(sock_connected)) ? "CONNECTED, " : "",
                (socks[i].flags & BIT(sock_bound)) ? "BOUND" : ""
            );
        }
    }
    return 0;
}

int ifcount;
void iface_cb(struct net_if *iface, void *user_data)
{
    const struct shell *shell = (struct shell*)user_data;
    shell_print(shell, "%d: %s", ifcount++, iface->if_dev->dev->name);
}

int cmd_tmo_list_ifaces(const struct shell *shell, size_t argc, char **argv)
{
    ifcount = 1;
    net_if_foreach(iface_cb, (void *)shell);
    return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(tmo_tcp_sub,
                   SHELL_CMD(create, NULL, "[<device>]", tcp_create),
			       SHELL_CMD(connect, NULL, "<ip> <port>", sock_connect),
                   SHELL_CMD(send, NULL, "<socket> <payload>", sock_send),
                   SHELL_CMD(recv, NULL, "<socket>", sock_rcv),
                   SHELL_CMD(sendb, NULL,  "<socket> <size>", sock_sendb),
                   SHELL_CMD(recvb, NULL,  "<socket> <size>", sock_recvb),
                   SHELL_CMD(close, NULL, "<socket>", sock_close),
			       SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(tmo_udp_sub,
			       SHELL_CMD(create, NULL, "[<device>]",  udp_create),
			       SHELL_CMD(connect, NULL, "<socket> <ip> <port>", sock_connect),
                   SHELL_CMD(bind, NULL, " <ip> <port>", sock_bind),
                   SHELL_CMD(send, NULL, "<socket> <payload>", sock_send),
                   SHELL_CMD(sendto, NULL,  "<socket> <ip> <port> <payload>", sock_sendto),
                   SHELL_CMD(sendb, NULL,  "<socket> <size>", sock_sendb),
                   SHELL_CMD(recv, NULL, "<socket>", sock_rcv),
                   SHELL_CMD(recvb, NULL,  "<socket> <size>", sock_recvb),
                   SHELL_CMD(recvfrom, NULL, "<socket> <ip> <port>", sock_rcvfrom),
                   SHELL_CMD(close, NULL, "<socket>", sock_close),
			       SHELL_SUBCMD_SET_END
);


// static int ble_list_connected(const struct shell *shell, int argc, char **argv)
// SHELL_CMD_ARG_REGISTER(tcp, &tmo_tcp_sub, "TCP test commands");

/** Wifi Shell Replacement */
#include <net/wifi_mgmt.h>
#include <net/net_event.h>
#define WIFI_SHELL_MGMT_EVENTS (NET_EVENT_WIFI_SCAN_RESULT |		\
				NET_EVENT_WIFI_SCAN_DONE |		\
				NET_EVENT_WIFI_CONNECT_RESULT |		\
				NET_EVENT_WIFI_DISCONNECT_RESULT)

static struct {
	const struct shell *shell;

	union {
		struct {

			uint8_t connecting		: 1;
			uint8_t disconnecting	: 1;
			uint8_t _unused		: 6;
		};
		uint8_t all;
	};
} context;

static uint32_t scan_result;

static struct net_mgmt_event_callback wifi_shell_mgmt_cb;

#define print(shell, level, fmt, ...)					\
	do {								\
		if (shell) {						\
			shell_fprintf(shell, level, fmt, ##__VA_ARGS__); \
		} else {						\
			printk(fmt, ##__VA_ARGS__);			\
		}							\
	} while (false)

#ifdef CONFIG_WIFI
static void handle_wifi_scan_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_scan_result *entry =
		(const struct wifi_scan_result *)cb->info;
	uint8_t mac_string_buf[sizeof("xx:xx:xx:xx:xx:xx")];

	scan_result++;

	if (scan_result == 1U) {
		print(context.shell, SHELL_NORMAL,
		      "\n%-4s | %-32s %-5s | %-4s | %-4s | %-5s    | %s\n",
		      "Num", "SSID", "(len)", "Chan", "RSSI", "Sec", "MAC");
	}

	print(context.shell, SHELL_NORMAL, "%-4d | %-32s %-5u | %-4u | %-4d | %-5s | %s\n",
	      scan_result, entry->ssid, entry->ssid_length, entry->channel, entry->rssi,
	      (entry->security == WIFI_SECURITY_TYPE_PSK ? "WPA/WPA2" : "Open    "),
	      ((entry->mac_length) ?
		      net_sprint_ll_addr_buf(entry->mac, WIFI_MAC_ADDR_LEN, mac_string_buf,
					     sizeof(mac_string_buf)) : ""));
}

static void handle_wifi_scan_done(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status =
		(const struct wifi_status *)cb->info;

	if (status->status) {
		print(context.shell, SHELL_WARNING,
		      "Scan request failed (%d)\n", status->status);
	} else {
		print(context.shell, SHELL_NORMAL, "Scan request done\n");
	}

	scan_result = 0U;
}

static void handle_wifi_connect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status =
		(const struct wifi_status *) cb->info;

	if (status->status) {
		print(context.shell, SHELL_WARNING,
		      "Connection request failed (%d)\n", status->status);
	} else {
		print(context.shell, SHELL_NORMAL, "Connected\n");
	}

	context.connecting = false;
}

static void handle_wifi_disconnect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status =
		(const struct wifi_status *) cb->info;

	if (context.disconnecting) {
		print(context.shell,
		      status->status ? SHELL_WARNING : SHELL_NORMAL,
		      "Disconnection request %s (%d)\n",
		      status->status ? "failed" : "done",
		      status->status);
		context.disconnecting = false;
	} else {
		print(context.shell, SHELL_NORMAL, "Disconnected\n");
	}
}

static void wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb,
				    uint32_t mgmt_event, struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_WIFI_SCAN_RESULT:
		handle_wifi_scan_result(cb);
		break;
	case NET_EVENT_WIFI_SCAN_DONE:
		handle_wifi_scan_done(cb);
		break;
	case NET_EVENT_WIFI_CONNECT_RESULT:
		handle_wifi_connect_result(cb);
		break;
	case NET_EVENT_WIFI_DISCONNECT_RESULT:
		handle_wifi_disconnect_result(cb);
		break;
	default:
		break;
	}
}

static int __wifi_args_to_params(size_t argc, char *argv[],
				struct wifi_connect_req_params *params)
{
	char *endptr;
	int idx = 1;

	if (argc < 1) {
		return -EINVAL;
	}

	/* SSID */
	params->ssid = argv[0];
	params->ssid_length = strlen(params->ssid);

	/* Channel (optional) */
	if ((idx < argc) && (strlen(argv[idx]) <= 2)) {
		params->channel = strtol(argv[idx], &endptr, 10);
		if (*endptr != '\0') {
			return -EINVAL;
		}

		if (params->channel == 0U) {
			params->channel = WIFI_CHANNEL_ANY;
		}

		idx++;
	} else {
		params->channel = WIFI_CHANNEL_ANY;
	}

	/* PSK (optional) */
	if (idx < argc) {
		params->psk = argv[idx];
		params->psk_length = strlen(argv[idx]);
		params->security = WIFI_SECURITY_TYPE_PSK;
	} else {
		params->security = WIFI_SECURITY_TYPE_NONE;
	}

	return 0;
}


static int cmd_wifi_connect(const struct shell *shell, size_t argc,
			    char *argv[])
{
	// struct net_if *iface = net_if_get_default();

    if (argc < 2){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }
    int idx = strtol(argv[1], NULL, 10);
    struct net_if *iface = net_if_get_by_index(idx);
    if (iface == NULL) {
        shell_error(shell, "Interface %d not found", idx);
        return -EINVAL;
    }

	static struct wifi_connect_req_params cnx_params;

	if (__wifi_args_to_params(argc - 2, &argv[2], &cnx_params)) {
		shell_help(shell);
		return -ENOEXEC;
	}

	context.connecting = true;
	context.shell = shell;

	if (net_mgmt(NET_REQUEST_WIFI_CONNECT, iface,
		     &cnx_params, sizeof(struct wifi_connect_req_params))) {
		shell_fprintf(shell, SHELL_WARNING,
			      "Connection request failed\n");
		context.connecting = false;

		return -ENOEXEC;
	} else {
		shell_fprintf(shell, SHELL_NORMAL,
			      "Connection requested\n");
	}

	return 0;
}

static int cmd_wifi_disconnect(const struct shell *shell, size_t argc,
			       char *argv[])
{
    if (argc < 2){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }
    int idx = strtol(argv[1], NULL, 10);
    struct net_if *iface = net_if_get_by_index(idx);
    if (iface == NULL) {
        shell_error(shell, "Interface %d not found", idx);
        return -EINVAL;
    }

	// struct net_if *iface = net_if_get_default();
	int status;

	context.disconnecting = true;
	context.shell = shell;

	status = net_mgmt(NET_REQUEST_WIFI_DISCONNECT, iface, NULL, 0);

	if (status) {
		context.disconnecting = false;

		if (status == -EALREADY) {
			shell_fprintf(shell, SHELL_INFO,
				      "Already disconnected\n");
		} else {
			shell_fprintf(shell, SHELL_WARNING,
				      "Disconnect request failed\n");
			return -ENOEXEC;
		}
	} else {
		shell_fprintf(shell, SHELL_NORMAL,
			      "Disconnect requested\n");
	}

	return 0;
}

static int cmd_wifi_scan(const struct shell *shell, size_t argc, char *argv[])
{
	// struct net_if *iface = net_if_get_default();
    if (argc < 2){
        shell_error(shell, "Missing required arguments");
        return -EINVAL;
    }
    int idx = strtol(argv[1], NULL, 10);
    struct net_if *iface = net_if_get_by_index(idx);
    if (iface == NULL) {
        shell_error(shell, "Interface %d not found", idx);
        return -EINVAL;
    }

	context.shell = shell;

	if (net_mgmt(NET_REQUEST_WIFI_SCAN, iface, NULL, 0)) {
		shell_fprintf(shell, SHELL_WARNING, "Scan request failed\n");

		return -ENOEXEC;
	} else {
		shell_fprintf(shell, SHELL_NORMAL, "Scan requested\n");
	}

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(tmo_wifi_commands,
	SHELL_CMD(connect, NULL,
		  "<iface> \"<SSID>\"\n<channel number (optional), "
		  "0 means all>\n"
		  "<PSK (optional: valid only for secured SSIDs)>",
		  cmd_wifi_connect),
	SHELL_CMD(disconnect, NULL, "\"<iface>\"",
		  cmd_wifi_disconnect),
	SHELL_CMD(scan, NULL, "\"<iface>\"", cmd_wifi_scan),
	SHELL_SUBCMD_SET_END
);

static int tmo_wifi_shell_init(const struct device *unused)
{
	ARG_UNUSED(unused);

	context.shell = NULL;
	context.all = 0U;
	scan_result = 0U;

	net_mgmt_init_event_callback(&wifi_shell_mgmt_cb,
				     wifi_mgmt_event_handler,
				     WIFI_SHELL_MGMT_EVENTS);

	net_mgmt_add_event_callback(&wifi_shell_mgmt_cb);

	return 0;
}

SYS_INIT(tmo_wifi_shell_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
#endif

/** */

SHELL_STATIC_SUBCMD_SET_CREATE(sub_tmo,
	SHELL_CMD(ifaces, NULL, "list ifaces", cmd_tmo_list_ifaces),
    SHELL_CMD(sockets, NULL, "list open sockets", cmd_tmo_list_socks),
	SHELL_CMD(tcp, &tmo_tcp_sub, "Send/recv TCP packets", NULL),
    SHELL_CMD(udp, &tmo_udp_sub, "Send/recv UDP packets", NULL),
#ifdef CONFIG_WIFI
    SHELL_CMD(wifi, &tmo_wifi_commands, "WiFi Controls", NULL),
#endif
	// SHELL_CMD(ping, NULL, "ping [-c count] [-i interval ms] <host>",  cmd_tmo_ping),
	SHELL_SUBCMD_SET_END /* Array terminated. */
);



SHELL_CMD_REGISTER(tmo, &sub_tmo, "TMO Shell Commands", NULL);

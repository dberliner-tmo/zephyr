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

#undef s6_addr

/**
 * @brief Function to convert between Zephyr and WiSeConnect address formats
 * 
 */
static struct rsi_sockaddr *translate_z_to_rsi_addrs(const struct sockaddr *addr,
					     socklen_t addrlen,
					     struct rsi_sockaddr_in *rsi_addr_in,
					     struct rsi_sockaddr_in6 *rsi_addr_in6,
					     rsi_socklen_t *rsi_addrlen)
{
	struct rsi_sockaddr *rsi_addr = NULL;

	if (addrlen == sizeof(struct sockaddr_in)) {
		memset(rsi_addr_in, 0, sizeof(*rsi_addr_in));
		struct sockaddr_in *z_sockaddr_in = (struct sockaddr_in *)addr;

		*rsi_addrlen = sizeof(struct rsi_sockaddr_in);
		rsi_addr_in->sin_family = RS_AF_INET;
		rsi_addr_in->sin_port = sys_be16_to_cpu(z_sockaddr_in->sin_port);
		rsi_addr_in->sin_addr.s_addr =
			z_sockaddr_in->sin_addr.s_addr;

		rsi_addr = (struct rsi_sockaddr *)rsi_addr_in;
	} else if (addrlen == sizeof(struct sockaddr_in6)) {
		memset(rsi_addr_in6, 0, sizeof(*rsi_addr_in6));
		struct sockaddr_in6 *z_sockaddr_in6 =
			(struct sockaddr_in6 *)addr;

		*rsi_addrlen = sizeof(struct rsi_sockaddr_in6);
		rsi_addr_in6->sin6_family = RS_AF_INET6;
		rsi_addr_in6->sin6_port = sys_be16_to_cpu(z_sockaddr_in6->sin6_port);
		memcpy(rsi_addr_in6->sin6_addr._S6_un._S6_u32,
		       z_sockaddr_in6->sin6_addr.s6_addr,
		       sizeof(rsi_addr_in6->sin6_addr._S6_un._S6_u32));

		rsi_addr = (struct rsi_sockaddr *)rsi_addr_in6;
	}

	return rsi_addr;
}


#define PROTOCOL_TLS_1_0 (BIT(0) | BIT(13))
#define PROTOCOL_TLS_1_1 (BIT(0) | BIT(14))
#define PROTOCOL_TLS_1_2 (BIT(0) | BIT(15))

#define Z_PF_INET         1          /**< IP protocol family version 4. */
#define Z_PF_INET6        2          /**< IP protocol family version 6. */
#define Z_AF_INET        Z_PF_INET     /**< IP protocol family version 4. */
#define Z_AF_INET6       Z_PF_INET6    /**< IP protocol family version 6. */

/**
 * @brief Small Wrapper Around rsi_socket to improve Zephyr compatability
 * 
 */
static int rs_socket(int family, int type, int proto)
{
	int sd;
	int retval = 0;
	int rsi_proto = proto;

	/* Map Zephyr socket.h family to WiSeConnect's: */
	switch (family) {
	case Z_AF_INET:
		family = RS_AF_INET;
		break;
	case Z_AF_INET6:
		family = RS_AF_INET6;
		break;
	default:
		LOG_ERR("unsupported family: %d", family);
		errno = EAFNOSUPPORT;
		return -1;
	}

	/* Map Zephyr socket.h type to WiSeConnect's: */
	switch (type) {
	case SOCK_STREAM:
	case SOCK_DGRAM:
	case SOCK_RAW:
		break;
	default:
		LOG_ERR("unrecognized type: %d", type);
		errno = ESOCKTNOSUPPORT;
		return -1;
	}

	/* Map Zephyr protocols to the 9116's values: */
	if (proto >= IPPROTO_TLS_1_0 && proto <= IPPROTO_TLS_1_2) {
		/* Todo: Check TLS enabled*/
		
		switch (proto){
			case IPPROTO_TLS_1_0:
				rsi_proto = PROTOCOL_TLS_1_0;
				break;
			case IPPROTO_TLS_1_1:
				rsi_proto = PROTOCOL_TLS_1_1;
				break;
			case IPPROTO_TLS_1_2:
				rsi_proto = PROTOCOL_TLS_1_2;
				break;
		}
	} else if (proto >= IPPROTO_DTLS_1_0 && proto <= IPPROTO_DTLS_1_2) {
		/* Don't think the 9116 supports DTLS */
		errno = EPROTONOSUPPORT;
		return -1;
	} else {
		switch (proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			rsi_proto = 0;
			break;
		default:
			LOG_ERR("unrecognized proto: %d", proto);
			errno = EPROTONOSUPPORT;
			return -1;
		}
	}

	sd = rsi_socket(family, type, rsi_proto);
	if (sd >= 0) {
		if (IS_ENABLED(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
		    && rsi_proto == 1) {
			if (retval < 0) {
				(void)rsi_shutdown(sd,0);
				errno = EPROTONOSUPPORT;
				return -1;
			}
		}
	}

	retval = sd;

	return retval;
}
// offload functions

/****************************************************************************/
/**
 * This function is called when the socket is to be opened.
 */
static int rs9116w_get(sa_family_t family,
        enum net_sock_type type,
        enum net_ip_protocol ip_proto,
        struct net_context **context)
{
    struct rs9116w_device *dev = rs9116w_by_iface_idx((*context)->iface);
    struct rs9116w_socket *socket = NULL;
    int32_t socket_idx;

    printk("In rs9116w_get (opening a socket), family:%d, type: %d, proto: %d \n",
            family, type, ip_proto);
    /*
     * 10.5.2 int32_t rsi_socket(int32_t protocolFamily, int32_t type, uint32_t protocol);
     */
    // third param is ip_proto
    // ip_proto = 0 for non SSL sockets
    //            1 for SSL sockets
    // TBD: Set ip_proto appropriately for SSL sockets
    // socket_idx = rsi_socket(family + 1, type, 0);
    socket_idx = rs_socket(family, type, ip_proto);

    printk("Socket index %d\n", socket_idx);

    if (socket_idx < 0)
        return socket_idx;

    socket = &dev->sockets[socket_idx];
    (*context)->offload_context = socket;

    return socket_idx;
}

/****************************************************************************/
/**
 * This function is called when user wants to create a connection
 * to a peer host.
 */
static int rs9116w_connect(struct net_context *context,
        const struct sockaddr *addr,
        socklen_t addrlen,
        net_context_connect_cb_t cb,
        int32_t timeout,
        void *user_data)
{
    struct rs9116w_socket *rs_socket = context->offload_context;
    // struct rsi_sockaddr_in r_sockaddr;
    // const struct sockaddr_in *addr_in = (const struct sockaddr_in *) addr;

    // printk("In rs9116w_connect, port number: %u\n", addr_in->sin_port);
    /* TBD: add support for cb, timeout, and user_data */

    /*
     * Document shows this:
     * 10.5.4 int32_t rsi_connect(uint32_t sockID, struct sockaddr *remoteAddress, int32_t addressLength);
     *
     * HOWEVER, rsi_socket.h defines rsi_connect like this:
     * int32_t  rsi_connect(int32_t sockID, struct rsi_sockaddr *remoteAddress, int32_t addressLength);
     *
     * 'struct sockaddr' and 'struct rsi_sockaddr' are not identical:
     *
     * struct sockaddr {
     *     sa_family_t sa_family;                                         sa_family_t is "unsigned short int"
     *     char        data[NET_SOCKADDR_MAX_SIZE - sizeof(sa_family_t)]; NET_SOCKADDR_MAX_SIZE depends on CONFIG_NET_IPV4, CONFIG_NET_SOCKETS_PACKET, and CONFIG 
     * };
     *
     * struct rsi_sockaddr {
     *     uint16_t sa_family; 
     *     uint8_t  sa_data[14];
     * };
     */

    /* bind to local addr if not already done */
    // if (rs9116w_local_bind(rs_socket, addr_in->sin_port))
    //     return -1;

    // Before calling connect, WiseConnect needs to bind to local address, we need the port number for this
    // addr_in = (const struct sockaddr_in *) addr;
    // printk("In rs9116w_connect, connecting to 0x%x\n", addr_in->sin_addr.s_addr);

    struct rsi_sockaddr *rsi_addr;
	struct rsi_sockaddr_in rsi_addr_in;
	struct rsi_sockaddr_in6 rsi_addr_in6;
	rsi_socklen_t rsi_addrlen;

    rsi_addr = translate_z_to_rsi_addrs(addr, addrlen, &rsi_addr_in,
					  &rsi_addr_in6, &rsi_addrlen);

    // r_sockaddr.sin_family = addr_in->sin_family + 1;
    // r_sockaddr.sin_port = addr_in->sin_port;
    // r_sockaddr.sin_addr.s_addr = addr_in->sin_addr.s_addr;

    printk("About to call rsi_connect\n");
    int ret = rsi_connect(rs_socket->sock_id, rsi_addr, rsi_addrlen);
    printk("returned from rsi_connect, ret=%d, errno=%d\n", ret, errno);

    return ret;
}

static int rs9116w_bind(struct net_context *context, const struct sockaddr *addr,
		    socklen_t addrlen)
{
    struct rs9116w_socket *rs_socket = context->offload_context;
    // struct rsi_sockaddr_in r_sockaddr;
    // const struct sockaddr_in *addr_in = (const struct sockaddr_in *) addr;
    int ret;

    // printk("In rs9116w_bind, binding to address 0x%x, port %u\n", addr_in->sin_addr.s_addr, addr_in->sin_port);

    // ret = rs9116w_local_bind(rs_socket, addr_in->sin_port);
    // if (ret != 0 || addr_in->sin_addr.s_addr == 0)
    //     return ret;

    struct rsi_sockaddr *rsi_addr;
	struct rsi_sockaddr_in rsi_addr_in;
	struct rsi_sockaddr_in6 rsi_addr_in6;
	rsi_socklen_t rsi_addrlen;

    rsi_addr = translate_z_to_rsi_addrs(addr, addrlen, &rsi_addr_in,
					  &rsi_addr_in6, &rsi_addrlen);

    // r_sockaddr.sin_family = addr_in->sin_family + 1;
    // r_sockaddr.sin_port = addr_in->sin_port;
    // r_sockaddr.sin_addr.s_addr = addr_in->sin_addr.s_addr;

    /*
     * 10.5.3 int32_t rsi_bind(uint32_t sockID, struct sockaddr *localAddress, int32_t addressLength);
     */
    printk("About to call rsi_bind\n");
    ret = rsi_bind(rs_socket->sock_id, rsi_addr, rsi_addrlen);
    printk("Returned from rsi_bind, ret=%d\n", ret);

    return ret;
}


/****************************************************************************/
/**
 * This function is called when user wants to send data to peer host.
 */
static int rs9116w_sendto(struct net_pkt *pkt,
        const struct sockaddr *dst_addr,
        socklen_t addrlen,
        net_context_send_cb_t cb,
        int32_t timeout,
        void *user_data)
{
    struct rs9116w_socket *rs_socket = pkt->context->offload_context;
    // struct rs9116w_device *rs9116w_dev = rs9116w_socket_to_dev(rs_socket);
    unsigned int bytes;
    int ret;
    // struct rsi_sockaddr_in rsi_addr;
    // const struct sockaddr_in *addr_in = (const struct sockaddr_in *) dst_addr;

    // printk("In rs9116w_sendto, port: %d\n", addr_in->sin_port);

    /* bind to local addr if not already done */
    // if (rs9116w_local_bind(rs_socket, addr_in->sin_port))
    //     return -1;

    bytes = net_pkt_get_len(pkt);

    if (net_pkt_read(pkt, rs_socket->pkt_data_out, bytes)) {
        return -ENOBUFS;
    }

    // Convert struct sockaddr dst_addr to struct rsi_sockaddr rsi_sockaddr
    // rsi_addr.sin_family = addr_in->sin_family + 1;
    // rsi_addr.sin_port = htons(addr_in->sin_port);       // seems to be a bug in rsi_sendto requiring this
    // rsi_addr.sin_addr.s_addr = addr_in->sin_addr.s_addr;

    struct rsi_sockaddr *rsi_addr;
	struct rsi_sockaddr_in rsi_addr_in;
	struct rsi_sockaddr_in6 rsi_addr_in6;
	rsi_socklen_t rsi_addrlen;

    rsi_addr = translate_z_to_rsi_addrs(dst_addr, addrlen, &rsi_addr_in,
					  &rsi_addr_in6, &rsi_addrlen);

    /*
     * 10.5.11 int32_t rsi_sendto(uint32_t sockID, int8_t *msg, int32_t msgLength, int32_t flags, struct sockaddr *destAddr, int32_t destAddrLen); 
     */
    ret = rsi_sendto(rs_socket->sock_id, rs_socket->pkt_data_out, bytes, 0, rsi_addr, rsi_addrlen);

    net_pkt_unref(pkt);

    return ret;
}

/****************************************************************************/
/**
 * This function is called when user wants to send data to peer host.
 */
static int rs9116w_send(struct net_pkt *pkt,
        net_context_send_cb_t cb,
        int32_t timeout,
        void *user_data)
{
    printk("In rs9116w_send\n");

    return rs9116w_sendto(pkt, NULL, 0, cb, timeout, user_data);
}

/****************************************************************************/
/**
 * This function is called when user wants to receive data from peer host.
 */
static int rs9116w_recv(struct net_context *context,
        net_context_recv_cb_t cb,
        int32_t timeout,
        void *user_data)
{
    struct rs9116w_socket *rs_socket = context->offload_context;
    struct rs9116w_device *rs9116w_dev = rs9116w_socket_to_dev(rs_socket);
    // const struct sockaddr_in *addr_in = (const struct sockaddr_in *) &context->remote;
    struct net_pkt *pkt;

    printk("In rs9116w_recv\n");

    /* bind to local addr if not already done */
    // if (rs9116w_local_bind(rs_socket, addr_in->sin_port))
    //     return -1;

    pkt = net_pkt_rx_alloc_with_buffer(rs9116w_dev->net_iface, RSI_MAX_PAYLOAD_SIZE, AF_UNSPEC, 0, K_NO_WAIT);

    if (!pkt) {
        LOG_ERR("Cannot allocate rx packet");
        return -ENOMEM;
    }

    if (timeout == 0) {
        struct rsi_timeval ptv;
		ptv.tv_sec = 0;
		ptv.tv_usec = 0;
		rsi_fd_set rfds;
		RSI_FD_ZERO(&rfds);
		RSI_FD_SET(rs_socket->sock_id, &rfds);
		rsi_select(rs_socket->sock_id + 1, &rfds, NULL, NULL, &ptv, NULL);
		if (!RSI_FD_ISSET(rs_socket->sock_id, &rfds)){
			return 0;
		}
    }

    /* 
     * 10.5.10 int32_t rsi_recv(uint32_t sockID, VOID *rcvBuffer, int32_t bufferLength, int32_t flags);
     */
    rs_socket->pkt_size_in = rsi_recv(rs_socket->sock_id, rs_socket->pkt_data_in, RSI_MAX_PAYLOAD_SIZE, 0);
    if (rs_socket->pkt_size_in == -1) {
        return -errno;
    }
    net_pkt_write(pkt, rs_socket->pkt_data_in, rs_socket->pkt_size_in);
    return rs_socket->pkt_size_in;
}

/****************************************************************************/
/**
 * This function is called when user wants to close the socket.
 */
static int rs9116w_put(struct net_context *context)
{
    struct rs9116w_socket *rs_socket = context->offload_context;

    printk("In rs9116w_put (close socket)\n");

    rs_socket->local_bound = 0;

    /*
     * 10.5.15 int32_t rsi_shutdown(uint32_t sockID, int32_t how);
     */
    return rsi_shutdown(rs_socket->sock_id, 0);
}

/****************************************************************************/

static struct net_offload rs9116w_offload = {
    .get      = rs9116w_get,
    .bind     = rs9116w_bind,
    .connect  = rs9116w_connect,
    .send     = rs9116w_send,
    .sendto   = rs9116w_sendto,
    .recv     = rs9116w_recv,
    .put      = rs9116w_put
};

int rs9116w_offload_init(struct rs9116w_device *rs9116w)
{
    rs9116w->net_iface->if_dev->offload = &rs9116w_offload;

    // TBD: What else goes here?

#if defined(CONFIG_NET_SOCKETS_OFFLOAD)
    rs9116w->net_iface->if_dev->offloaded = true;
    rs9116w->net_iface->if_dev->socket = rs9116w_socket_create;
    rs9116w_socket_offload_init();
#endif

    return 0;
}

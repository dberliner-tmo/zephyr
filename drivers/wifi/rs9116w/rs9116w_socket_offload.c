/*
 * Copyright (c) 2021 T-Mobile USA, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_MODULE_NAME wifi_rs9116w_socket_offload
#define LOG_LEVEL CONFIG_WIFI_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME);


#include "rs9116w.h"

#include <zephyr.h>
#include <kernel.h>
#include <device.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <net/socket_offload.h>
#include <net/tls_credentials.h>

#include "sockets_internal.h"
#include "tls_internal.h"
#include <rsi_wlan_common_config.h>
#include <rsi_wlan_apis.h>
#include <rsi_wlan_non_rom.h>
#include <rsi_socket.h>
#include <net/net_pkt.h>

/* Dealing with mismatched define values */
/* Protocol families. */
#define Z_PF_UNSPEC       0          /**< Unspecified protocol family.  */
#define Z_PF_INET         1          /**< IP protocol family version 4. */
#define Z_PF_INET6        2          /**< IP protocol family version 6. */
#define Z_PF_PACKET       3          /**< Packet family.                */
#define Z_PF_CAN          4          /**< Controller Area Network.      */
#define Z_PF_NET_MGMT     5          /**< Network management info.      */
#define Z_PF_LOCAL        6          /**< Inter-process communication   */
#define Z_PF_UNIX         PF_LOCAL   /**< Inter-process communication   */

/* Address families. */
#define Z_AF_UNSPEC      Z_PF_UNSPEC   /**< Unspecified address family.   */
#define Z_AF_INET        Z_PF_INET     /**< IP protocol family version 4. */
#define Z_AF_INET6       Z_PF_INET6    /**< IP protocol family version 6. */
#define Z_AF_PACKET      Z_PF_PACKET   /**< Packet family.                */
#define Z_AF_CAN         Z_PF_CAN      /**< Controller Area Network.      */
#define Z_AF_NET_MGMT    Z_PF_NET_MGMT /**< Network management info.      */
#define Z_AF_LOCAL       Z_PF_LOCAL    /**< Inter-process communication   */
#define Z_AF_UNIX        Z_PF_UNIX     /**< Inter-process communication   */


/* Socket options for SOL_SOCKET level */
/** sockopt: Enable server address reuse (ignored, for compatibility) */
#define Z_SO_REUSEADDR 2

/* Socket options for IPPROTO_IPV6 level */
/** sockopt: Don't support IPv4 access (ignored, for compatibility) */
#define Z_IPV6_V6ONLY 26


#undef s6_addr
#undef IPPROTO_TCP
#undef IPPROTO_UDP


#define FAILED (-1)

/* Increment by 1 to make sure we do not store the value of 0, which has
 * a special meaning in the fdtable subsys.
 */
#define SD_TO_OBJ(sd) ((void *)(sd + 1))
#define OBJ_TO_SD(obj) (((int)obj) - 1)


static int rs9116w_socket(int family, int type, int proto)
{
	// uint8_t sec_method = SL_SO_SEC_METHOD_SSLv3_TLSV1_2;
	int sd;
	int retval = 0;
	int rsi_proto = proto;

	/* Map Zephyr socket.h family to WiSeConnect's: */
	switch (family) {
	case Z_AF_INET:
		family = AF_INET;
		break;
	case Z_AF_INET6:
		family = AF_INET6;
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
			/* There is a way to do it with sockopts for the 9116 (i think),
			    but i don't know if its the best solution*/

			/* Now, set specific TLS version via setsockopt(): */
			// sec_method = (proto - IPPROTO_TLS_1_0) +
			// 	SL_SO_SEC_METHOD_TLSV1;
			// retval = sl_SetSockOpt(sd, SL_SOL_SOCKET,
			// 	SL_SO_SECMETHOD,
			// 	&sec_method, sizeof(sec_method));
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

static int rs9116w_close(void *obj)
{
	int sd = OBJ_TO_SD(obj);
	int retval;

	retval = rsi_shutdown(sd, 0);

	if (retval < 0) {
		// errno = rsi_wlan_get_status();
		return -1;
	}

	return retval;
}


static struct rsi_sockaddr *translate_z_to_rsi_addrlen(socklen_t addrlen,
					       struct rsi_sockaddr_in *rsi_addr_in,
					       struct rsi_sockaddr_in6 *rsi_addr_in6,
					       rsi_socklen_t *rsi_addrlen)
{
	struct rsi_sockaddr *rsi_addr = NULL;

	if (addrlen == sizeof(struct sockaddr_in)) {
		*rsi_addrlen = sizeof(struct rsi_sockaddr_in);
		rsi_addr = (struct rsi_sockaddr *)rsi_addr_in;
	} else if (addrlen == sizeof(struct sockaddr_in6)) {
		*rsi_addrlen = sizeof(struct rsi_sockaddr_in6);
		rsi_addr = (struct rsi_sockaddr *)rsi_addr_in6;
	}

	return rsi_addr;
}

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
		rsi_addr_in->sin_family = AF_INET;
		rsi_addr_in->sin_port = sys_be16_to_cpu(z_sockaddr_in->sin_port);
		rsi_addr_in->sin_addr.s_addr =
			z_sockaddr_in->sin_addr.s_addr;

		rsi_addr = (struct rsi_sockaddr *)rsi_addr_in;
	} else if (addrlen == sizeof(struct sockaddr_in6)) {
		memset(rsi_addr_in6, 0, sizeof(*rsi_addr_in6));
		struct sockaddr_in6 *z_sockaddr_in6 =
			(struct sockaddr_in6 *)addr;

		*rsi_addrlen = sizeof(struct rsi_sockaddr_in6);
		rsi_addr_in6->sin6_family = AF_INET6;
		rsi_addr_in6->sin6_port = sys_be16_to_cpu(z_sockaddr_in6->sin6_port);
		memcpy(rsi_addr_in6->sin6_addr._S6_un._S6_u32,
		       z_sockaddr_in6->sin6_addr.s6_addr,
		       sizeof(rsi_addr_in6->sin6_addr._S6_un._S6_u32));

		rsi_addr = (struct rsi_sockaddr *)rsi_addr_in6;
	}

	return rsi_addr;
}

static void translate_rsi_to_z_addr(struct rsi_sockaddr *rsi_addr,
				   rsi_socklen_t rsi_addrlen,
				   struct sockaddr *addr,
				   socklen_t *addrlen)
{
	struct rsi_sockaddr_in *rsi_addr_in;
	struct rsi_sockaddr_in6 *rsi_addr_in6;

	if (rsi_addr->sa_family == AF_INET) {
		if (rsi_addrlen == (rsi_socklen_t)sizeof(struct rsi_sockaddr_in)) {
			struct sockaddr_in *z_sockaddr_in =
				(struct sockaddr_in *)addr;
			rsi_addr_in = (struct rsi_sockaddr_in *)rsi_addr;
			z_sockaddr_in->sin_family = Z_AF_INET;
			z_sockaddr_in->sin_port = sys_cpu_to_be16(rsi_addr_in->sin_port);
			z_sockaddr_in->sin_addr.s_addr =
				rsi_addr_in->sin_addr.s_addr;
			*addrlen = sizeof(struct sockaddr_in);
		} else {
			*addrlen = rsi_addrlen;
		}
	} else if (rsi_addr->sa_family == AF_INET6) {
		if (rsi_addrlen == sizeof(struct rsi_sockaddr_in6)) {
			struct sockaddr_in6 *z_sockaddr_in6 =
				(struct sockaddr_in6 *)addr;
			rsi_addr_in6 = (struct rsi_sockaddr_in6 *)rsi_addr;

			z_sockaddr_in6->sin6_family = Z_AF_INET6;
			z_sockaddr_in6->sin6_port = sys_cpu_to_be16(rsi_addr_in6->sin6_port);
			z_sockaddr_in6->sin6_scope_id =
				(uint8_t)rsi_addr_in6->sin6_scope_id;
			memcpy(z_sockaddr_in6->sin6_addr.s6_addr,
			       rsi_addr_in6->sin6_addr._S6_un._S6_u32,
			       sizeof(z_sockaddr_in6->sin6_addr.s6_addr));
			*addrlen = sizeof(struct sockaddr_in6);
		} else {
			*addrlen = rsi_addrlen;
		}
	}
}

static int rs9116w_accept(void *obj, struct sockaddr *addr,
			     socklen_t *addrlen)
{
	int sd = OBJ_TO_SD(obj);
	int retval;
	struct rsi_sockaddr *rsi_addr;
	struct rsi_sockaddr_in rsi_addr_in;
	struct rsi_sockaddr_in6 rsi_addr_in6;
	rsi_socklen_t rsi_addrlen;

	if ((addrlen == NULL) || (addr == NULL)) {
		errno = EINVAL;
		return -1;
	}

	/* Translate between Zephyr's and WiSeConnects's sockaddr's: */
	rsi_addr = translate_z_to_rsi_addrlen(*addrlen, &rsi_addr_in, &rsi_addr_in6,
				  &rsi_addrlen);
	if (rsi_addr == NULL) {
		errno = EINVAL;
		return -1;
	}

	retval = rsi_accept(sd, rsi_addr, &rsi_addrlen);
	
	if (retval < 0) {
		errno = rsi_wlan_get_status();
		return -1;
	}

	/* Translate returned rsi_addr into *addr and set *addrlen: */
	translate_rsi_to_z_addr(rsi_addr, rsi_addrlen, addr, addrlen);

	return retval;
}


static int rs9116w_bind(void *obj, const struct sockaddr *addr,
			   socklen_t addrlen)
{
	int sd = OBJ_TO_SD(obj);
	LOG_DBG("SOCK BIND %d", sd);
	int retval;
	struct rsi_sockaddr *rsi_addr;
	struct rsi_sockaddr_in rsi_addr_in;
	struct rsi_sockaddr_in6 rsi_addr_in6;
	rsi_socklen_t rsi_addrlen;

	if (addr == NULL) {
		errno = EINVAL;
		return -1;//EISDIR?
	}

	/* Translate to rsi_bind() parameters: */
	rsi_addr = translate_z_to_rsi_addrs(addr, addrlen, &rsi_addr_in,
					  &rsi_addr_in6, &rsi_addrlen);

	if (rsi_addr == NULL) {
		errno = EINVAL;
		return -1;
	}
	retval = rsi_bind(sd, rsi_addr, rsi_addrlen);

	return retval;
}

static int rs9116w_listen(void *obj, int backlog)
{
	int sd = OBJ_TO_SD(obj);
	int retval;

	retval = (int)rsi_listen(sd, backlog);

	return retval;
}


static int rs9116w_connect(void *obj, const struct sockaddr *addr,
			      socklen_t addrlen)
{
	int sd = OBJ_TO_SD(obj);
	int retval;
    struct rsi_sockaddr *rsi_addr;
	struct rsi_sockaddr_in rsi_addr_in;
	struct rsi_sockaddr_in6 rsi_addr_in6;
	rsi_socklen_t rsi_addrlen;

	__ASSERT_NO_MSG(addr);

	/* Translate to rsi_connect() parameters: */
	rsi_addr = translate_z_to_rsi_addrs(addr, addrlen, &rsi_addr_in,
					  &rsi_addr_in6, &rsi_addrlen);

	if (rsi_addr == NULL) {
		errno = EINVAL;
		return -1;
	}

	retval = rsi_connect(sd, rsi_addr, rsi_addrlen);
	// errno = rsi_wlan_get_status();
	return retval;
}

static const struct socket_op_vtable rs9116w_socket_fd_op_vtable;

static int rs9116w_poll(struct zsock_pollfd *fds, int nfds, int msecs)
{
	int max_sd = 0;
	struct rsi_timeval tv, *ptv;
	rsi_fd_set rfds;	 /* Set of read file descriptors */
	rsi_fd_set wfds;	 /* Set of write file descriptors */
	int i, retval = 0, sd;
	void *obj;

	if (nfds > FD_SETSIZE) {
		errno = EINVAL;
		return -1;
	}

	/* Convert time to rsi_timeval struct values: */
	if (msecs == SYS_FOREVER_MS) {
		ptv = NULL;
	} else {
		tv.tv_sec = msecs / 1000;
		tv.tv_usec = (msecs % 1000) * 1000;
		ptv = &tv;
	}

	/* Setup read and write fds for select, based on pollfd fields: */
	RSI_FD_ZERO(&rfds);
	RSI_FD_ZERO(&wfds);

	for (i = 0; i < nfds; i++) {
		fds[i].revents = 0;
		if (fds[i].fd < 0) {
			continue;
		} else {
			obj = z_get_fd_obj(fds[i].fd,
					   (const struct fd_op_vtable *)
						&rs9116w_socket_fd_op_vtable,
					   ENOTSUP);
			if (obj != NULL) {
				/* Offloaded socket found. */
				sd = OBJ_TO_SD(obj);
			} else {
				/* Non-offloaded socket, return an error. */
				errno = EINVAL;
				return -1;
			}
		}
		if (fds[i].events & ZSOCK_POLLIN) {
			RSI_FD_SET(sd, &rfds);
		}
		if (fds[i].events & ZSOCK_POLLOUT) {
			RSI_FD_SET(sd, &wfds);
		}
		if (sd > max_sd) {
			max_sd = sd;
		}
	}

	/* Wait for requested read and write fds to be ready: */
	retval = rsi_select(max_sd + 1, &rfds, &wfds, NULL, ptv, NULL);
	
	if (retval > 0) {
		for (i = 0; i < nfds; i++) {
			if (fds[i].fd >= 0) {
				obj = z_get_fd_obj(
					fds[i].fd,
					(const struct fd_op_vtable *)
						&rs9116w_socket_fd_op_vtable,
					ENOTSUP);
				sd = OBJ_TO_SD(obj);
				if (RSI_FD_ISSET(sd, &rfds)) {
					fds[i].revents |= ZSOCK_POLLIN;
				}
				if (RSI_FD_ISSET(sd, &wfds)) {
					fds[i].revents |= ZSOCK_POLLOUT;
				}
			}
		}
	}

	return retval;
}

//Deal with TLS !TODO
#ifdef CONFIG_NET_SOCKETS_SOCKOPT_TLS
#include <sys/base64.h>
uint8_t pem[6144];

static uint8_t cert_idx_ca = 0, cert_idx_pkey = 0, cert_idx_crt = 0;

static int map_credentials(int sd, const void *optval, socklen_t optlen)
{
	sec_tag_t *sec_tags = (sec_tag_t *)optval;
	int retval = 0;
	int sec_tags_len;
	sec_tag_t tag;
	int cert_type;
	int i;
	struct tls_credential *cert;

	if ((optlen % sizeof(sec_tag_t)) != 0 || (optlen == 0)) {
		retval = EINVAL;
		goto exit;
	} else {
		sec_tags_len = optlen / sizeof(sec_tag_t);
	}

	/* For each tag, retrieve the credentials value and type: */
	for (i = 0; i < sec_tags_len; i++) {
		tag = sec_tags[i];
		cert = credential_next_get(tag, NULL);
		uint8_t cert_idx;
		int offset;
		char *header, *footer;
		while (cert != NULL) {
			/* Map Zephyr cert types to WiSeConnect cert types: */
			switch (cert->type) {
			case TLS_CREDENTIAL_CA_CERTIFICATE:
				cert_type = RSI_SSL_CA_CERTIFICATE;
				header = "-----BEGIN CERTIFICATE-----\n";
				footer = "\n-----END CERTIFICATE-----\n";
				cert_idx = cert_idx_ca;
				cert_idx_ca++;
				cert_idx_ca %= 2;
				break;
			case TLS_CREDENTIAL_SERVER_CERTIFICATE:
				cert_type = RSI_SSL_SERVER_CERTIFICATE;
				cert_idx = cert_idx_crt;
				cert_idx_crt++;
				cert_idx_crt %= 2;
				header = "-----BEGIN CERTIFICATE-----\n";
				footer = "\n-----END CERTIFICATE-----\n";
				// if (cert_idx_crt == 2) {
				// 	LOG_WARN("Certificate Wraparound?")
				// }
				break;
			case TLS_CREDENTIAL_PRIVATE_KEY:
				cert_type = RSI_SSL_CLIENT_PRIVATE_KEY; //Maybe server?
				cert_idx = cert_idx_pkey;
				cert_idx_pkey++;
				cert_idx_pkey %= 2;
				header = "-----BEGIN RSA PRIVATE KEY-----\n";
				footer = "\n-----END RSA PRIVATE KEY-----\n";
				break;
			case TLS_CREDENTIAL_NONE:
			case TLS_CREDENTIAL_PSK:
			case TLS_CREDENTIAL_PSK_ID:
			default:
				retval = -EINVAL;
				goto exit;
			}
			uint32_t ce_val = cert_idx;
			strcpy(pem, header);
			offset = strlen(header);
			size_t written;
			base64_encode(pem + offset, 6144 - offset - strlen(footer), &written, cert->buf, cert->len);
			memcpy(pem + offset + written, footer, strlen(footer));
			retval = rsi_wlan_set_certificate_index(cert_type, cert_idx, pem, offset + written + strlen(footer));
			if (retval < 0) {
				break;
			}
			retval = rsi_setsockopt(sd, SOL_SOCKET, SO_CERT_INDEX, &ce_val, sizeof(ce_val));
			if (retval < 0) {
				// retval = getErrno(retval);
				break;
			}
			cert = credential_next_get(tag, cert);
		}
	}

exit:
	return retval;
}
#else
static int map_credentials(int sd, const void *optval, socklen_t optlen)
{
	return 0;
}
#endif  /* CONFIG_NET_SOCKETS_SOCKOPT_TLS */

/* This was borrowed from simplelink, undoubtedly some sockopts aren't defined */
#define Z_SO_BROADCAST  (200)
#define Z_SO_SNDBUF     (202)

static int rs9116w_setsockopt(void *obj, int level, int optname,
				 const void *optval, socklen_t optlen)
{
	/*Unsure if all the sockopts are actuall supported; Documentation is unclear */
	int sd = OBJ_TO_SD(obj);
	int retval;

	//Todo, tls stuff
	if (IS_ENABLED(CONFIG_NET_SOCKETS_SOCKOPT_TLS) && level == SOL_TLS) {
		/* Handle Zephyr's SOL_TLS secure socket options: */
		switch (optname) {
		case TLS_SEC_TAG_LIST:
			/* Bind credential filenames to this socket: */
			retval = map_credentials(sd, optval, optlen);
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
		case TLS_HOSTNAME: //SNI?
			return rsi_setsockopt(sd, level, SO_TLS_SNI, optval, (rsi_socklen_t)optlen);
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
		case Z_SO_BROADCAST:
			return rsi_setsockopt(sd, level, SO_BROADCAST, optval, (rsi_socklen_t)optlen);
		case Z_SO_REUSEADDR:
			return rsi_setsockopt(sd, level, SO_REUSEADDR, optval, (rsi_socklen_t)optlen);
		case Z_SO_SNDBUF:
			return rsi_setsockopt(sd, level, SO_SNDBUF, optval, (rsi_socklen_t)optlen);
		case Z_IPV6_V6ONLY:
			errno = EINVAL;
			return -1;
		default:
			break;
		}
		return rsi_setsockopt(sd, SOL_SOCKET, optname, optval,
				       (rsi_socklen_t)optlen);
	}

	return retval;
}

static int rs9116w_getsockopt(void *obj, int level, int optname,
				 void *optval, socklen_t *optlen)
{
	/*Unsure if all the sockopts are actuall supported; Documentation is unclear */
	int sd = OBJ_TO_SD(obj);
	int retval;
	//Todo, tls stuff
	if (IS_ENABLED(CONFIG_NET_SOCKETS_SOCKOPT_TLS) && level == SOL_TLS) {
		/* Handle Zephyr's SOL_TLS secure socket options: */
		switch (optname) {
		case TLS_SEC_TAG_LIST:
		case TLS_CIPHERSUITE_LIST:
		case TLS_CIPHERSUITE_USED:
			/* Not yet supported: */
			errno = ENOTSUP;
			return -1;
		default:
			errno = EINVAL;
			return -1;
		}
	} else {
		/* Can be SOL_SOCKET or TI specific: */

		switch (optname) {
			/* TCP_NODELAY always set by the NWP, so return True */
		case Z_SO_BROADCAST:
			return rsi_getsockopt(sd, SOL_SOCKET, SO_BROADCAST, optval, *(rsi_socklen_t *)optlen);
		case Z_SO_REUSEADDR:
			return rsi_getsockopt(sd, SOL_SOCKET, SO_REUSEADDR, optval, *(rsi_socklen_t *)optlen);
		case Z_SO_SNDBUF:
			return rsi_getsockopt(sd, SOL_SOCKET, SO_SNDBUF, optval, *(rsi_socklen_t *)optlen);
		case Z_IPV6_V6ONLY:
			errno = EINVAL;
			return -1;
		default:
			break;
		}
		/* Optlen is actually unused? */
		return rsi_getsockopt(sd, SOL_SOCKET, optname, optval,
				       *(rsi_socklen_t *)optlen);
	}

}


static ssize_t rs9116w_recvfrom(void *obj, void *buf, size_t len, int flags,
				   struct sockaddr *from, socklen_t *fromlen)
{
	int sd = OBJ_TO_SD(obj);
	ssize_t retval;
	struct rsi_sockaddr *rsi_addr;
	struct rsi_sockaddr_in rsi_addr_in;
	struct rsi_sockaddr_in6 rsi_addr_in6;
	rsi_socklen_t rsi_addrlen;
	if (flags & ~ZSOCK_MSG_DONTWAIT){
		errno = ENOTSUP;
		return -1;
	}
	/* Non-blocking is only able to be set on socket creation
	 * Also doesn't affect recieve anyways
	 * Therefore, this is the simplest solution...
	 */
	if (flags & ZSOCK_MSG_DONTWAIT) {
		struct rsi_timeval ptv;
		ptv.tv_sec = 0;
		ptv.tv_usec = 0;
		rsi_fd_set rfds;
		RSI_FD_ZERO(&rfds);
		RSI_FD_SET(sd, &rfds);
		rsi_select(sd + 1, &rfds, NULL, NULL, &ptv, NULL);
		if (!RSI_FD_ISSET(sd, &rfds)){
			errno = EAGAIN;
			return -1;
		}
	}

	if (!retval) {
		/* Translate to rsi_recvfrom() parameters: */
		if (fromlen != NULL) {
			rsi_addr = translate_z_to_rsi_addrlen(*fromlen,
							    &rsi_addr_in,
							    &rsi_addr_in6,
							    &rsi_addrlen);
			retval = (ssize_t)rsi_recvfrom(sd, buf, len, 0, rsi_addr,
						      &rsi_addrlen);
		} else {
			retval = (ssize_t)rsi_recv(sd, buf, len, 0);
		}

		// handle_recv_flags(sd, flags, FALSE, &nb_enabled); //Todo
		if (retval >= 0) {
			if (fromlen != NULL) {
				/*
				 * Translate rsi_addr into *addr and set
				 * *addrlen
				 */
				translate_rsi_to_z_addr(rsi_addr, rsi_addrlen,
						       from, fromlen);
			}
		}
	}

	return retval;
}

static ssize_t rs9116w_sendto(void *obj, const void *buf, size_t len,
				 int flags, const struct sockaddr *to,
				 socklen_t tolen)
{
	int sd = OBJ_TO_SD(obj);
	ssize_t retval;
	struct rsi_sockaddr *rsi_addr;
	struct rsi_sockaddr_in rsi_addr_in;
	struct rsi_sockaddr_in6 rsi_addr_in6;
	rsi_socklen_t rsi_addrlen;

	if (to != NULL) {
		/* Translate to rsi_sendto() parameters: */
		rsi_addr = translate_z_to_rsi_addrs(to, tolen, &rsi_addr_in,
						  &rsi_addr_in6, &rsi_addrlen);

		if (rsi_addr == NULL) {
			errno = EINVAL;
			return -1;
		}

		retval = rsi_sendto(sd, buf, (uint16_t)len, flags,
				   rsi_addr, rsi_addrlen);
	} else {
		retval = (ssize_t)rsi_send(sd, buf, len, flags);
	}

	return retval;
}

static int rs9116w_ioctl(void *obj, unsigned int request, va_list args)
{
	// int sd = OBJ_TO_SD(obj);
	ARG_UNUSED(obj);

	switch (request) {
	case ZFD_IOCTL_POLL_PREPARE:
		return -EXDEV;

	case ZFD_IOCTL_POLL_UPDATE:
		return -EOPNOTSUPP;

	case ZFD_IOCTL_POLL_OFFLOAD: {
		struct zsock_pollfd *fds;
		int nfds;
		int timeout;

		fds = va_arg(args, struct zsock_pollfd *);
		nfds = va_arg(args, int);
		timeout = va_arg(args, int);

		return rs9116w_poll(fds, nfds, timeout);
	}

	default:
		errno = EINVAL;
		return -1;
	}
}


static ssize_t rs9116w_read(void *obj, void *buffer, size_t count)
{
	return rs9116w_recvfrom(obj, buffer, count, 0, NULL, 0);
}

static ssize_t rs9116w_write(void *obj, const void *buffer,
					  size_t count)
{
	return rs9116w_sendto(obj, buffer, count, 0, NULL, 0);
}

static const struct socket_op_vtable rs9116w_socket_fd_op_vtable = {
	.fd_vtable = {
		.read = rs9116w_read,
		.write = rs9116w_write,
		.close = rs9116w_close,
		.ioctl = rs9116w_ioctl, //In progress
	},
	.bind = rs9116w_bind,
	.connect = rs9116w_connect,
	.listen = rs9116w_listen,
	.accept = rs9116w_accept,
	.sendto = rs9116w_sendto,
	.recvfrom = rs9116w_recvfrom,
	.getsockopt = rs9116w_getsockopt,
	.setsockopt = rs9116w_setsockopt, 
};

static bool rs9116w_is_supported(int family, int type, int proto)
{
	/* TODO offloading always enabled for now. */
	return true;
}

int rs9116w_socket_create(int family, int type, int proto)
{
	int fd = z_reserve_fd();
	int sock;

	if (fd < 0) {
		return -1;
	}

	sock = rs9116w_socket(family, type, proto);
	LOG_DBG("SOCK CREATE %d", sock);
	if (sock < 0) {
		z_free_fd(fd);
		return -1;
	}

	z_finalize_fd(fd, SD_TO_OBJ(sock),
		      (const struct fd_op_vtable *)
					&rs9116w_socket_fd_op_vtable);

	return fd;
}

#ifdef CONFIG_NET_SOCKETS_OFFLOAD
NET_SOCKET_REGISTER(rs9116w, NET_SOCKET_DEFAULT_PRIO, AF_UNSPEC,
		    rs9116w_is_supported, rs9116w_socket_create);
// NET_SOCKET_REGISTER(rs9116w, AF_UNSPEC,
// 		    rs9116w_is_supported, rs9116w_socket_create);
#endif

#include <rsi_nwk.h>

int rs9116w_socket_offload_init()
{
	return 0;
}

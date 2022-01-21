/*
 * Copyright (c) 2017-2021 Nordic Semiconductor ASA
 * Copyright (c) 2015-2016 Intel Corporation
 * Copyright (c) 2022 T-Mobile USA, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "rs9116w_ble_gap.h"
#include <rsi_common_apis.h>
#include <rsi_bt_common.h>
#include <rsi_bt_common_apis.h>
#include <rsi_bt_apis.h>
#include <rsi_ble.h>
#include <rsi_ble_apis.h>
#include <bluetooth/bluetooth.h>

struct bt_le_ext_adv dev_adv;

rsi_ble_req_adv_t adv_params;

enum {
	RSI_EVT_NONE = 0,
	RSI_EVT_CONN,
	RSI_EVT_DISCONN
};

typedef struct rsi_gap_event_s{
	uint8_t event_type;
	uint16_t status;
	union {
		rsi_ble_event_enhance_conn_status_t conn;
		rsi_ble_event_disconnect_t disconn;
	};
} rsi_gap_event_t;

rsi_gap_event_t gap_event_queue[CONFIG_RSI_BT_EVENT_QUEUE_SIZE] = { 0 };
int gap_event_ptr;

/**
 * @brief Get the event slot pointer
 *
 * @return Event slot pointer or NULL if none available
 */
static rsi_gap_event_t *get_event_slot()
{
	int old_event_ptr = gap_event_ptr;
	gap_event_ptr++;
	gap_event_ptr %= CONFIG_RSI_BT_EVENT_QUEUE_SIZE;
	rsi_gap_event_t *target_event = &gap_event_queue[gap_event_ptr];
	if (target_event->event_type){
		gap_event_ptr = old_event_ptr;
		return NULL;
	}
	return target_event;
}

/**
 * @brief Get the adv channel map from advertisement options
 *
 * @param options Advertise param options object
 * @return Channel map value
 */
static uint8_t get_adv_channel_map(uint32_t options)
{
	uint8_t channel_map = 0x07;

	if (options & BT_LE_ADV_OPT_DISABLE_CHAN_37) {
		channel_map &= ~0x01;
	}

	if (options & BT_LE_ADV_OPT_DISABLE_CHAN_38) {
		channel_map &= ~0x02;
	}

	if (options & BT_LE_ADV_OPT_DISABLE_CHAN_39) {
		channel_map &= ~0x04;
	}

	return channel_map;
}

/**
 * @brief Get the filter policy from advertisement options
 *
 * @param options Advertise param options object
 * @return Filter policy value
 */
static uint8_t get_filter_policy(uint32_t options)
{
	if (!IS_ENABLED(CONFIG_BT_WHITELIST)) {
		return BT_LE_ADV_FP_NO_WHITELIST;
	} else if ((options & BT_LE_ADV_OPT_FILTER_SCAN_REQ) &&
		   (options & BT_LE_ADV_OPT_FILTER_CONN)) {
		return BT_LE_ADV_FP_WHITELIST_BOTH;
	} else if (options & BT_LE_ADV_OPT_FILTER_SCAN_REQ) {
		return BT_LE_ADV_FP_WHITELIST_SCAN_REQ;
	} else if (options & BT_LE_ADV_OPT_FILTER_CONN) {
		return BT_LE_ADV_FP_WHITELIST_CONN_IND;
	} else {
		return BT_LE_ADV_FP_NO_WHITELIST;
	}
}

/**
 * @brief Callback for Bluetooth LE enhanced connection event
 *
 * @param resp_enh_conn Enhanced connection data object
 */
void rsi_ble_gap_enhance_conn_event(rsi_ble_event_enhance_conn_status_t *resp_enh_conn)
{
	BT_DBG("BT ECONN");
	rsi_gap_event_t *target_evt = get_event_slot();
	if (!target_evt) {
		BT_ERR("Event queue full!");
		return;
	}
	target_evt->event_type = RSI_EVT_CONN;
	memcpy(&target_evt->conn, resp_enh_conn, sizeof(rsi_ble_event_enhance_conn_status_t));
	rsi_bt_raise_evt();
}

/**
 * @brief Deferred event to process the connection event
 * 
 * @param resp_enh_conn Enhanced connection data object
 */
void complete_enh_conn(rsi_ble_event_enhance_conn_status_t *resp_enh_conn)
{
	bt_addr_le_t peer_addr, id_addr;

	if (resp_enh_conn->dev_addr_type == BT_ADDR_LE_PUBLIC_ID ||
	    resp_enh_conn->dev_addr_type == BT_ADDR_LE_RANDOM_ID) {
		memcpy(id_addr.a.val, resp_enh_conn->dev_addr, 6);
		id_addr.type = resp_enh_conn->dev_addr_type;
		id_addr.type -= BT_ADDR_LE_PUBLIC_ID;

		memcpy(peer_addr.a.val, resp_enh_conn->peer_resolvlable_addr, 6);
		peer_addr.type = BT_ADDR_LE_RANDOM;
	} else {
		memcpy(id_addr.a.val, resp_enh_conn->dev_addr, 6);// ? bt_lookup_id_addr(id, &evt->peer_addr));
		id_addr.type = resp_enh_conn->dev_addr_type;
		bt_addr_le_copy(&peer_addr, &id_addr);
	}
	struct bt_conn *conn = bt_conn_add_le(0, &id_addr);
	if (conn == NULL) {
		BT_ERR("No slots available for connection, aborting...\n");
		return;
	}
	bt_conn_set_state(conn, BT_CONN_CONNECT);
	bt_addr_le_copy(&conn->le.dst, &id_addr);
	conn->le.interval = resp_enh_conn->conn_interval;
	conn->le.latency = resp_enh_conn->conn_latency;
	conn->le.timeout = resp_enh_conn->supervision_timeout;
	conn->role = resp_enh_conn->role;
	conn->err = resp_enh_conn->status;
#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
	conn->le.data_len.tx_max_len = BT_GAP_DATA_LEN_DEFAULT;
	conn->le.data_len.tx_max_time = BT_GAP_DATA_TIME_DEFAULT;
	conn->le.data_len.rx_max_len = BT_GAP_DATA_LEN_DEFAULT;
	conn->le.data_len.rx_max_time = BT_GAP_DATA_TIME_DEFAULT;
#endif
	if (IS_ENABLED(CONFIG_BT_PERIPHERAL) &&
	    conn->role == BT_HCI_ROLE_SLAVE) {
		bt_addr_le_copy(&conn->le.init_addr, &peer_addr);

		struct bt_le_ext_adv *adv = &dev_adv;

		if (IS_ENABLED(CONFIG_BT_PRIVACY) &&
		    !atomic_test_bit(adv->flags, BT_ADV_USE_IDENTITY)) {
			conn->le.resp_addr.type = BT_ADDR_LE_RANDOM;
			if (memcmp(resp_enh_conn->local_resolvlable_addr,
				   BT_ADDR_ANY, 6) != 0) {

				memcpy(conn->le.resp_addr.a.val, resp_enh_conn->local_resolvlable_addr, 6);
			} else {

				memcpy(conn->le.resp_addr.a.val, rsi_bt_random_addr, 6);
			}
		}
	}

	if (IS_ENABLED(CONFIG_BT_CENTRAL) &&
	    conn->role == BT_HCI_ROLE_MASTER) {
		bt_addr_le_copy(&conn->le.resp_addr, &peer_addr);

		if (IS_ENABLED(CONFIG_BT_PRIVACY)) {
			conn->le.init_addr.type = BT_ADDR_LE_RANDOM;
			if (memcmp(resp_enh_conn->local_resolvlable_addr, BT_ADDR_ANY, 6) != 0) {
				memcpy(conn->le.init_addr.a.val,
				       resp_enh_conn->local_resolvlable_addr, 6);
			} else {
				memcpy(conn->le.init_addr.a.val, rsi_bt_random_addr, 6);
			}
		} else {
			/* Todo: Seems to crash occasionally, need to look into */
			rsi_bt_get_local_device_address(conn->le.init_addr.a.val);
		}
	}

	if (resp_enh_conn->status) {
		bt_conn_set_state(conn, BT_CONN_DISCONNECTED);
		bt_conn_unref(conn);
	} else {
		bt_conn_set_state(conn, BT_CONN_CONNECTED); //Todo: is notify needed here?
		notify_connected(conn);
	}
	bt_conn_unref(conn);
}

/**
 * @brief Callback for Bluetooth LE connection event
 *
 * @param resp_conn Connection status object
 */
void rsi_ble_gap_connect_event(rsi_ble_event_conn_status_t *resp_conn)
{
	BT_DBG("BT CONN");
	rsi_ble_event_enhance_conn_status_t enh;


	enh.status = resp_conn->status;
	enh.role = BT_HCI_ROLE_SLAVE;
	enh.conn_interval = CONNECTION_INTERVAL_MAX;

	memcpy(enh.dev_addr, resp_conn->dev_addr, 6);
	enh.dev_addr_type = resp_conn->dev_addr_type;

	if (IS_ENABLED(CONFIG_BT_PRIVACY)) {
		memcpy(enh.local_resolvlable_addr, rsi_bt_random_addr, 6);
	} else {
		memcpy(enh.local_resolvlable_addr, BT_ADDR_ANY, 6);
	}

	memcpy(enh.peer_resolvlable_addr, BT_ADDR_ANY, 6);

	rsi_ble_gap_enhance_conn_event(&enh);
}

/**
 * @brief Callback for Bluetooth LE diconnect event
 *
 * @param resp_disconnect Disconnect object
 * @param reason Disconnect reason code
 */
void rsi_ble_gap_disconnect_event(rsi_ble_event_disconnect_t *resp_disconnect, uint16_t reason)
{
	BT_DBG("BT DISCONN");
	rsi_gap_event_t *target_evt = get_event_slot();
	if (!target_evt) {
		BT_ERR("Event queue full!");
		return;
	}
	target_evt->event_type = RSI_EVT_DISCONN;
	target_evt->status = reason;
	memcpy(&target_evt->disconn, resp_disconnect, sizeof(rsi_ble_event_disconnect_t));
	rsi_bt_raise_evt();
}

/**
 * @brief Deferred event to process the disconnect event
 * 
 * @param resp_disconnect Disconnect data object
 * @param reason Disconnect reason code
 */
void complete_disconnect(rsi_ble_event_disconnect_t *resp_disconnect, uint16_t reason)
{
	bt_addr_le_t addr;

	memcpy(addr.a.val, resp_disconnect->dev_addr, 6);
	struct bt_conn *conn = bt_conn_lookup_addr_le(0, &addr);
	if (conn == NULL) {
		return;
	}
	bt_conn_set_state(conn, BT_CONN_DISCONNECT_COMPLETE);
	notify_disconnected(conn);
	bt_conn_unref(conn);
}

/**
 * @brief Initialize GAP callbacks
 */
void bt_gap_init(void)
{
	rsi_ble_gap_register_callbacks(
		NULL,
		rsi_ble_gap_connect_event,
		rsi_ble_gap_disconnect_event,
		NULL,
		NULL,
		NULL,
		rsi_ble_gap_enhance_conn_event,
		NULL,
		NULL,
		NULL
	);
}

struct bt_ad {
	const struct bt_data *data;
	size_t len;
};

/**
 * @brief Set the advertisement payload and parameters to be utilized
 *
 * @param adv Advertisement parameter object
 * @param ad Advertisement data
 * @param ad_len Advertisement length
 * @return Status
 */
static int set_ad(struct bt_le_ext_adv *adv, const struct bt_ad *ad,
		  size_t ad_len)
{
	size_t required_buffer = 0;

	for (int i = 0; i < ad_len; i++) {
		const struct bt_ad *cur_ad = &ad[i];
		for (int j = 0; j < cur_ad->len; j++) {
			required_buffer += cur_ad[j].data->data_len;
			required_buffer += 2;
		}
	}
	uint8_t buf[required_buffer];
	uint8_t *buf_traverse = buf;
	for (int i = 0; i < ad_len; i++) {
		const struct bt_ad *cur_ad = &ad[i];
		for (int j = 0; j < cur_ad->len; j++) {
			*buf_traverse = cur_ad[j].data->data_len + 1;
			buf_traverse++;
			*buf_traverse = cur_ad[j].data->type;
			buf_traverse++;
			memcpy(buf_traverse, cur_ad[j].data->data, cur_ad[j].data->data_len);
			buf_traverse += cur_ad[j].data->data_len;
		}
	}
	return rsi_ble_set_advertise_data(buf, required_buffer);
}

/**
 * @brief Set the scan response data payload and parameters to be utilized
 *
 * @param adv Advertisement parameter object
 * @param sd Scan response data
 * @param sd_len Scan response data length
 * @return Status
 */
static int set_sd(struct bt_le_ext_adv *adv, const struct bt_ad *sd,
		  size_t sd_len)
{
	size_t required_buffer = 0;

	for (int i = 0; i < sd_len; i++) {
		const struct bt_ad *cur_sd = &sd[i];
		for (int j = 0; j < cur_sd->len; j++) {
			required_buffer += cur_sd[j].data->data_len;
			required_buffer += 2;
		}
	}
	uint8_t buf[required_buffer];
	uint8_t *buf_traverse = buf;
	for (int i = 0; i < sd_len; i++) {
		const struct bt_ad *cur_sd = &sd[i];
		for (int j = 0; j < cur_sd->len; j++) {
			*buf_traverse = cur_sd[j].data->data_len + 1;
			buf_traverse++;
			*buf_traverse = cur_sd[j].data->type;
			buf_traverse++;
			memcpy(buf_traverse, cur_sd[j].data->data, cur_sd[j].data->data_len);
			buf_traverse += cur_sd[j].data->data_len;
		}
	}
	return rsi_ble_set_scan_response_data(buf, required_buffer);
}

/**
 * @brief Check if advertisement contains name
 *
 * @param ad Advertisement data
 * @param ad_len Advertisement length
 */
static inline bool ad_has_name(const struct bt_data *ad, size_t ad_len)
{
	size_t i;

	for (i = 0; i < ad_len; i++) {
		if (ad[i].type == BT_DATA_NAME_COMPLETE ||
		    ad[i].type == BT_DATA_NAME_SHORTENED) {
			return true;
		}
	}

	return false;
}

/**
 * @brief Update advertisement & Scan response data
 *
 * @param adv
 * @param ad Advertisement data
 * @param ad_len Advertisement length
 * @param sd Scan response data
 * @param sd_len Scan response data length
 * @param ext_adv Extended advertising enabled (Unused)
 * @param scannable Device scannable flag
 * @param use_name Use name flag
 * @param force_name_in_ad Force name in ad flag
 * @return Status
 */
static int le_adv_update(struct bt_le_ext_adv *adv,
			 const struct bt_data *ad, size_t ad_len,
			 const struct bt_data *sd, size_t sd_len,
			 bool ext_adv, bool scannable, bool use_name,
			 bool force_name_in_ad)
{
	struct bt_ad d[2] = {};
	struct bt_data data;
	size_t d_len;
	int err;

	if (use_name) {
		const char *name = bt_get_name();

		if ((ad && ad_has_name(ad, ad_len)) ||
		    (sd && ad_has_name(sd, sd_len))) {
			/* Cannot use name if name is already set */
			return -EINVAL;
		}

		data = (struct bt_data)BT_DATA(
			BT_DATA_NAME_COMPLETE,
			name, strlen(name));
	}

	if (!(ext_adv && scannable) || force_name_in_ad) {
		d_len = 1;
		d[0].data = ad;
		d[0].len = ad_len;

		if (use_name && (!scannable || force_name_in_ad)) {
			d[1].data = &data;
			d[1].len = 1;
			d_len = 2;
		}

		err = set_ad(adv, d, d_len);
		if (err) {
			return err;
		}
	}

	if (scannable) {
		d_len = 1;
		d[0].data = sd;
		d[0].len = sd_len;

		if (use_name && !force_name_in_ad) {
			d[1].data = &data;
			d[1].len = 1;
			d_len = 2;
		}

		err = set_sd(adv, d, d_len);
		if (err) {
			return err;
		}
	}

	atomic_set_bit(adv->flags, BT_ADV_DATA_SET);
	return 0;
}


/**
 * @brief Update advertising
 *
 * Update advertisement and scan response data.
 *
 * @param ad Data to be used in advertisement packets.
 * @param ad_len Number of elements in ad
 * @param sd Data to be used in scan response packets.
 * @param sd_len Number of elements in sd
 *
 * @return Zero on success or (negative) error code otherwise.
 */
int bt_le_adv_update_data(const struct bt_data *ad, size_t ad_len,
			  const struct bt_data *sd, size_t sd_len)
{
	struct bt_le_ext_adv *adv = &dev_adv;
	bool scannable, use_name, force_name_in_ad;

	if (!adv) {
		return -EINVAL;
	}

	if (!atomic_test_bit(adv->flags, BT_ADV_ENABLED)) {
		return -EAGAIN;
	}

	scannable = atomic_test_bit(adv->flags, BT_ADV_SCANNABLE);
	use_name = atomic_test_bit(adv->flags, BT_ADV_INCLUDE_NAME);
	force_name_in_ad = atomic_test_bit(adv->flags, BT_ADV_FORCE_NAME_IN_AD);

	return le_adv_update(adv, ad, ad_len, sd, sd_len, false, scannable,
			     use_name, force_name_in_ad);
}

/**
 * @brief Stop advertising
 *
 * Stops ongoing advertising.
 *
 * @return Zero on success or (negative) error code otherwise.
 */
int bt_le_adv_stop(void)
{
	return rsi_ble_stop_advertising();
}

/**
 * @brief Enable legacy advertising
 *
 * @param adv Advertising parameters
 * @param enable Enablement flag
 * @return Advertisement start status
 */
int bt_le_adv_set_enable_legacy(struct bt_le_ext_adv *adv, bool enable)
{
	/* TODO: utilized advertising parameters */
	adv_params.status = enable;
	return rsi_ble_start_advertising_with_values(&adv_params);
}

/**
 * @brief Enable advertising
 *
 * @param adv Advertising parameters
 * @param enable Enablement flag
 * @return Advertisement start status
 */
int bt_le_adv_set_enable(struct bt_le_ext_adv *adv, bool enable)
{
	return bt_le_adv_set_enable_legacy(adv, enable);
}

/**
 * @brief Validate extended advertising parameters
 *
 * @param param Advertising parameters to validate
 * @return true on sucessfuly validation
 * @return false on failed validation
 */
static bool valid_adv_ext_param(const struct bt_le_adv_param *param)
{

	if (IS_ENABLED(CONFIG_BT_PRIVACY) &&
	    param->peer &&
	    (param->options & BT_LE_ADV_OPT_USE_IDENTITY) &&
	    (param->options & BT_LE_ADV_OPT_DIR_ADDR_RPA)) {
		/* own addr type used for both RPAs in directed advertising. */
		return false;
	}

	if (param->id > 0) {
		return false;
	}

	if ((param->options & (BT_LE_ADV_OPT_DIR_MODE_LOW_DUTY |
			       BT_LE_ADV_OPT_DIR_ADDR_RPA)) &&
	    !param->peer) {
		return false;
	}

	if ((param->options & BT_LE_ADV_OPT_DIR_MODE_LOW_DUTY) ||
	    !param->peer) {
		if (param->interval_min > param->interval_max ||
		    param->interval_min < 0x0020 ||
		    param->interval_max > 0x4000) {
			return false;
		}
	}

	if ((param->options & BT_LE_ADV_OPT_DISABLE_CHAN_37) &&
	    (param->options & BT_LE_ADV_OPT_DISABLE_CHAN_38) &&
	    (param->options & BT_LE_ADV_OPT_DISABLE_CHAN_39)) {
		return false;
	}

	return true;
}

/**
 * @brief Validate extended advertising parameters
 *
 * @param param Advertising parameters to validate
 * @return true on sucessfuly validation
 * @return false on failed validation
 */
static bool valid_adv_param(const struct bt_le_adv_param *param)
{
	if (param->options & BT_LE_ADV_OPT_EXT_ADV) {
		return false;
	}

	if (param->peer && !(param->options & BT_LE_ADV_OPT_CONNECTABLE)) {
		return false;
	}

	return valid_adv_ext_param(param);
}

int bt_le_adv_start_legacy(struct bt_le_ext_adv *adv,
			   const struct bt_le_adv_param *param,
			   const struct bt_data *ad, size_t ad_len,
			   const struct bt_data *sd, size_t sd_len)
{
	rsi_ble_req_adv_t set_param;
	bool dir_adv = (param->peer != NULL), scannable;
	int err;

	if (!atomic_test_bit(bt_dev_flags, BT_DEV_READY)) {
		return -EAGAIN;
	}

	if (!valid_adv_param(param)) {
		return -EINVAL;
	}

	(void)memset(&set_param, 0, sizeof(set_param));

	set_param.adv_int_min = param->interval_min;
	set_param.adv_int_max = param->interval_max;
	set_param.adv_channel_map = get_adv_channel_map(param->options);
	set_param.filter_type = get_filter_policy(param->options);


	adv->id = param->id;

	if (dir_adv) {
		bt_addr_le_copy(&adv->target_addr, param->peer);
	} else {
		bt_addr_le_copy(&adv->target_addr, BT_ADDR_LE_ANY);
	}

	if (param->options & BT_LE_ADV_OPT_CONNECTABLE) {
		scannable = true;

		if (dir_adv) {
			if (param->options & BT_LE_ADV_OPT_DIR_MODE_LOW_DUTY) {
				set_param.adv_type = DIR_CONN_LOW_DUTY_CYCLE;
			} else {
				set_param.adv_type = DIR_CONN;
			}

			memcpy(set_param.direct_addr, param->peer->a.val, 6);
			set_param.direct_addr_type = param->peer->type;
		} else {
			set_param.adv_type = UNDIR_CONN;
		}
	} else {
		scannable = sd || (param->options & BT_LE_ADV_OPT_USE_NAME);

		set_param.adv_type = scannable ? UNDIR_SCAN :
				     UNDIR_NON_CONN;
	}

	memcpy(&adv_params, &set_param, sizeof(set_param));


	if (!dir_adv) {
		err = le_adv_update(adv, ad, ad_len, sd, sd_len, false,
				    scannable,
				    param->options & BT_LE_ADV_OPT_USE_NAME,
				    param->options & BT_LE_ADV_OPT_FORCE_NAME_IN_AD);
		if (err) {
			return err;
		}
	}

	err = bt_le_adv_set_enable(adv, true);
	if (err) {
		BT_ERR("Failed to start advertiser");
		return err;
	}

	atomic_set_bit_to(adv->flags, BT_ADV_PERSIST, !dir_adv &&
			  !(param->options & BT_LE_ADV_OPT_ONE_TIME));

	atomic_set_bit_to(adv->flags, BT_ADV_INCLUDE_NAME,
			  param->options & BT_LE_ADV_OPT_USE_NAME);

	atomic_set_bit_to(adv->flags, BT_ADV_FORCE_NAME_IN_AD,
			  param->options & BT_LE_ADV_OPT_FORCE_NAME_IN_AD);

	atomic_set_bit_to(adv->flags, BT_ADV_CONNECTABLE,
			  param->options & BT_LE_ADV_OPT_CONNECTABLE);

	atomic_set_bit_to(adv->flags, BT_ADV_SCANNABLE, scannable);

	atomic_set_bit_to(adv->flags, BT_ADV_USE_IDENTITY,
			  param->options & BT_LE_ADV_OPT_USE_IDENTITY);

	return 0;
}

/**
 * @brief Start advertising
 *
 * Set advertisement data, scan response data, advertisement parameters
 * and start advertising.
 *
 * When the advertisement parameter peer address has been set the advertising
 * will be directed to the peer. In this case advertisement data and scan
 * response data parameters are ignored. If the mode is high duty cycle
 * the timeout will be @ref BT_GAP_ADV_HIGH_DUTY_CYCLE_MAX_TIMEOUT.
 *
 * @param param Advertising parameters.
 * @param ad Data to be used in advertisement packets.
 * @param ad_len Number of elements in ad
 * @param sd Data to be used in scan response packets.
 * @param sd_len Number of elements in sd
 *
 * @return Zero on success or (negative) error code otherwise.
 * @return -ENOMEM No free connection objects available for connectable
 *                 advertiser.
 * @return -ECONNREFUSED When connectable advertising is requested and there
 *                       is already maximum number of connections established
 *                       in the controller.
 *                       This error code is only guaranteed when using Zephyr
 *                       controller, for other controllers code returned in
 *                       this case may be -EIO.
 */
int bt_le_adv_start(const struct bt_le_adv_param *param,
		    const struct bt_data *ad, size_t ad_len,
		    const struct bt_data *sd, size_t sd_len)
{
	struct bt_le_ext_adv *adv = &dev_adv;
	int err;

	if (!adv) {
		return -ENOMEM;
	}

	err = bt_le_adv_start_legacy(adv, param, ad, ad_len, sd, sd_len);

	return err;
}

/**
 * @brief Resume advertising with set parameters
 *
 */
void bt_le_adv_resume(void)
{
	if (adv_params.status) {
		rsi_ble_start_advertising();
	}
}

void bt_gap_process(void)
{
	rsi_gap_event_t *current_event = &gap_event_queue[gap_event_ptr];
#if !IS_ENABLED(CONFIG_WISECONNECT_USE_OS_BINDINGS)
	if (current_event->event_type){
		force_rx_evt();
	}
#endif
	while (current_event->event_type){
		switch (current_event->event_type) {
			case RSI_EVT_CONN:
			{
				complete_enh_conn(&current_event->conn);
				break;
			}
			case RSI_EVT_DISCONN:
			{
				complete_disconnect(&current_event->disconn, current_event->status);
				break;
			}
		}
		current_event->event_type = RSI_EVT_NONE;
		gap_event_ptr--;
		gap_event_ptr = gap_event_ptr < 0 ? ARRAY_SIZE(gap_event_queue) : gap_event_ptr;
		current_event = &gap_event_queue[gap_event_ptr];
	}
}

/**
 * @brief UNSUPPORTED
 */
int bt_le_oob_get_local(uint8_t id, struct bt_le_oob *oob)
{
	return -ENOTSUP;
}
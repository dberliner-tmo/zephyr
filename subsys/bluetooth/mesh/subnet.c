/*
 * Copyright (c) 2017 Intel Corporation
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/atomic.h>
#include <sys/util.h>
#include <sys/byteorder.h>

#include <net/buf.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>
#include <bluetooth/mesh.h>

#define BT_DBG_ENABLED IS_ENABLED(CONFIG_BT_MESH_DEBUG_KEYS)
#define LOG_MODULE_NAME bt_mesh_net_keys
#include "common/log.h"

#include "crypto.h"
#include "adv.h"
#include "mesh.h"
#include "net.h"
#include "lpn.h"
#include "friend.h"
#include "proxy.h"
#include "transport.h"
#include "access.h"
#include "foundation.h"
#include "beacon.h"
#include "rpl.h"
#include "settings.h"
#include "host/ecc.h"
#include "prov.h"

/* Tracking of what storage changes are pending for Net Keys. We track this in
 * a separate array here instead of within the respective bt_mesh_subnet
 * struct itself, since once a key gets deleted its struct becomes invalid
 * and may be reused for other keys.
 */
struct net_key_update {
	uint16_t key_idx:12,    /* NetKey Index */
		 valid:1,       /* 1 if this entry is valid, 0 if not */
		 clear:1;       /* 1 if key needs clearing, 0 if storing */
};

/* NetKey storage information */
struct net_key_val {
	uint8_t kr_flag:1,
		kr_phase:7;
	uint8_t val[2][16];
} __packed;

static struct net_key_update net_key_updates[CONFIG_BT_MESH_SUBNET_COUNT];

static struct bt_mesh_subnet subnets[CONFIG_BT_MESH_SUBNET_COUNT] = {
	[0 ... (CONFIG_BT_MESH_SUBNET_COUNT - 1)] = {
		.net_idx = BT_MESH_KEY_UNUSED,
	},
};

static void subnet_evt(struct bt_mesh_subnet *sub, enum bt_mesh_key_evt evt)
{
	STRUCT_SECTION_FOREACH(bt_mesh_subnet_cb, cb) {
		cb->evt_handler(sub, evt);
	}
}

static void clear_net_key(uint16_t net_idx)
{
	char path[20];
	int err;

	BT_DBG("NetKeyIndex 0x%03x", net_idx);

	snprintk(path, sizeof(path), "bt/mesh/NetKey/%x", net_idx);
	err = settings_delete(path);
	if (err) {
		BT_ERR("Failed to clear NetKeyIndex 0x%03x", net_idx);
	} else {
		BT_DBG("Cleared NetKeyIndex 0x%03x", net_idx);
	}
}

static void store_subnet(uint16_t net_idx)
{
	const struct bt_mesh_subnet *sub;
	struct net_key_val key;
	char path[20];
	int err;

	sub = bt_mesh_subnet_get(net_idx);
	if (!sub) {
		BT_WARN("NetKeyIndex 0x%03x not found", net_idx);
		return;
	}

	BT_DBG("NetKeyIndex 0x%03x", net_idx);

	snprintk(path, sizeof(path), "bt/mesh/NetKey/%x", net_idx);

	memcpy(&key.val[0], sub->keys[0].net, 16);
	memcpy(&key.val[1], sub->keys[1].net, 16);
	key.kr_flag = 0U; /* Deprecated */
	key.kr_phase = sub->kr_phase;

	err = settings_save_one(path, &key, sizeof(key));
	if (err) {
		BT_ERR("Failed to store NetKey value");
	} else {
		BT_DBG("Stored NetKey value");
	}
}

static struct net_key_update *net_key_update_find(uint16_t key_idx,
					struct net_key_update **free_slot)
{
	struct net_key_update *match;
	int i;

	match = NULL;
	*free_slot = NULL;

	for (i = 0; i < ARRAY_SIZE(net_key_updates); i++) {
		struct net_key_update *update = &net_key_updates[i];

		if (!update->valid) {
			*free_slot = update;
			continue;
		}

		if (update->key_idx == key_idx) {
			match = update;
		}
	}

	return match;
}

uint8_t bt_mesh_net_flags(struct bt_mesh_subnet *sub)
{
	uint8_t flags = 0x00;

	if (sub && (sub->kr_phase == BT_MESH_KR_PHASE_2)) {
		flags |= BT_MESH_NET_FLAG_KR;
	}

	if (atomic_test_bit(bt_mesh.flags, BT_MESH_IVU_IN_PROGRESS)) {
		flags |= BT_MESH_NET_FLAG_IVU;
	}

	return flags;
}

static void update_subnet_settings(uint16_t net_idx, bool store)
{
	struct net_key_update *update, *free_slot;
	uint8_t clear = store ? 0U : 1U;

	BT_DBG("NetKeyIndex 0x%03x", net_idx);

	update = net_key_update_find(net_idx, &free_slot);
	if (update) {
		update->clear = clear;
		bt_mesh_settings_store_schedule(
			BT_MESH_SETTINGS_NET_KEYS_PENDING);
		return;
	}

	if (!free_slot) {
		if (store) {
			store_subnet(net_idx);
		} else {
			clear_net_key(net_idx);
		}
		return;
	}

	free_slot->valid = 1U;
	free_slot->key_idx = net_idx;
	free_slot->clear = clear;

	bt_mesh_settings_store_schedule(BT_MESH_SETTINGS_NET_KEYS_PENDING);
}

void bt_mesh_subnet_store(uint16_t net_idx)
{
	update_subnet_settings(net_idx, true);
}

static void key_refresh(struct bt_mesh_subnet *sub, uint8_t new_phase)
{
	BT_DBG("Phase 0x%02x -> 0x%02x", sub->kr_phase, new_phase);

	switch (new_phase) {
	/* Added second set of keys */
	case BT_MESH_KR_PHASE_1:
		sub->kr_phase = new_phase;
		subnet_evt(sub, BT_MESH_KEY_UPDATED);
		break;
	/* Now using new keys for TX */
	case BT_MESH_KR_PHASE_2:
		sub->kr_phase = new_phase;
		subnet_evt(sub, BT_MESH_KEY_SWAPPED);
		break;
	/* Revoking keys */
	case BT_MESH_KR_PHASE_3:
		if (sub->kr_phase == BT_MESH_KR_NORMAL) {
			return;
		}
		__fallthrough;
	case BT_MESH_KR_NORMAL:
		sub->kr_phase = BT_MESH_KR_NORMAL;
		memcpy(&sub->keys[0], &sub->keys[1], sizeof(sub->keys[0]));
		sub->keys[1].valid = 0U;
		subnet_evt(sub, BT_MESH_KEY_REVOKED);
		break;
	}

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		BT_DBG("Storing Updated NetKey persistently");
		bt_mesh_subnet_store(sub->net_idx);
	}
}

void bt_mesh_kr_update(struct bt_mesh_subnet *sub, bool kr_flag, bool new_key)
{
	if (!new_key) {
		return;
	}

	if (sub->kr_phase == BT_MESH_KR_PHASE_1) {
		/* Bluetooth Mesh Profile Specification Section 3.10.4.1:
		 * Can skip phase 2 if we get KR=0 on new key.
		 */
		key_refresh(sub, (kr_flag ? BT_MESH_KR_PHASE_2 :
					    BT_MESH_KR_PHASE_3));
	} else if (sub->kr_phase == BT_MESH_KR_PHASE_2 && !kr_flag) {
		key_refresh(sub, BT_MESH_KR_PHASE_3);
	}
}

static struct bt_mesh_subnet *subnet_alloc(uint16_t net_idx)
{
	struct bt_mesh_subnet *sub = NULL;

	for (int i = 0; i < ARRAY_SIZE(subnets); i++) {
		/* Check for already existing subnet */
		if (subnets[i].net_idx == net_idx) {
			return &subnets[i];
		}

		if (!sub && subnets[i].net_idx == BT_MESH_KEY_UNUSED) {
			sub = &subnets[i];
		}
	}

	return sub;
}

static void subnet_del(struct bt_mesh_subnet *sub)
{
	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		update_subnet_settings(sub->net_idx, false);
	}

	bt_mesh_net_loopback_clear(sub->net_idx);

	subnet_evt(sub, BT_MESH_KEY_DELETED);
	(void)memset(sub, 0, sizeof(*sub));
	sub->net_idx = BT_MESH_KEY_UNUSED;
}

static int msg_cred_create(struct bt_mesh_net_cred *cred, const uint8_t *p,
			   size_t p_len, const uint8_t key[16])
{
	return bt_mesh_k2(key, p, p_len, &cred->nid, cred->enc, cred->privacy);
}

static int net_keys_create(struct bt_mesh_subnet_keys *keys,
			   const uint8_t key[16])
{
	uint8_t p = 0;
	int err;

	err = msg_cred_create(&keys->msg, &p, 1, key);
	if (err) {
		BT_ERR("Unable to generate NID, EncKey & PrivacyKey");
		return err;
	}

	memcpy(keys->net, key, 16);

	BT_DBG("NID 0x%02x EncKey %s", keys->msg.nid,
	       bt_hex(keys->msg.enc, 16));
	BT_DBG("PrivacyKey %s", bt_hex(keys->msg.privacy, 16));

	err = bt_mesh_k3(key, keys->net_id);
	if (err) {
		BT_ERR("Unable to generate Net ID");
		return err;
	}

	BT_DBG("NetID %s", bt_hex(keys->net_id, 8));

#if defined(CONFIG_BT_MESH_GATT_PROXY)
	err = bt_mesh_identity_key(key, keys->identity);
	if (err) {
		BT_ERR("Unable to generate IdentityKey");
		return err;
	}

	BT_DBG("IdentityKey %s", bt_hex(keys->identity, 16));
#endif /* GATT_PROXY */

	err = bt_mesh_beacon_key(key, keys->beacon);
	if (err) {
		BT_ERR("Unable to generate beacon key");
		return err;
	}

	BT_DBG("BeaconKey %s", bt_hex(keys->beacon, 16));

	keys->valid = 1U;

	return 0;
}

uint8_t bt_mesh_subnet_add(uint16_t net_idx, const uint8_t key[16])
{
	struct bt_mesh_subnet *sub = NULL;
	int err;

	BT_DBG("0x%03x", net_idx);

	sub = subnet_alloc(net_idx);
	if (!sub) {
		return STATUS_INSUFF_RESOURCES;
	}

	if (sub->net_idx == net_idx) {
		if (memcmp(key, sub->keys[0].net, 16)) {
			return STATUS_IDX_ALREADY_STORED;
		}

		return STATUS_SUCCESS;
	}

	err = net_keys_create(&sub->keys[0], key);
	if (err) {
		return STATUS_UNSPECIFIED;
	}

	sub->net_idx = net_idx;
	sub->kr_phase = BT_MESH_KR_NORMAL;

	if (IS_ENABLED(CONFIG_BT_MESH_GATT_PROXY)) {
		sub->node_id = BT_MESH_NODE_IDENTITY_STOPPED;
	} else {
		sub->node_id = BT_MESH_NODE_IDENTITY_NOT_SUPPORTED;
	}

	subnet_evt(sub, BT_MESH_KEY_ADDED);

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		BT_DBG("Storing NetKey persistently");
		bt_mesh_subnet_store(sub->net_idx);
	}

	return STATUS_SUCCESS;
}

bool bt_mesh_subnet_exists(uint16_t net_idx)
{
	return !!bt_mesh_subnet_get(net_idx);
}

uint8_t bt_mesh_subnet_update(uint16_t net_idx, const uint8_t key[16])
{
	struct bt_mesh_subnet *sub;
	int err;

	BT_DBG("0x%03x", net_idx);

	sub = bt_mesh_subnet_get(net_idx);
	if (!sub) {
		return STATUS_INVALID_NETKEY;
	}

	/* The node shall successfully process a NetKey Update message on a
	 * valid NetKeyIndex when the NetKey value is different and the Key
	 * Refresh procedure has not been started, or when the NetKey value is
	 * the same in Phase 1. The NetKey Update message shall generate an
	 * error when the node is in Phase 2, or Phase 3.
	 */
	switch (sub->kr_phase) {
	case BT_MESH_KR_NORMAL:
		if (!memcmp(key, sub->keys[0].net, 16)) {
			return STATUS_IDX_ALREADY_STORED;
		}
		break;
	case BT_MESH_KR_PHASE_1:
		if (!memcmp(key, sub->keys[1].net, 16)) {
			return STATUS_SUCCESS;
		}
		__fallthrough;
	case BT_MESH_KR_PHASE_2:
	case BT_MESH_KR_PHASE_3:
		return STATUS_CANNOT_UPDATE;
	}

	err = net_keys_create(&sub->keys[1], key);
	if (err) {
		return STATUS_CANNOT_UPDATE;
	}

	key_refresh(sub, BT_MESH_KR_PHASE_1);

	return STATUS_SUCCESS;
}

uint8_t bt_mesh_subnet_del(uint16_t net_idx)
{
	struct bt_mesh_subnet *sub;

	BT_DBG("0x%03x", net_idx);

	sub = bt_mesh_subnet_get(net_idx);
	if (!sub) {
		/* This could be a retry of a previous attempt that had its
		 * response lost, so pretend that it was a success.
		 */
		return STATUS_INVALID_NETKEY;
	}

	subnet_del(sub);

	return STATUS_SUCCESS;
}

int bt_mesh_friend_cred_create(struct bt_mesh_net_cred *cred, uint16_t lpn_addr,
			       uint16_t frnd_addr, uint16_t lpn_counter,
			       uint16_t frnd_counter, const uint8_t key[16])
{
	uint8_t p[9];

	p[0] = 0x01;
	sys_put_be16(lpn_addr, p + 1);
	sys_put_be16(frnd_addr, p + 3);
	sys_put_be16(lpn_counter, p + 5);
	sys_put_be16(frnd_counter, p + 7);

	return msg_cred_create(cred, p, sizeof(p), key);
}

uint8_t bt_mesh_subnet_kr_phase_set(uint16_t net_idx, uint8_t *phase)
{
	/* Table in Bluetooth Mesh Profile Specification Section 4.2.14: */
	const uint8_t valid_transitions[] = {
		BIT(BT_MESH_KR_PHASE_3), /* Normal phase: KR is started by key update */
		BIT(BT_MESH_KR_PHASE_2) | BIT(BT_MESH_KR_PHASE_3), /* Phase 1 */
		BIT(BT_MESH_KR_PHASE_3), /* Phase 2 */
		/* Subnet is never in Phase 3 */
	};
	struct bt_mesh_subnet *sub;

	BT_DBG("0x%03x", net_idx);

	sub = bt_mesh_subnet_get(net_idx);
	if (!sub) {
		*phase = 0x00;
		return STATUS_INVALID_NETKEY;
	}

	if (*phase == sub->kr_phase) {
		return STATUS_SUCCESS;
	}

	if (sub->kr_phase < ARRAY_SIZE(valid_transitions) &&
	    valid_transitions[sub->kr_phase] & BIT(*phase)) {
		key_refresh(sub, *phase);

		*phase = sub->kr_phase;

		return STATUS_SUCCESS;
	}

	BT_WARN("Invalid KR transition: 0x%02x -> 0x%02x", sub->kr_phase,
		*phase);

	*phase = sub->kr_phase;

	return STATUS_CANNOT_UPDATE;
}

uint8_t bt_mesh_subnet_kr_phase_get(uint16_t net_idx, uint8_t *phase)
{
	struct bt_mesh_subnet *sub;

	sub = bt_mesh_subnet_get(net_idx);
	if (!sub) {
		*phase = BT_MESH_KR_NORMAL;
		return STATUS_INVALID_NETKEY;
	}

	*phase = sub->kr_phase;

	return STATUS_SUCCESS;
}

uint8_t bt_mesh_subnet_node_id_set(uint16_t net_idx,
				   enum bt_mesh_feat_state node_id)
{
	struct bt_mesh_subnet *sub;

	if (node_id == BT_MESH_FEATURE_NOT_SUPPORTED) {
		return STATUS_CANNOT_SET;
	}

	sub = bt_mesh_subnet_get(net_idx);
	if (!sub) {
		return STATUS_INVALID_NETKEY;
	}

	if (!IS_ENABLED(CONFIG_BT_MESH_GATT_PROXY)) {
		return STATUS_FEAT_NOT_SUPP;
	}

	if (node_id) {
		bt_mesh_proxy_identity_start(sub);
	} else {
		bt_mesh_proxy_identity_stop(sub);
	}

	bt_mesh_adv_gatt_update();

	return STATUS_SUCCESS;
}

uint8_t bt_mesh_subnet_node_id_get(uint16_t net_idx,
				   enum bt_mesh_feat_state *node_id)
{
	struct bt_mesh_subnet *sub;

	sub = bt_mesh_subnet_get(net_idx);
	if (!sub) {
		*node_id = 0x00;
		return STATUS_INVALID_NETKEY;
	}

	*node_id = sub->node_id;

	return STATUS_SUCCESS;
}

ssize_t bt_mesh_subnets_get(uint16_t net_idxs[], size_t max, off_t skip)
{
	size_t count = 0;

	for (int i = 0; i < ARRAY_SIZE(subnets); i++) {
		struct bt_mesh_subnet *sub = &subnets[i];

		if (sub->net_idx == BT_MESH_KEY_UNUSED) {
			continue;
		}

		if (skip) {
			skip--;
			continue;
		}

		if (count >= max) {
			return -ENOMEM;
		}

		net_idxs[count++] = sub->net_idx;
	}

	return count;
}

struct bt_mesh_subnet *bt_mesh_subnet_get(uint16_t net_idx)
{
	for (int i = 0; i < ARRAY_SIZE(subnets); i++) {
		struct bt_mesh_subnet *sub = &subnets[i];

		if (sub->net_idx == net_idx) {
			return sub;
		}
	}

	return NULL;
}

int bt_mesh_subnet_set(uint16_t net_idx, uint8_t kr_phase,
		       const uint8_t old_key[16], const uint8_t new_key[16])
{
	const uint8_t *keys[] = { old_key, new_key };
	struct bt_mesh_subnet *sub;

	sub = subnet_alloc(net_idx);
	if (!sub) {
		return -ENOMEM;
	}

	if (sub->net_idx == net_idx) {
		return -EALREADY;
	}

	for (int i = 0; i < ARRAY_SIZE(keys); i++) {
		if (!keys[i]) {
			continue;
		}

		if (net_keys_create(&sub->keys[i], keys[i])) {
			return -EIO;
		}
	}

	sub->net_idx = net_idx;
	sub->kr_phase = kr_phase;

	if (IS_ENABLED(CONFIG_BT_MESH_GATT_PROXY)) {
		sub->node_id = BT_MESH_NODE_IDENTITY_STOPPED;
	} else {
		sub->node_id = BT_MESH_NODE_IDENTITY_NOT_SUPPORTED;
	}

	/* Make sure we have valid beacon data to be sent */
	bt_mesh_beacon_update(sub);

	return 0;
}

struct bt_mesh_subnet *bt_mesh_subnet_find(bool (*cb)(struct bt_mesh_subnet *sub, void *cb_data),
					   void *cb_data)
{
	for (int i = 0; i < ARRAY_SIZE(subnets); i++) {
		if (subnets[i].net_idx == BT_MESH_KEY_UNUSED) {
			continue;
		}

		if (!cb || cb(&subnets[i], cb_data)) {
			return &subnets[i];
		}
	}

	return NULL;
}

size_t bt_mesh_subnet_foreach(void (*cb)(struct bt_mesh_subnet *sub))
{
	size_t count = 0;

	for (int i = 0; i < ARRAY_SIZE(subnets); i++) {
		if (subnets[i].net_idx == BT_MESH_KEY_UNUSED) {
			continue;
		}

		cb(&subnets[i]);
		count++;
	}

	return count;
}

struct bt_mesh_subnet *bt_mesh_subnet_next(struct bt_mesh_subnet *sub)
{
	if (sub) {
		sub++;
	} else {
		sub = &subnets[0];
	}

	for (int i = 0; i < ARRAY_SIZE(subnets); i++, sub++) {
		/* Roll over once we reach the end */
		if (sub == &subnets[ARRAY_SIZE(subnets)]) {
			sub = &subnets[0];
		}

		if (sub->net_idx != BT_MESH_KEY_UNUSED) {
			return sub;
		}
	}

	return NULL;
}

void bt_mesh_net_keys_reset(void)
{
	int i;

	/* Delete all net keys, which also takes care of all app keys which
	 * are associated with each net key.
	 */
	for (i = 0; i < ARRAY_SIZE(subnets); i++) {
		struct bt_mesh_subnet *sub = &subnets[i];

		if (sub->net_idx != BT_MESH_KEY_UNUSED) {
			subnet_del(sub);
		}
	}
}

bool bt_mesh_net_cred_find(struct bt_mesh_net_rx *rx, struct net_buf_simple *in,
			   struct net_buf_simple *out,
			   bool (*cb)(struct bt_mesh_net_rx *rx,
				      struct net_buf_simple *in,
				      struct net_buf_simple *out,
				      const struct bt_mesh_net_cred *cred))
{
	int i, j;

	BT_DBG("");

#if defined(CONFIG_BT_MESH_LOW_POWER)
	if (bt_mesh_lpn_waiting_update()) {
		rx->sub = bt_mesh.lpn.sub;

		for (j = 0; j < ARRAY_SIZE(bt_mesh.lpn.cred); j++) {
			if (!rx->sub->keys[j].valid) {
				continue;
			}

			if (cb(rx, in, out, &bt_mesh.lpn.cred[j])) {
				rx->new_key = (j > 0);
				rx->friend_cred = 1U;
				rx->ctx.net_idx = rx->sub->net_idx;
				return true;
			}
		}

		/* LPN Should only receive on the friendship credentials when in
		 * a friendship.
		 */
		return false;
	}
#endif

#if defined(CONFIG_BT_MESH_FRIEND)
	/** Each friendship has unique friendship credentials */
	for (i = 0; i < ARRAY_SIZE(bt_mesh.frnd); i++) {
		struct bt_mesh_friend *frnd = &bt_mesh.frnd[i];

		if (!frnd->subnet) {
			continue;
		}

		rx->sub = frnd->subnet;

		for (j = 0; j < ARRAY_SIZE(frnd->cred); j++) {
			if (!rx->sub->keys[j].valid) {
				continue;
			}

			if (cb(rx, in, out, &frnd->cred[j])) {
				rx->new_key = (j > 0);
				rx->friend_cred = 1U;
				rx->ctx.net_idx = rx->sub->net_idx;
				return true;
			}
		}
	}
#endif

	for (i = 0; i < ARRAY_SIZE(subnets); i++) {
		rx->sub = &subnets[i];
		if (rx->sub->net_idx == BT_MESH_KEY_UNUSED) {
			continue;
		}

		for (j = 0; j < ARRAY_SIZE(rx->sub->keys); j++) {
			if (!rx->sub->keys[j].valid) {
				continue;
			}

			if (cb(rx, in, out, &rx->sub->keys[j].msg)) {
				rx->new_key = (j > 0);
				rx->friend_cred = 0U;
				rx->ctx.net_idx = rx->sub->net_idx;
				return true;
			}
		}
	}

	return false;
}

static int net_key_set(const char *name, size_t len_rd,
		       settings_read_cb read_cb, void *cb_arg)
{
	struct net_key_val key;
	int err;
	uint16_t net_idx;

	if (!name) {
		BT_ERR("Insufficient number of arguments");
		return -ENOENT;
	}

	net_idx = strtol(name, NULL, 16);
	err = bt_mesh_settings_set(read_cb, cb_arg, &key, sizeof(key));
	if (err) {
		BT_ERR("Failed to set \'net-key\'");
		return err;
	}

	BT_DBG("NetKeyIndex 0x%03x recovered from storage", net_idx);

	return bt_mesh_subnet_set(
		net_idx, key.kr_phase, key.val[0],
		(key.kr_phase != BT_MESH_KR_NORMAL) ? key.val[1] : NULL);
}

BT_MESH_SETTINGS_DEFINE(subnet, "NetKey", net_key_set);

void bt_mesh_subnet_pending_store(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(net_key_updates); i++) {
		struct net_key_update *update = &net_key_updates[i];

		if (!update->valid) {
			continue;
		}

		if (update->clear) {
			clear_net_key(update->key_idx);
		} else {
			store_subnet(update->key_idx);
		}

		update->valid = 0U;
	}
}

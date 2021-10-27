/** @file
 * @brief Modem SMS for SMS common structure.
 *
 * Modem SMS handling for modem driver.
 */

/*
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DRIVERS_MODEM_MODEM_SMS_H_
#define _DRIVERS_MODEM_MODEM_SMS_H_

#define PHN_SIZE 16
#ifndef CONFIG_SMS_TEXT_SIZE
#define CONFIG_SMS_TEXT_SIZE 168
#endif

typedef union {
	char phntxt[PHN_SIZE + CONFIG_SMS_TEXT_SIZE];
	struct {
		char phn[PHN_SIZE];
		char text[CONFIG_SMS_TEXT_SIZE];
	};
} phn_text_t;

enum io_ctl {
	SMS_SEND,
	SMS_RECV,
};

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

static inline void clear_phntext(phn_text_t *pt) {
	memset(pt, 0, sizeof(phn_text_t));
}


static inline void set_sms_phn(phn_text_t *pt, char *str, size_t phn_len) {
	size_t n = min(PHN_SIZE - 1, phn_len);
	memcpy(pt->phn, str, n);
	pt->phn[n] = 0;
}

static inline void set_sms_text(phn_text_t *pt, char *str, size_t text_len) {
	size_t n = min(CONFIG_SMS_TEXT_SIZE - 1, text_len);
	memcpy(pt->text, str, n);
	pt->text[n] = 0;
}

#endif

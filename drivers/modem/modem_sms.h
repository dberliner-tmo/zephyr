/** @file
 * @brief Modem SMS for SMS common structure.
 *
 * Modem SMS handling for modem driver.
 */

/*
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#define SMS_PHONE_MAX_LEN          16
#define SMS_TIME_MAX_LEN           26

#ifndef CONFIG_SMS_IN_MSG_MAX_LEN
#define CONFIG_SMS_IN_MSG_MAX_LEN  168
#endif

#ifndef CONFIG_SMS_OUT_MSG_MAX_LEN
#define CONFIG_SMS_OUT_MSG_MAX_LEN 168
#endif

struct sms_out {
        char phone[SMS_PHONE_MAX_LEN];
        char msg  [CONFIG_SMS_OUT_MSG_MAX_LEN];
};

struct sms_in {
        char phone[SMS_PHONE_MAX_LEN];
        char time [SMS_TIME_MAX_LEN];
        char msg  [CONFIG_SMS_IN_MSG_MAX_LEN];
};

typedef int (*send_sms_func)(void *obj, struct sms_out *sms);
typedef int (*recv_sms_func)(void *obj, struct sms_in  *sms);

enum io_ctl {
	SMS_SEND,
	SMS_RECV,
	GET_IPV4_CONF,
};

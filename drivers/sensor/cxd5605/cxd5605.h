/*
 * Copyright (c) 2022 Kim Mansfield <kmansfie@yahoo.com>
 * Copyright (c) 2022 T-Mobile USA, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_SENSOR_CXD5605_CXD5605_H_
#define ZEPHYR_DRIVERS_SENSOR_CXD5605_CXD5605_H_

#include <stdint.h>

#include <drivers/sensor.h>
#include <drivers/gpio.h>

struct cxd5605_data {
	const struct device *cxd5605_dev;

	struct gpio_callback data_ready_gpio_cb;
	struct gpio_callback one_pps_gpio_cb;
	struct gpio_callback gpio_cb;

	gpps_func gpps_cb;
	struct gnss_global_data pvt;
	struct cxd5605_cmd_data cxd5605_cmd_data;
	char version[32];
	uint16_t bin_data_ptr;
	uint16_t bin_data_len;
	uint16_t bytes_remaining;
	uint16_t copy_length;

	uint16_t cepw_packet_num;
	struct cxd5605_cepw_binary_data cepw_packet;
	int cxd5605_cmd;
	int num_msg;

	struct fs_file_t cxdfile;
};

int cxd5605_trigger_set(const struct device *dev,
			const struct sensor_trigger *trig,
			sensor_trigger_handler_t handler);

int setup_interrupts(const struct device *dev);
int sony_cxd5605_read_temp(const struct device *dev);
void cxd5605_trigger_handle_alert(const struct device *port,
				 struct gpio_callback *cb,
				 gpio_port_pins_t pins);

#endif /*  ZEPHYR_DRIVERS_SENSOR_CXD5605_CXD5605_H_ */

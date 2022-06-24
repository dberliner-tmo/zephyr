/*
 * Copyright (c) 2021 Jimmy Johnson <catch22@fastmail.net>
 * Copyright (c) 2022 T-Mobile USA, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_SENSOR_TMP108_TMP108_H_
#define ZEPHYR_DRIVERS_SENSOR_TMP108_TMP108_H_

#include <stdint.h>

#include <zephyr/drivers/sensor.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/sensor/tmp108.h>

#if DT_PROP(DT_INST(0, ti_tmp108), variant_as621x)
#include "as621x_defs.h"
#else
#include "tmp108_defs.h"
#endif

struct tmp108_data {
	const struct device *tmp108_dev;

	uint16_t sample;

	bool one_shot_mode;

	struct k_work_delayable scheduled_work;

	struct sensor_trigger temp_alert_trigger;
	sensor_trigger_handler_t temp_alert_handler;

	sensor_trigger_handler_t data_ready_handler;
	struct sensor_trigger data_ready_trigger;

	struct gpio_callback temp_alert_gpio_cb;
};

int tmp_108_trigger_set(const struct device *dev,
			const struct sensor_trigger *trig,
			sensor_trigger_handler_t handler);

int tmp108_reg_read(const struct device *dev, uint8_t reg, uint16_t *val);

int ti_tmp108_read_temp(const struct device *dev);
void tmp108_trigger_handle_one_shot(struct k_work *work);
void tmp108_trigger_handle_alert(const struct device *port,
				 struct gpio_callback *cb,
				 gpio_port_pins_t pins);

#endif /*  ZEPHYR_DRIVERS_SENSOR_TMP108_TMP108_H_ */

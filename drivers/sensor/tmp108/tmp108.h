/*
 * Copyright (c) 2019 Centaur Analytics, Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_SENSOR_TMP108_TMP108_H_
#define ZEPHYR_DRIVERS_SENSOR_TMP108_TMP108_H_

#define TI_TMP108_I2C_ADDRESS      0x48                ///< The i2c address for the ti TMP 108

#define TI_TMP108_CONF_M0          0x0100              ///< Mode 1 configuration register
#define TI_TMP108_CONF_M1          0x0200              ///< Mode 2 configuration register
#define TI_TMP108_MODE_ONE_SHOT    TI_TMP108_CONF_M1   ///< One-Shot Mode (M1 = 0, M0 = 1)

#define TI_TMP108_MODE_SHUTDOWN    0x0000              ///< Shutdown Mode (M1 = 0, M0 = 0)

#define TI_TMP108_REG_TEMP         0x00                ///< Temperature register
#define TI_TMP108_REG_CONF         0x01                ///< Configuration register
#define TI_TMP108_REG_CONF         0x01                ///< Configuration register

struct tmp108_data {
	const struct device *i2c;
	uint16_t sample;
};

struct tmp108_dev_config {
	uint16_t i2c_addr;
	char *i2c_bus_label;
};

#endif /*  ZEPHYR_DRIVERS_SENSOR_TMP108_TMP108_H_ */

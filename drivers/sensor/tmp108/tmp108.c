/*
 * Copyright (c) 2019 Centaur Analytics, Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT ti_tmp108

#include <device.h>
#include <drivers/i2c.h>
#include <drivers/sensor.h>
#include <sys/util.h>
#include <sys/byteorder.h>
#include <sys/__assert.h>
#include <logging/log.h>
#include <kernel.h>

#include "tmp108.h"

/* scale in micro degrees Celsius */

#define TMP108_TEMP_SCALE       62500
#define TMP108_I2C_ADDRESS      DT_INST_REG_ADDR(0)

#define LOG_LEVEL CONFIG_SENSOR_LOG_LEVEL
LOG_MODULE_REGISTER(TMP108);

static int tmp108_reg_read(const struct device *dev, uint8_t reg, uint16_t *val)
{
	struct tmp108_data *drv_data = dev->data;

	if (i2c_burst_read(drv_data->i2c, TMP108_I2C_ADDRESS, reg, (uint8_t*) val, 2)  < 0) {
		return -EIO;
	}

	*val = sys_be16_to_cpu(*val);

	return 2;
}

static int tmp108_reg_write(const struct device *dev, uint8_t reg, uint16_t val)
{
	struct tmp108_data *drv_data = dev->data;
	uint8_t tx_buf[3] = {reg, val >> 8, val & 0xFF};

	i2c_write(drv_data->i2c, tx_buf, sizeof(tx_buf), TMP108_I2C_ADDRESS);

	return 2;
}

/**
 * Set up shut down mode for power saving
 *
 * @return TMO_ERROR on error TMO_SUCCESS on success
 */
static inline int ti_tmp108_shutdown_mode(const struct device *dev) {

    uint16_t config = 0;

    config &= ~(TI_TMP108_CONF_M1 | TI_TMP108_CONF_M0); ///< Shutdown Mode (M1 = 0, M0 = 0)

    return tmp108_reg_write(dev, TI_TMP108_REG_CONF, config);
}

static int tmp108_sample_fetch(const struct device *dev, enum sensor_channel chan)
{
	struct tmp108_data *drv_data = dev->data;
	uint16_t temp_code = 0;
    uint16_t config = 0;

	__ASSERT_NO_MSG(chan == SENSOR_CHAN_ALL || chan == SENSOR_CHAN_AMBIENT_TEMP);

	// clear sensor values

	drv_data->sample = 0U;

	// Get the most recent temperature measurement

    if (tmp108_reg_read(dev,
                        TI_TMP108_REG_CONF,
                        &config) < 0) {

        return -EIO;
    }

    config &= ~(TI_TMP108_CONF_M0 | TI_TMP108_CONF_M1); ///< Set up one shot mode for power saving

    config |= TI_TMP108_MODE_ONE_SHOT;                  ///< One-Shot Mode (M1 = 0, M0 = 1)

    if (tmp108_reg_write(dev,
                         TI_TMP108_REG_CONF,
                         config) < 0) {

        return -EIO;
    }

    if (tmp108_reg_read(dev,
                        TI_TMP108_REG_TEMP,
                        &temp_code) > 0) {

        drv_data->sample =  temp_code;

    } else {

        return -EIO;
    }

    if (ti_tmp108_shutdown_mode(dev) < 0) { ///< reconfigure shutdown mode

        return -EIO;
    }

	return 0;
}

static int tmp108_channel_get(const struct device *dev,
			      enum sensor_channel chan,
			      struct sensor_value *val)
{
	struct tmp108_data *drv_data = dev->data;
    int32_t uval;

	if (chan != SENSOR_CHAN_AMBIENT_TEMP) {
		return -ENOTSUP;
	}

    uval = (int32_t)(drv_data->sample  >> 4) * TMP108_TEMP_SCALE;
    val->val1 = uval / 1000000;
    val->val2 = uval % 1000000;

	return 0;
}

static int tmp108_attr_set(const struct device *dev,
			   enum sensor_channel chan,
			   enum sensor_attribute attr,
			   const struct sensor_value *val)
{

	if (chan != SENSOR_CHAN_AMBIENT_TEMP) {
		return -ENOTSUP;
	}

	return 0;
}

static const struct sensor_driver_api tmp108_driver_api = {
	.attr_set = tmp108_attr_set,
	.sample_fetch = tmp108_sample_fetch,
	.channel_get = tmp108_channel_get
};

static int tmp108_init(const struct device *dev)
{
	struct tmp108_data *drv_data = dev->data;

	/* Bind to the I2C bus that the sensor is connected */
	drv_data->i2c = device_get_binding(DT_INST_BUS_LABEL(0));

	if (!drv_data->i2c) {
		LOG_ERR("Cannot bind to %s device!", DT_INST_BUS_LABEL(0));
		return -EINVAL;
	}

	return 0;
}

static struct tmp108_data tmp108_prv_data;

DEVICE_DT_INST_DEFINE(0,
                      tmp108_init,
                      NULL,
                      &tmp108_prv_data,
                      NULL,
                      POST_KERNEL,
                      CONFIG_SENSOR_INIT_PRIORITY,
                      &tmp108_driver_api);

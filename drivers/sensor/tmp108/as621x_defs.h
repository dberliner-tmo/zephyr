/*
 * Copyright (c) 2021 Jimmy Johnson <catch22@fastmail.net>
 * Copyright (c) 2022 T-Mobile USA, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_SENSOR_TMP108_AS621X_DEFS_H_
#define ZEPHYR_DRIVERS_SENSOR_TMP108_AS621X_DEFS_H_

#include <stdint.h>

#define TI_TMP108_REG_TEMP			0x00   /** Temperature register */
#define TI_TMP108_REG_CONF			0x01   /** Configuration register */
#define TI_TMP108_REG_LOW_LIMIT		0x02   /** Low alert set register */
#define TI_TMP108_REG_HIGH_LIMIT	0x03   /** High alert set register */


#define TI_TMP108_CONF_M0	0x8000	/** Mode 1 configuration bit */
#define TI_TMP108_CONF_M1	0x0100	/** Mode 2 configuration bit */
#define TI_TMP108_CONF_CR0	0x0040	/** Conversion rate 1 configuration bit */
#define TI_TMP108_CONF_CR1	0x0080	/** Conversion rate 2 configuration bit */
#define TI_TMP108_CONF_POL	0x0400	/** Alert pin Polarity configuration bit */
#define TI_TMP108_CONF_TM	0x0200	/** Thermostat mode setting bit */
#define TI_TMP108_CONF_HYS1	0		/** Temperature hysteresis config 1 bit  */
#define TI_TMP108_CONF_HYS0	0		/** Temperature hysteresis config 2 bit */


#define TI_TMP108_CONF_WFH	OVER_TEMP_MASK
#define TI_TMP108_CONF_WFL	UNDER_TEMP_MASK

#define TI_TMP108_MODE_SHUTDOWN		TI_TMP108_CONF_M1
#define TI_TMP108_MODE_ONE_SHOT		TI_TMP108_CONF_M0 | TI_TMP108_CONF_M1
#define TI_TMP108_MODE_CONTINUOUS	0
#define TI_TMP108_MODE_MASK			(uint16_t)~(TI_TMP108_CONF_M0 | TI_TMP108_CONF_M1)

#define TI_TMP108_FREQ_4_SECS	0
#define TI_TMP108_FREQ_1_HZ	TI_TMP108_CONF_CR0
#define TI_TMP108_FREQ_4_HZ	TI_TMP108_CONF_CR1
#define TI_TMP108_FREQ_16_HZ	(TI_TMP108_CONF_CR1 | TI_TMP108_CONF_CR0)
#define TI_TMP108_FREQ_MASK	~(TI_TMP108_CONF_CR1 | TI_TMP108_CONF_CR0)

#define TI_TMP108_CONF_POL_LOW		0
#define TI_TMP108_CONF_POL_HIGH		TI_TMP108_CONF_POL
#define TI_TMP108_CONF_POL_MASK		~(TI_TMP108_CONF_POL)

#define TI_TMP108_CONF_TM_CMP		0
#define TI_TMP108_CONF_TM_INT		TI_TMP108_CONF_TM
#define TI_TMP108_CONF_TM_MASK		~(TI_TMP108_CONF_TM)

#define TI_TMP108_HYSTER_0_C	0
#define TI_TMP108_HYSTER_1_C	TI_TMP108_CONF_HYS0
#define TI_TMP108_HYSTER_2_C	TI_TMP108_CONF_HYS1
#define TI_TMP108_HYSTER_4_C	(TI_TMP108_CONF_HYS1 | TI_TMP108_CONF_HYS0)
#define TI_TMP108_HYSTER_MASK	~(TI_TMP108_CONF_HYS1 | TI_TMP108_CONF_HYS0)

/* AS621x series conversion multiplier */
#define TMP108_TEMP_MULTIPLIER    125000

/** AS621x Typical conversion time of 120 ms for single shot */
#define TMP108_WAKEUP_TIME_IN_MS 120

#endif /*  ZEPHYR_DRIVERS_SENSOR_TMP108_AS621X_DEFS_H_ */

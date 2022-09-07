/*
 * Copyright (c) 2022 T-Mobile Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <drivers/sensor.h>
#include <drivers/sensor/cxd5605.h>
#include <drivers/flash.h>
#include <device.h>
#include <devicetree.h>
#include <stdio.h>
#include <init.h>
#include <drivers/i2c.h>
#include <drivers/gpio.h>
#include <string.h>
#include <stdlib.h>
#include <drivers/sensor/gnss.h>
#include <fs/fs.h>

typedef enum {
	ST_WAIT_FOR_FIX = 1,
	ST_STOP_GNSS,
	ST_UPDATE_TIME,
	ST_COLD_START,
	ST_WARM_START,
	ST_SGE_DATA_GEN,
	ST_SGE_STATUS,
	NEXT_FIX,
	NEXT_FIX1,
} fix_state_st;


static uint32_t fix_time_sec = 0;

void call_back_1PPS() 
{
	//printf("%s:%d - User 1PPS\n",__FUNCTION__,__LINE__);
}

void hot_start_handler(struct k_work *work)
{
	fix_time_sec++;
}

K_WORK_DEFINE(hot_start, hot_start_handler);

void hot_start_timer_handler(struct k_timer *dummy)
{
	k_work_submit(&hot_start);
}

K_TIMER_DEFINE(hot_start_timer, hot_start_timer_handler, NULL);

int main(void)
{
	int fix_state = ST_SGE_DATA_GEN;
	struct sensor_value temp_flags;

	const struct device *cxd5605;
	int rc;

	struct sensor_value sensValues;

	printf("Sony CXD5605 Hot Fix Example, %s\n", CONFIG_ARCH);

	cxd5605 = DEVICE_DT_GET_ANY(sony_cxd5605);

	if (!cxd5605) {
		printf("cxd5605 driver error\n");
		return 1;
	}

	k_msleep(1000);

	sensValues.val1 = 1;
	sensValues.val2 = 38;
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_CALLBACK, &sensValues);

	printf("Reading NMEA sentences\n");

	/* wait 3 seconds for GNSS to boot*/
	k_msleep(3000);

	printf("cxd5605 booted up\n");
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_VER, NULL);
	k_msleep(200);
	struct sensor_value gsop[3] = {{1,2000},{0,0}};
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GSOP, gsop);
	k_msleep(200);
	sensValues.val1 = 0x01;
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_BSSL, &sensValues);
	k_msleep(200);
	sensValues.val1 = 1;
	sensValues.val2 = (int32_t)call_back_1PPS;
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_TURN_ON_1PPS, &sensValues);
	k_msleep(200);
	sensValues.val1 = 1;
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GENERATE_SGE_DATA, &sensValues);
	k_msleep(200);
	struct sensor_value gtim[3] = {{2022,8},{31,07},{53,30}};
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GTIM, gtim);
	k_msleep(200);
	k_msleep(4000);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GSW, &sensValues);
	k_timer_start(&hot_start_timer, K_SECONDS(1), K_SECONDS(1));

	fix_state = ST_WAIT_FOR_FIX;

	while (1) {
		switch (fix_state) {
			case ST_WAIT_FOR_FIX:
				k_msleep(1000); 	// wait for packet
				sensor_attr_get(cxd5605,
						GNSS_CHANNEL_POSITION,
						GNSS_ATTRIBUTE_FIXTYPE,
						&temp_flags);
				if (temp_flags.val1 >= 1) {
					temp_flags.val1 = 0;
					temp_flags.val2 = 0;

					printf("%s:%d - got fix! %d sec\n", __FUNCTION__, __LINE__ ,fix_time_sec);
					fix_state = ST_STOP_GNSS;
				}
				break;

			case ST_SGE_DATA_GEN:
				k_msleep(1000);
				printf("%s:%d - [AEPS] generate SGE data \n", __FUNCTION__, __LINE__ );
				sensValues.val1 = 1;
				rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GENERATE_SGE_DATA, &sensValues);
				fix_state = ST_UPDATE_TIME;
				break;

			case ST_SGE_STATUS:
				k_msleep(1000);
				printf("%s:%d - [AEPG] SGE status \n", __FUNCTION__, __LINE__ );
				rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_SGE_STATUS, &sensValues);
				fix_state = ST_WARM_START;
				break;

			case ST_STOP_GNSS:
				k_msleep(1000);
				printf("%s:%d - [GSTP] stop gnss \n", __FUNCTION__, __LINE__ );
				rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GSTP, &temp_flags);
				k_msleep(200);
				fix_state = ST_SGE_STATUS;
				break;

			case ST_UPDATE_TIME:
				k_msleep(1000);
				printf("%s:%d - [GTIM] update time \n", __FUNCTION__, __LINE__);
				struct sensor_value gtim[3] = {{2022,8},{29,16},{11,30}};
				rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GTIM, gtim);
				fix_state = ST_SGE_STATUS;
				break;

			case ST_COLD_START:
				k_msleep(1000);
				rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GCD, &sensValues);

				fix_time_sec = 0;
				k_timer_start(&hot_start_timer, K_SECONDS(1), K_SECONDS(1));
				printf("%s:%d - [GCD] cold start GNSS \n", __FUNCTION__, __LINE__);
				fix_state = ST_WAIT_FOR_FIX;
				break;

			case ST_WARM_START:
				k_msleep(1000);
				rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GSW, &sensValues);
				k_msleep(4000);

				fix_time_sec = 0;
				k_timer_start(&hot_start_timer, K_SECONDS(1), K_SECONDS(1));
				printf("%s:%d - [GSW] warm start GNSS \n", __FUNCTION__, __LINE__);
				fix_state = ST_WAIT_FOR_FIX;
				break;

			case NEXT_FIX1:
				k_msleep(5000);
				fix_state = ST_WAIT_FOR_FIX;
				break;

			default:
				fix_state = ST_WAIT_FOR_FIX;
				break;

		}

		k_msleep(500);
	}
}

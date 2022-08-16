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

#define DISPLAY_LOCATION

/*#define DEBUG_PRINT*/

void call_back_1PPS() {
	printf("%s:%d - User 1PPS\n",__FUNCTION__,__LINE__);
}

int main(void)
{
#ifdef DISPLAY_LOCATION
	uint32_t ppsonoff = 0;
	int32_t integral;
	int32_t frac;
	struct sensor_value temp_flags;
#endif

	const struct device *cxd5605;
	int rc;

	struct sensor_value sensValues;

	printf("Sony CXD5605 Example, %s\n", CONFIG_ARCH);

	cxd5605 = DEVICE_DT_GET_ANY(sony_cxd5605);

	if (!cxd5605) {
		printf("cxd5605 driver error\n");
		return 1;
	}

	sensor_attr_set(cxd5605,
		SENSOR_CHAN_AMBIENT_TEMP,
		SENSOR_ATTRIBUTE_CXD5605_CONTINUOUS_CONVERSION_MODE,
		NULL);

	sensValues.val1 = 1;
	sensValues.val2 = 38;
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_CALLBACK, &sensValues);
	sensValues.val1 = 1;
	sensValues.val2 = (int32_t)call_back_1PPS;
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_TURN_ON_1PPS, &sensValues);

	printf("Reading NMEA sentences\n");

	/* wait 3 seconds for GNSS to boot*/
	k_msleep(3000);

	printf("cxd5605 booted up\n");
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_VER, NULL);
	k_msleep(200);
	struct sensor_value gsop[3] = {{1,3000},{0,0}};
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GSOP, gsop);
	k_msleep(200);
	sensValues.val1 = 0x01;
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_BSSL, &sensValues);
	k_msleep(200);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GCD, &sensValues);
	k_msleep(200);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_WAKE_UP, &sensValues);
	k_msleep(200);
#ifndef DISPLAY_LOCATION
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GPTC, NULL);
	k_msleep(200);
	sensValues.val1 = 100;
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_ABPT, &sensValues);
	k_msleep(200);
	sensValues.val1 = 1;
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_ABUP, &sensValues);
	k_msleep(200);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_BUP, NULL);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_BUPC, NULL);
	sensValues.val1 = 115200;
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_CSBR, &sensValues);
	struct sensor_value gpos[3] = {{35123456,139987650},{0,0}};
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GPOS, gpos);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GSP, NULL);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GSR, NULL);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GSW, NULL);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GTE,NULL);
	sensValues.val1 = -250;
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GTCX, NULL);
	sensValues.val1 = GUSE_FITNESS_MODE;
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GUSE, &sensValues);
	struct sensor_value gtim[3] = {{2022,6},{4,13},{30,30}};
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GTIM, gtim);
	struct sensor_value sval[3] = {{35,37},{9,139},{43,51}};
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GPOE, sval);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GALG, &sensValues);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_LALG, &sensValues);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_LEMG, &sensValues);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_QALG, &sensValues);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_QEMG, &sensValues);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_GALS, &sensValues);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_LALS, &sensValues);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_LEMS, &sensValues);
	rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_QALS, &sensValues);
#endif

	/* get version from CXD5605 */
	sensor_attr_get(cxd5605, GNSS_CHANNEL_POSITION,
			GNSS_ATTRIBUTE_VER,
			&temp_flags);
	printf("Version = %s\n",(char *)temp_flags.val1);

	while (1) {
#ifdef DISPLAY_LOCATION
		sensor_attr_get(cxd5605,
			GNSS_CHANNEL_POSITION,
			GNSS_ATTRIBUTE_LATITUDE,
			&temp_flags);
		integral = temp_flags.val1/10000000;
		frac = temp_flags.val1-(integral*10000000);
		frac = (frac / 60.0) * 100.0;
		frac = (frac < 0) ? (frac * -1) : frac;
		printf("Latitude = %d.%d\n",integral,frac);
		sensor_attr_get(cxd5605,
			GNSS_CHANNEL_POSITION,
			GNSS_ATTRIBUTE_LONGITUDE,
			&temp_flags);
		integral = temp_flags.val1/10000000;
		frac = temp_flags.val1-(integral*10000000);
		frac = (frac / 60.0) * 100.0;
		frac = (frac < 0) ? (frac * -1) : frac;
		printf("Longitude = %d.%d\n",integral,frac);
		sensor_attr_get(cxd5605,
			GNSS_CHANNEL_POSITION,
			GNSS_ATTRIBUTE_ALTITUDE_MSL,
			&temp_flags);
		printf("Altitude (MSL) = %d.%d\n",temp_flags.val1,temp_flags.val2);
		sensor_attr_get(cxd5605,
			GNSS_CHANNEL_POSITION,
			GNSS_ATTRIBUTE_ALTITUDE_HAE,
			&temp_flags);
		printf("Altitude (HAE) = %d.%d\n",temp_flags.val1,temp_flags.val2);
		sensor_attr_get(cxd5605,
			GNSS_CHANNEL_POSITION,
			GNSS_ATTRIBUTE_HDOP,
			&temp_flags);
		printf("HDOP = %d.%d\n",temp_flags.val1,temp_flags.val2);
		sensor_attr_get(cxd5605,
			GNSS_CHANNEL_POSITION,
			GNSS_ATTRIBUTE_SIV,
			&temp_flags);
		printf("Number of Satellites = %d\n",temp_flags.val1);
		sensor_attr_get(cxd5605,
			GNSS_CHANNEL_POSITION,
			GNSS_ATTRIBUTE_FIXTYPE,
			&temp_flags);
		printf("Fix type = %d\n",temp_flags.val1);

		sensor_attr_get(cxd5605,
			GNSS_CHANNEL_VELOCITY,
			GNSS_ATTRIBUTE_PDOP,
			&temp_flags);
		printf("PDOP = %d.%d\n",temp_flags.val1, temp_flags.val2);
		ppsonoff++;
		if (ppsonoff == 10) {
			sensValues.val1 = 1;
			sensValues.val2 = (int32_t)call_back_1PPS;
			rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_TURN_ON_1PPS, &sensValues);
		} else if (ppsonoff == 20) {
			ppsonoff = 0;
			sensValues.val1 = 0;
			sensValues.val2 = 0;
			rc = sensor_attr_set(cxd5605,SENSOR_CHAN_ALL,SENSOR_ATTRIBUTE_CXD5605_TURN_ON_1PPS, &sensValues);

		}
#endif
		k_msleep(2000);
	}
}

 /*
 * Copyright (c) 2022 Kim Mansfield <kmansfie@yahoo.com>
 * Copyright (c) 2022 T-Mobile USA, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief Device driver for the gnss (CXD5605) device
 */

#define DT_DRV_COMPAT sony_cxd5605

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <stddef.h>
#include <float.h>
#include <device.h>
#include <string.h>
#include <ctype.h>
#include <kernel.h>
#include <drivers/i2c.h>
#include <drivers/sensor.h>
#include <drivers/sensor/gnss.h>
#include <drivers/sensor/cxd5605.h>
#include <sys/util.h>
#include <sys/byteorder.h>
#include <logging/log.h>
#include <fs/fs.h>

#include "cxd5605.h"

extern char  *strtok_r(char *str, const char *sep, char **state);

LOG_MODULE_REGISTER(CXD5605, CONFIG_SENSOR_LOG_LEVEL);

#define SEND_BUF_SIZE 32

#define CXD5605_ADDRESS DT_N_S_soc_S_i2c_4000c400_S_sonycxd5605_24_REG_IDX_0_VAL_ADDRESS

#define CXD5605_LLE_XFER_SIZE 2048
#define MAXFIELDS 32

#define COMMAND_STR_LENGTH 12

struct cxd5605_config {
	const struct i2c_dt_spec i2c_spec;
	const struct gpio_dt_spec alert_gpio;
	const struct gpio_dt_spec int_gpio;
};

struct drv_data {
	struct gpio_callback gpio_cb;
	gpio_flags_t mode;
	int index;
	int aux;
};

/** @brief Initial routine to call to get things running
 *
 *  This routine does the usual things in that it sets some variables
 *  to an initial value check that the i2c bus is operational and saves
 *  the device structure pointer off for use by other routines in the
 *  driver
 *
 *  @param dev The pointer to the device structure for this driver
 *
 *  @return returns an error (-ENODEV) if the i2c bus is not ready
 *
 */
int init(const struct device *dev)
{
	const struct cxd5605_config *cfg = dev->config;
	struct cxd5605_data *drv_data = dev->data;
	int result = 0;

	drv_data->pvt.position.latitude = 0.0;
	drv_data->pvt.position.longitude = 0.0;
	drv_data->pvt.position.altitude_MSL = 0.0;
	drv_data->pvt.position.altitude = 0.0;

	drv_data->cxd5605_cmd = -1;
	drv_data->num_msg = 0;

	if (!device_is_ready(cfg->i2c_spec.bus)) {
		LOG_ERR("I2C dev %s not ready", cfg->i2c_spec.bus->name);
		return -ENODEV;
	}

#ifdef CONFIG_CXD5605_ALERT_INTERRUPTS
	LOG_DBG("Got CXD5605_ALERT_INTERRUPTS\n");
	setup_interrupts(dev);
#endif

	/* save this driver instance for passing to other functions */
	drv_data->cxd5605_dev = dev;

	return result;
}

/** @brief This routine takes a comma separated list and breaks it up
 * 	   into tokens.
 *
 *  This routine takes a comma separated string and creates an array
 *  of string pointers that point to each token in the string.  Each
 *  comman is replaced by a null to terminate the string.  If there are
 *  two commas together there are two nulls put in their place and you
 *  get a 0 length token which is perfect.  This routine does not
 *  require any dynamic memory allocation for the tokens and you get
 *  the exact token that came in the string.  The number of maximum
 *  fields is MAXFIELDS defined above.
 *
 *  @param string is a pointer to the comma separated list
 *  @param separator contains the comma separator
 *  @param fields is the array of pointer to the field or tokens
 *
 *  @return returns the number of fields that was scanned
 *
 */
int csv_split(char *string, char separator, char *fields[])
{
	int field=0;		
	char separates[4];

	separates[0] = separator;
	separates[1] = '\n';
	separates[2] = '\r';
	separates[3] = 0;

	while ((fields[field++] = strtok_r(string, separates, &string)) && (field < MAXFIELDS))
		;
	
	return (field-1);
}

/** @brief This routine is a wrapper for the i2c_write_dt routine
 *
 *  @param dev device structure
 *  @param addr the address of the I2C device
 *  @param data pointer to the data to send
 *  @param num_bytes is the number of bytes to send
 *
 *  @return it returns the error code from i2c_write_dt
 *
 */
static int write_bytes(const struct device *dev, uint16_t addr,
		       uint8_t *data, uint32_t num_bytes)
{
	const struct cxd5605_config *cfg = dev->config;

	return i2c_write_dt(&cfg->i2c_spec, data, num_bytes);
}

/** @brief This routine is a wrapper for the i2c_read_dt routine
 *
 *  @param dev device structure
 *  @param addr the address of the I2C device
 *  @param data pointer to buffer to receive characters
 *  @param num_bytes is the number of bytes you can receive
 *
 *  @return it returns the error code from i2c_read_dt
 *
 */
static int read_bytes(const struct device *dev, uint16_t addr,
		      uint8_t *data, uint32_t num_bytes)
{
	const struct cxd5605_config *cfg = dev->config;

	return i2c_read_dt(&cfg->i2c_spec, data, num_bytes);
}

/** @brief Convert attribute from int to string.
 *
 *  @param cmd integer representation of the attribute.
 * 
 *  @return Returns a string value of the attribute.
 *
 */
static char * cmd_to_str(int cmd) {
	switch(cmd) {
		case SENSOR_ATTRIBUTE_CXD5605_TURN_ON_1PPS: return "GPPS";
		case SENSOR_ATTRIBUTE_CXD5605_BSSL: return "BSSL";
		case SENSOR_ATTRIBUTE_CXD5605_GCD: return "GCD";
		case SENSOR_ATTRIBUTE_CXD5605_WAKE_UP: return "WUP";
		case SENSOR_ATTRIBUTE_CXD5605_ABPT: return "ABPT";
		case SENSOR_ATTRIBUTE_CXD5605_ABUP: return "ABUP";
		case SENSOR_ATTRIBUTE_CXD5605_BUP: return "BUP";
		case SENSOR_ATTRIBUTE_CXD5605_BUPC: return "BUPC";
		case SENSOR_ATTRIBUTE_CXD5605_CSBR: return "CSBR";
		case SENSOR_ATTRIBUTE_CXD5605_FER: return "FER";
		case SENSOR_ATTRIBUTE_CXD5605_GALG: return "GALG";
		case SENSOR_ATTRIBUTE_CXD5605_GALS: return "GALS";
		case SENSOR_ATTRIBUTE_CXD5605_GEMG: return "GEMG";
		case SENSOR_ATTRIBUTE_CXD5605_GEMS: return "GEMS";
		case SENSOR_ATTRIBUTE_CXD5605_GNS: return "GNS";
		case SENSOR_ATTRIBUTE_CXD5605_GPOE: return "GPOE";
		case SENSOR_ATTRIBUTE_CXD5605_GPOS: return "GPOS";
		case SENSOR_ATTRIBUTE_CXD5605_GPTC: return "GPTC";
		case SENSOR_ATTRIBUTE_CXD5605_GSOP: return "GSOP";
		case SENSOR_ATTRIBUTE_CXD5605_GSP: return "GSP";
		case SENSOR_ATTRIBUTE_CXD5605_GSR: return "GSR";
		case SENSOR_ATTRIBUTE_CXD5605_GSW: return "GSW";
		case SENSOR_ATTRIBUTE_CXD5605_GTCX: return "GTCX";
		case SENSOR_ATTRIBUTE_CXD5605_GTE: return "GTE";
		case SENSOR_ATTRIBUTE_CXD5605_GTIM: return "GTIM";
		case SENSOR_ATTRIBUTE_CXD5605_GTR: return "GTR";
		case SENSOR_ATTRIBUTE_CXD5605_GTS: return "GTS";
		case SENSOR_ATTRIBUTE_CXD5605_LALG: return "LALG";
		case SENSOR_ATTRIBUTE_CXD5605_LALS: return "LALS";
		case SENSOR_ATTRIBUTE_CXD5605_LEMG: return "LEMG";
		case SENSOR_ATTRIBUTE_CXD5605_LEMS: return "LEMS";
		case SENSOR_ATTRIBUTE_CXD5605_QALG: return "QALG";
		case SENSOR_ATTRIBUTE_CXD5605_QALS: return "QALS";
		case SENSOR_ATTRIBUTE_CXD5605_QEMG: return "QEMG";
		case SENSOR_ATTRIBUTE_CXD5605_QEMS: return "QEMS";
		case SENSOR_ATTRIBUTE_CXD5605_SLP: return "SLP";
		case SENSOR_ATTRIBUTE_CXD5605_VER: return "VER";
		case SENSOR_ATTRIBUTE_CXD5605_GUSE: return "GUSE";
		case SENSOR_ATTRIBUTE_CXD5605_CEPS: return "CEPS";
		case SENSOR_ATTRIBUTE_CXD5605_CEPW: return "CEPW";
		case SENSOR_ATTRIBUTE_CXD5605_CEPC: return "CEPC";
		default:
			return "NA";
		break;
	}
}

/** @brief This routine takes a command response and converts it
 *         to tokens.
 *
 *  It takes a string and uses csv_split above to create the tokens
 *
 *  @param string which is a pointer to the comma separated list
 *
 *  @return it returns the number of tokens
 *
 */
static int get_cmd_response(char *string) 
{
	char *temp_field[MAXFIELDS];

	int num_field = csv_split(string, ' ',temp_field);
	return (num_field > 2 ? atoi(temp_field[2]) : 0);
}

/** @brief This routine reads almanac and ephemeris binary data
 *
 *  @param dev device structure
 *  @param dest pointer to the binary data
 *  @param src pointer to buffer to receive characters
 *
 *  @return None
 *
 */
static void read_binary_data(const struct device *dev, uint8_t *dest, struct cxd5605_packet *src) 
{
	int ret;
	struct cxd5605_data *drv_data = dev->data;

	switch(drv_data->num_msg) {
		case 0:
			// Get the size of the binary data
			drv_data->bin_data_len = drv_data->bytes_remaining = (src->data[2] << 8 ) | (src->data[3] + 8); // header + data + footer
		case 1:
			if (drv_data->bytes_remaining < CXD5605_PACKET_DATA_SIZE)
				drv_data->copy_length = drv_data->bytes_remaining;
			else 
				drv_data->copy_length = CXD5605_PACKET_DATA_SIZE;
			memcpy(&dest[drv_data->bin_data_ptr],src->data, drv_data->copy_length);
			drv_data->bin_data_ptr += drv_data->copy_length;
			drv_data->bytes_remaining = (drv_data->bin_data_len  - drv_data->bin_data_ptr);
			drv_data->num_msg = (!drv_data->bytes_remaining ? 2:1);
			break;
		case 2:
			ret = get_cmd_response(src->data);
			drv_data->num_msg = 0;
			drv_data->cxd5605_cmd = -1;
			drv_data->bin_data_ptr = 0;
			break;
	}
}

/** @brief This routine calculates checksum of the binary data
 *
 *  @param vals block of data to be calculated
 *  @param len size of the data
 *
 *  @return returns 8-bit checksum
 *
 */
static uint8_t get_checksum(uint8_t *vals, uint8_t len) 
{
	uint32_t checksum = 0;
	for (int i=0; i<len; i++) {
		checksum += vals[i];
	}
	checksum &= 0xFF;
	checksum = ~checksum;
	return checksum & 0x000000FF;
}

/** @brief This routine writes almanac and ephemeris binary data
 *
 *  @param dev device structure
 *  @param cmd is the command to send
 *  @param to_send pointer to a buffer to send
 *  @param rd_data pointer to a buffer to receive characters
 *
 *  @return None
 *
 */
static void write_binary_data(const struct device *dev, int cmd, uint8_t *to_send, struct cxd5605_packet *rd_data) 
{
	int ret;
	char cmd_str[COMMAND_STR_LENGTH];
	int snprintf_return;
	struct cxd5605_data *drv_data = dev->data;
	
	snprintf_return = snprintf(cmd_str, COMMAND_STR_LENGTH, "[%s] Ready", cmd_to_str(cmd));
	if (snprintf_return > COMMAND_STR_LENGTH || snprintf_return < 0) {
		LOG_ERR("%s:%d, snprintf error %d ",__FILE__,__LINE__,snprintf_return);
		return;
	}

	switch(drv_data->num_msg) {
		case 0: 
			if (!strncmp(cmd_str, rd_data->data, 0x0c)) {
				drv_data->bin_data_len = (to_send[2] << 8 ) | (to_send[3] + 8); // header + data + footer
				LOG_DBG("cxd5600: bin_data_len %d\n", drv_data->bin_data_len);
				drv_data->bin_data_ptr = 0;

				struct cxd5605_packet packet;
				packet.preamble = 0xa5;
				packet.packet_type = 0x0f;
				
				while((drv_data->bytes_remaining = (drv_data->bin_data_len - drv_data->bin_data_ptr))) {
					LOG_DBG("bytes_remaining %d\n", drv_data->bytes_remaining);
					packet.data_size = (drv_data->bytes_remaining < 70 ? drv_data->bytes_remaining:70);
					memcpy(packet.data, &to_send[drv_data->bin_data_ptr],packet.data_size );
					packet.checksum = get_checksum((uint8_t *)&packet,CXD5605_PACKET_SIZE-1);
					ret = write_bytes(dev, CXD5605_ADDRESS, (uint8_t *)&packet, CXD5605_PACKET_SIZE);
					drv_data->bin_data_ptr+=packet.data_size;
				}
				LOG_DBG("done writing almanac data\n");
				drv_data->num_msg = 1;
			}
			break;
		case 1:
			ret = get_cmd_response(rd_data->data);
			LOG_DBG("[cxd5605:rx] - cmd: %d  err: %d \n", drv_data->cxd5605_cmd, ret);
			drv_data->num_msg = 0;
			drv_data->cxd5605_cmd = -1;
			break;
	}
}

/** @brief Callback routine for 1PPS interrupt. It will be called every second
 *  from 1PPS output port after getting a fix
 *
 *  @param dev Pointer to device structure for the driver instance.
 *  @param gpio_cb pointer to gpio callback structure
 *  @param pins Mask of pins that triggers the callback handler
 *
 *  @return None
 *
 */
static void callback_1pps(const struct device *dev,
			 struct gpio_callback *gpio_cb, uint32_t pins)
{
	struct cxd5605_data *drv_data = CONTAINER_OF(gpio_cb, struct cxd5605_data, one_pps_gpio_cb);

	if (drv_data->gpps_cb)
		(drv_data->gpps_cb)();
}

/** @brief Local implementation of atof since atof and strod are not in
 * minimal libc
 *
 * @param str Pointer to string representing float, [+/-][<decimal>][.<fraction>]
 *
 * @return Converted double value
 */
static double atod(const char *str)
{
	double ret = 0.0;
	bool neg = false;

	// remove leading space
	while (isspace(*str)) str++;

	// get sign if present
	if (*str && (*str == '-' || *str == '+')) {
		if (*str == '-') {
			neg = true;
		}
		str++;
	}

	// get decimal part
	while (*str && isdigit(*str)) {
		ret = ret * 10 + (*str - '0');
		str++;
	}

	// get fractional part
	if (*str && *str == '.') {
		double frac = 0.0;
		double div = 1.0;
		str++;
		while (*str && isdigit(*str)) {
			frac = frac * 10 + (*str - '0');
			str++;
			div *= 10.0;
		}
		ret = ret + frac / div;
	}
	return neg ? (ret * -1.0) : ret;
}

/** @brief Callback routine for alert gpio interrupt. It will be called when GPS data/response is ready.
 *
 *  @param dev Pointer to device structure for the driver instance.
 *  @param gpio_cb pointer to gpio callback structure
 *  @param pins Mask of pins that triggers the callback handler
 *
 *  @return None
 *
 */
static void callback(const struct device *dev,
                     struct gpio_callback *gpio_cb, uint32_t pins)
{
	int ret;
	int field;
	char to_send[32];
	struct cxd5605_packet rd_data;
	int result;
	char *temp_field[MAXFIELDS];
	int readbytes;

	struct cxd5605_data *drv_data = CONTAINER_OF(gpio_cb, struct cxd5605_data, data_ready_gpio_cb);

	ret = read_bytes(drv_data->cxd5605_dev, CXD5605_ADDRESS, (uint8_t *)&rd_data, CXD5605_PACKET_SIZE);
	if (ret) {
		LOG_ERR("read_bytes function:Error reading from CXD5605! error code (%d)\n", ret);
	} else   {
		/* decode response*/
		rd_data.data[rd_data.data_size] = 0;
		LOG_DBG("nmea - %s\n", rd_data.data);
			if (strchr(rd_data.data,'$')) {
				field = csv_split(rd_data.data, ',', temp_field);

				if (!strncmp("$GPGGA",temp_field[NMEA_SENTENCE_ID_IDX], NMEA_SENTENCE_ID_LEN)) {
					if (atoi(temp_field[GGA_QUALITY_INDICATOR_IDX]) == 1) {
						uint32_t t = atod(temp_field[GGA_UTC_OF_POSITION_IDX]) * 100;
						drv_data->pvt.time.gnss_hour = (t / 1000000);
						drv_data->pvt.time.gnss_minute = (t % 1000000) / 10000;
						drv_data->pvt.time.gnss_second = (t % 10000) / 100;
						drv_data->pvt.time.gnss_nanosecond = (t % 100) * 10000000;

						drv_data->pvt.position.latitude= (atod(temp_field[GGA_LATITUDE_IDX]) * 100000);
						if (temp_field[GGA_LATITUDE_DIR_IDX][0] == 'S') {
							drv_data->pvt.position.latitude *= -1;
						}
						drv_data->pvt.position.longitude = (atod(temp_field[GGA_LONGITUDE_IDX]) * 100000);
						if (temp_field[GGA_LONGITUDE_DIR_IDX][0] == 'W') {
							drv_data->pvt.position.longitude *= -1;
						}
						drv_data->pvt.position.fix_type = atoi(temp_field[GGA_QUALITY_INDICATOR_IDX]);
						drv_data->pvt.position.SIV = atoi(temp_field[GGA_NUM_SATELLITE_IDX]);
						drv_data->pvt.position.horizontal_accuracy = atod(temp_field[GGA_HDOP_IDX]) * 10;
						drv_data->pvt.position.altitude_MSL = atod(temp_field[GGA_ALTITUDE_IDX]);
						/* Subtract geoidal separation value from altitude (MSL) to arrive at the 
						 * altitude (height above Ellipsoid)
						 */
						drv_data->pvt.position.altitude = drv_data->pvt.position.altitude_MSL - atod(temp_field[GGA_GEOIDAL_SEPARATION_IDX]);
					} else {
						drv_data->pvt.time.gnss_hour = 0;
						drv_data->pvt.time.gnss_minute = 0;
						drv_data->pvt.time.gnss_second = 0;
						drv_data->pvt.time.gnss_nanosecond = 0;
						drv_data->pvt.position.latitude= 0.0;
						drv_data->pvt.position.longitude = 0.0;
						drv_data->pvt.position.fix_type = 0;
						drv_data->pvt.position.SIV = 0;
						drv_data->pvt.position.horizontal_accuracy = 0.0;
						drv_data->pvt.position.altitude_MSL = 0.0;
						drv_data->pvt.position.altitude = 0.0;
					}

				} else if (!strncmp("$GPGNS",temp_field[NMEA_SENTENCE_ID_IDX],NMEA_SENTENCE_ID_LEN)) {

					uint32_t t = atod(temp_field[GGA_UTC_OF_POSITION_IDX]) * 100;
					drv_data->pvt.time.gnss_hour = (t / 1000000);
					drv_data->pvt.time.gnss_minute = (t % 1000000) / 10000;
					drv_data->pvt.time.gnss_second = (t % 10000) / 100;
					drv_data->pvt.time.gnss_nanosecond = (t % 100) * 10000000;

					drv_data->pvt.position.latitude= (atod(temp_field[GNS_LATITUDE_IDX]) * 100000);
					if (temp_field[GNS_LATITUDE_DIR_IDX][0] == 'S') {
						drv_data->pvt.position.latitude *= -1;
					}
					drv_data->pvt.position.longitude = (atod(temp_field[GNS_LONGITUDE_IDX]) * 100000);
					if (temp_field[GNS_LONGITUDE_DIR_IDX][0] == 'W') {
						drv_data->pvt.position.longitude *= -1;
					}

					drv_data->pvt.position.SIV = atoi(temp_field[GNS_NUM_SATELLITE_IDX]);
					drv_data->pvt.position.horizontal_accuracy = atod(temp_field[GNS_HDOP_IDX]) * 10;
					drv_data->pvt.position.altitude_MSL = atod(temp_field[GNS_ALTITUDE_IDX]);
					/* Subtract geoidal separation value from altitude (MSL) to arrive at the 
					* altitude (height above Ellipsoid)
					*/
					drv_data->pvt.position.altitude = drv_data->pvt.position.altitude_MSL - atod(temp_field[GNS_GEOIDAL_SEPARATION_IDX]);

					
				} else if (!strncmp("$GPGLL",temp_field[NMEA_SENTENCE_ID_IDX], NMEA_SENTENCE_ID_LEN)) {

					uint32_t t = atod(temp_field[GLL_UTC_OF_POSITION_IDX]) * 100;
					drv_data->pvt.time.gnss_hour = (t / 1000000);
					drv_data->pvt.time.gnss_minute = (t % 1000000) / 10000;
					drv_data->pvt.time.gnss_second = (t % 10000) / 100;
					drv_data->pvt.time.gnss_nanosecond = (t % 100) * 10000000;

					drv_data->pvt.position.latitude= (atod(temp_field[GLL_LATITUDE_IDX]) * 100000);
					if (temp_field[GLL_LATITUDE_DIR_IDX][0] == 'S') {
						drv_data->pvt.position.latitude *= -1;
					}
					drv_data->pvt.position.longitude = (atod(temp_field[GLL_LONGITUDE_IDX]) * 100000);
					if (temp_field[GLL_LONGITUDE_DIR_IDX][0] == 'W') {
						drv_data->pvt.position.longitude *= -1;
					}
					
				}
			} else {
				if (drv_data->cxd5605_cmd < 0) {
					return;
				}

				switch (drv_data->cxd5605_cmd) {
					case SENSOR_ATTRIBUTE_CXD5605_CEPW:
					field = csv_split(rd_data.data, ' ', temp_field);
					if (!strncmp("[CEPW]",temp_field[0],5)) {
						if (!strncmp("Ready",temp_field[1],5)) {
							uint32_t csum = 0;
							uint8_t *packet_ptr;
							// LLE binary data
							drv_data->cepw_packet.preamble = 0xA0;
							drv_data->cepw_packet.control_type = 0x80;	// no checksum 0, checksum 0x80
							drv_data->cepw_packet.data_length_upper = (CXD5605_LLE_XFER_SIZE & 0xFF00) >> 8 ;
							drv_data->cepw_packet.data_length_lower = CXD5605_LLE_XFER_SIZE & 0x00FF;

							readbytes = fs_read(&(drv_data->cxdfile), drv_data->cepw_packet.data, CXD5605_LLE_XFER_SIZE);
							LOG_DBG("readbytes = %d\n",readbytes);
							if (readbytes < 0) {
								LOG_ERR("Could not read file %s","/tmo/cep_pak.bin");
								// stop the transmission
								drv_data->cxd5605_cmd = -1;
							}

							for (int i=0; i<CXD5605_LLE_XFER_SIZE; i++)
								csum += drv_data->cepw_packet.data[i];

							csum += drv_data->cepw_packet.preamble;
							csum += drv_data->cepw_packet.control_type;
							csum += drv_data->cepw_packet.data_length_upper;
							csum += drv_data->cepw_packet.data_length_lower;

							drv_data->cepw_packet.checksum_upper = (csum & 0xFF00) >> 8;
							drv_data->cepw_packet.checksum_lower = csum & 0x00FF;
							drv_data->cepw_packet.fixed_value1 = 0x00;
							drv_data->cepw_packet.fixed_value2 = 0xB0;

							drv_data->bin_data_len = CXD5605_LLE_XFER_SIZE +  8;
							LOG_DBG("bin_data_len %d\n", drv_data->bin_data_len);
							drv_data->bin_data_ptr = 0;

							
							packet_ptr = (uint8_t *)(&(drv_data->cepw_packet));

							while (drv_data->bin_data_ptr < drv_data->bin_data_len) {
								if ((drv_data->bin_data_len - drv_data->bin_data_ptr) < 28) {
									write_bytes(dev, CXD5605_ADDRESS, &packet_ptr[drv_data->bin_data_ptr], drv_data->bin_data_len-drv_data->bin_data_ptr);
									drv_data->bin_data_ptr = drv_data->bin_data_len;
								} else {
									write_bytes(dev, CXD5605_ADDRESS, &packet_ptr[drv_data->bin_data_ptr], 28);
									drv_data->bin_data_ptr += 28;
								}
								k_usleep((3000));
							}

						} else if (!strncmp("Done",temp_field[1],4)) {
							if (drv_data->cepw_packet_num > 127) {
								drv_data->cxd5605_cmd = -1;
							} else {
								result = snprintf(to_send, SEND_BUF_SIZE, "@CEPW %d\r\n", drv_data->cepw_packet_num++);
								if (result > SEND_BUF_SIZE || result < 0) {
									LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
								}
								write_bytes(dev, CXD5605_ADDRESS, to_send, strlen(to_send));
							}
						} else if (!strncmp("Err",temp_field[1],3)) {
							LOG_ERR("Err: %s\n",temp_field[2]);
							drv_data->cxd5605_cmd = -1;
						}
					}
					break;
					
					case SENSOR_ATTRIBUTE_CXD5605_VER:
					if (drv_data->num_msg == 0) {
						csv_split(rd_data.data, ',', temp_field);
						drv_data->cxd5605_cmd_data.ver.major = strtol(temp_field[0], NULL, 16);
						drv_data->cxd5605_cmd_data.ver.minor = strtol(temp_field[1], NULL, 16);
						drv_data->cxd5605_cmd_data.ver.patch = strtol(temp_field[2], NULL, 16);
						drv_data->num_msg++;
					} else if (drv_data->num_msg == 1) {
						ret = get_cmd_response(rd_data.data);
						result = snprintf(drv_data->version, 32, "%d.%d.%d", drv_data->cxd5605_cmd_data.ver.major, drv_data->cxd5605_cmd_data.ver.minor, drv_data->cxd5605_cmd_data.ver.patch);
						if (result > 32 || result < 0) {
							LOG_ERR("[%s:%d] to_send buffer error %d",__FILE__,__LINE__,result);
						}

						drv_data->num_msg = 0;
						drv_data->cxd5605_cmd = -1;
					}
					break;

					case SENSOR_ATTRIBUTE_CXD5605_ERASE: 
					break;
					
					case SENSOR_ATTRIBUTE_CXD5605_GTR: 
					if (drv_data->num_msg == 0) {
						csv_split(rd_data.data, ',', temp_field);
						drv_data->cxd5605_cmd_data.gtr.cn_level = atod(temp_field[0]);
						drv_data->cxd5605_cmd_data.gtr.doppler_freq = atod(temp_field[1]);
						drv_data->num_msg++;
					} else if (drv_data->num_msg == 1) {
						ret = get_cmd_response(rd_data.data);
						drv_data->num_msg = 0;
						drv_data->cxd5605_cmd = -1;
					}
					break;

					case SENSOR_ATTRIBUTE_CXD5605_GPTC:
					if (drv_data->num_msg == 0) {
						if (strstr(rd_data.data,"INVALID")) {
							drv_data->cxd5605_cmd_data.txco_offset = 0.0;
						} else {
							drv_data->cxd5605_cmd_data.txco_offset = atod(rd_data.data);
						}
						drv_data->num_msg++;
					} else if (drv_data->num_msg ==1) {
						ret = get_cmd_response(rd_data.data);
						drv_data->num_msg = 0;
						drv_data->cxd5605_cmd = -1;
					}
					break;

					case SENSOR_ATTRIBUTE_CXD5605_GALG: 
					read_binary_data(dev, drv_data->cxd5605_cmd_data.galg_almanac, &rd_data);
					break;

					case SENSOR_ATTRIBUTE_CXD5605_GEMG:
					read_binary_data(dev, drv_data->cxd5605_cmd_data.gemg_ephemeris, &rd_data);
					break;
					
					case SENSOR_ATTRIBUTE_CXD5605_LALG:
					read_binary_data(dev, drv_data->cxd5605_cmd_data.lalg_almanac, &rd_data);
					break;

					case SENSOR_ATTRIBUTE_CXD5605_LEMG:
					read_binary_data(dev, drv_data->cxd5605_cmd_data.lemg_ephemeris, &rd_data);
					break;

					case SENSOR_ATTRIBUTE_CXD5605_QALG:
					read_binary_data(dev, drv_data->cxd5605_cmd_data.qalg_almanac, &rd_data);
					break;

					case SENSOR_ATTRIBUTE_CXD5605_QEMG:
					read_binary_data(dev, drv_data->cxd5605_cmd_data.qemg_ephemeris, &rd_data);
					break;

					case SENSOR_ATTRIBUTE_CXD5605_GALS:
					write_binary_data(dev,drv_data->cxd5605_cmd,drv_data->cxd5605_cmd_data.galg_almanac, &rd_data);
					break;

					case SENSOR_ATTRIBUTE_CXD5605_GEMS:
					write_binary_data(dev,drv_data->cxd5605_cmd,drv_data->cxd5605_cmd_data.gemg_ephemeris, &rd_data);
					break;

					case SENSOR_ATTRIBUTE_CXD5605_LALS:
					write_binary_data(dev,drv_data->cxd5605_cmd,drv_data->cxd5605_cmd_data.lalg_almanac, &rd_data);
					break;

					case SENSOR_ATTRIBUTE_CXD5605_LEMS:
					write_binary_data(dev,drv_data->cxd5605_cmd,drv_data->cxd5605_cmd_data.lemg_ephemeris, &rd_data);
					break;

					case SENSOR_ATTRIBUTE_CXD5605_QALS:
					write_binary_data(dev,drv_data->cxd5605_cmd,drv_data->cxd5605_cmd_data.qalg_almanac, &rd_data);
					break;

					case SENSOR_ATTRIBUTE_CXD5605_QEMS:
					write_binary_data(dev,drv_data->cxd5605_cmd,drv_data->cxd5605_cmd_data.qemg_ephemeris, &rd_data);
					break;

					default: 
					/* These are commands that do not have data. We just simply print the result. */
					ret = get_cmd_response(rd_data.data);
					drv_data->num_msg = 0;
					drv_data->cxd5605_cmd = -1;
					break;
				
				}
			}

	}
}

/** @brief Get a reading from CXD5605.
 *
 *  @param dev device structure
 *  @param chan The channel to read
 *  @param val Where to store the value
 *
 *  @return Return a useful value for a particular channel, from the driver’s internal data
 *
 */
static int cxd5605_channel_get(const struct device *dev,
                              enum sensor_channel chan,
                              struct sensor_value *val)
{
	int32_t integral;
	int32_t frac;
	struct cxd5605_data *drv_data = dev->data;

	switch(chan) {
	case SENSOR_CHAN_POS_DX:
       		integral = (int)(drv_data->pvt.position.latitude)/10000000.0;
		frac = drv_data->pvt.position.latitude - (integral*10000000);
		frac = (frac / 60.0) * 100.0;
		frac = (frac < 0) ? (frac * -1) : frac;
       		val->val1 = integral;
       		val->val2 = frac/10;
		break;

	case SENSOR_CHAN_POS_DY:
       		integral = (int)(drv_data->pvt.position.longitude)/10000000.0;
		frac = drv_data->pvt.position.longitude - (integral*10000000);
		frac = (frac / 60.0) * 100.0;
       		val->val1 = integral;
       		val->val2 = frac/10;
		break;

	case SENSOR_CHAN_ALTITUDE:
       		val->val1 = (drv_data->pvt.position.altitude_MSL);
       		val->val2 = 0;
		break;

	default:
        	return -ENOTSUP;
	}

        return 0;
}

/** @brief Read attribute value 
 *
 *  @param dev device structure
 *  @param chan The channel the attribute belongs to
 * 	depending on device capabilities.
 *  @param attr The attribute to get
 *  @param val Pointer to where to store the attribute
 *
 *  @return 0 if successful, negative errno code if failure.
 *
 */
static int cxd5605_attr_get(const struct device *dev,
			   enum sensor_channel chan,
			   enum sensor_attribute attr,
			   struct sensor_value *val)
{
	struct cxd5605_data *drv_data = dev->data;

	if (chan == (enum sensor_channel)GNSS_CHANNEL_TIME) {
		val->val1 =(int)((drv_data->pvt.time.gnss_hour * 10000) + (drv_data->pvt.time.gnss_minute * 100) + (drv_data->pvt.time.gnss_second));
		val->val2 = 0;
	}
	if (chan == (enum sensor_channel)GNSS_CHANNEL_TIME && attr == (enum sensor_attribute)GNSS_ATTRIBUTE_DAY) {
		val->val1 = (int)drv_data->pvt.time.gnss_day;
		val->val2 = 0;
	}
	if (chan == (enum sensor_channel)GNSS_CHANNEL_TIME && attr == (enum sensor_attribute)GNSS_ATTRIBUTE_MONTH) {
		val->val1 = (int)drv_data->pvt.time.gnss_month;
		val->val2 = 0;
	}
	if (chan == (enum sensor_channel)GNSS_CHANNEL_TIME && attr == (enum sensor_attribute)GNSS_ATTRIBUTE_YEAR) {
		val->val1 = (int)drv_data->pvt.time.gnss_year;
		val->val2 = 0;
	}

	if (chan == (enum sensor_channel)GNSS_CHANNEL_POSITION && attr == (enum sensor_attribute)GNSS_ATTRIBUTE_LATITUDE) {
		val->val1 = (int)(drv_data->pvt.position.latitude);
		val->val2 = 0;
	}
	if (chan == (enum sensor_channel)GNSS_CHANNEL_POSITION && attr == (enum sensor_attribute)GNSS_ATTRIBUTE_LONGITUDE) {
		val->val1 = (int)(drv_data->pvt.position.longitude);
		val->val2 = 0;
	}
	if (chan == (enum sensor_channel)GNSS_CHANNEL_POSITION && attr == (enum sensor_attribute)GNSS_ATTRIBUTE_ALTITUDE_MSL) {
		val->val1 = (int)(drv_data->pvt.position.altitude_MSL);
		val->val2 = (int)((drv_data->pvt.position.altitude_MSL-val->val1) * 100);
	}
	if (chan == (enum sensor_channel)GNSS_CHANNEL_POSITION && attr == (enum sensor_attribute)GNSS_ATTRIBUTE_ALTITUDE_HAE) {
		val->val1 = (int)(drv_data->pvt.position.altitude);
		val->val2 = (int)((drv_data->pvt.position.altitude-val->val1) * 100);
	}
	if (chan == (enum sensor_channel)GNSS_CHANNEL_POSITION && attr == (enum sensor_attribute)GNSS_ATTRIBUTE_HDOP) {
		val->val1 = (int)(drv_data->pvt.position.horizontal_accuracy / 10);
		val->val2 = (int)(drv_data->pvt.position.horizontal_accuracy%10);
	}
	if (chan == (enum sensor_channel)GNSS_CHANNEL_POSITION && attr == (enum sensor_attribute)GNSS_ATTRIBUTE_SIV) {
		val->val1 = (int)(drv_data->pvt.position.SIV);
		val->val2 = 0;
	}
	if (chan == (enum sensor_channel)GNSS_CHANNEL_POSITION && attr == (enum sensor_attribute)GNSS_ATTRIBUTE_FIXTYPE) {
		val->val1 = (int)(drv_data->pvt.position.fix_type);
		val->val2 = 0;
	}

	if (chan == (enum sensor_channel)GNSS_CHANNEL_VELOCITY && attr == (enum sensor_attribute)GNSS_ATTRIBUTE_PDOP) {
		val->val1 = (int)(drv_data->pvt.velocity.pDOP);
		val->val2 = (int)((drv_data->pvt.velocity.pDOP-val->val1) * 100);
	}

	if (chan == (enum sensor_channel)GNSS_CHANNEL_POSITION && attr == (enum sensor_attribute)GNSS_ATTRIBUTE_VER) {
		val->val1 = (int)(drv_data->version);
		val->val2 = 0;
	}
	return 0;
}

/** @brief Set attribute value 
 *
 *  @param dev device structure
 *  @param chan The channel the attribute belongs to
 *  @param attr The attribute to set
 *  @param val value to set the attribute to
 *
 *  @return 0 if successful, negative errno code if failure
 *
 */
static int cxd5605_attr_set(const struct device *dev,
			   enum sensor_channel chan,
			   enum sensor_attribute attr,
			   const struct sensor_value *val)
{
	int result = 0;
	char to_send[SEND_BUF_SIZE];

	uint32_t lat_deg = 0;
	uint32_t lat_min = 0;
	uint32_t lat_sec = 0;
	uint32_t lon_deg = 0;
	uint32_t lon_min = 0;
	uint32_t lon_sec = 0;

	uint8_t year = 0;
	uint8_t month = 0;
	uint8_t day = 0;
	uint8_t hour = 0;
	uint8_t min = 0;
	uint8_t sec = 0;


	//struct cxd5605_config *cfg = dev->config;
	struct cxd5605_data *drv_data = dev->data;

	if (chan != SENSOR_CHAN_AMBIENT_TEMP && chan != SENSOR_CHAN_ALL) {
		return -ENOTSUP;
	}

	drv_data->cxd5605_cmd = (int)attr;
	LOG_DBG("[cxd5605:tx] - cmd %s (%d)\r\n", cmd_to_str(drv_data->cxd5605_cmd), drv_data->cxd5605_cmd);

	switch (drv_data->cxd5605_cmd) {
	
		case SENSOR_ATTRIBUTE_CXD5605_TURN_ON_1PPS:

			if (val->val1 > 0) {
				result = snprintf(to_send, SEND_BUF_SIZE, "@GPPS 0x01\r\n");
				if (result > SEND_BUF_SIZE || result < 0) {
					LOG_ERR("[%s:%d] to_send buffer error %d",__FILE__,__LINE__,result);
					return result;
				}
				if (val->val2) {
					/* set 1 pps interrupt callback routine */
					drv_data->gpps_cb = ((void (*)(void))val->val2);
				}
			} else {
				result = snprintf(to_send, SEND_BUF_SIZE, "@GPPS 0x00\r\n");
				if (result > SEND_BUF_SIZE || result < 0) {
					LOG_ERR("[%s:%d] to_send buffer error " "%d", __FILE__, __LINE__, result);
					return result;
				}
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GCD:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GCD\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_WAKE_UP:
			result = snprintf(to_send, SEND_BUF_SIZE, "@WUP\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_ABPT:
			result = snprintf(to_send, SEND_BUF_SIZE, "@ABPT %d\r\n", val->val1);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_ABUP:
			result = snprintf(to_send, SEND_BUF_SIZE, "@ABUP %d\r\n", val->val1);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_BSSL:
			result = snprintf(to_send, SEND_BUF_SIZE, "@BSSL  0x%02X\r\n", val->val1);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_BUP:
			result = snprintf(to_send, SEND_BUF_SIZE, "@BUP\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_BUPC:
			result = snprintf(to_send, SEND_BUF_SIZE, "@BUPC\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;
		
		case SENSOR_ATTRIBUTE_CXD5605_CSBR:
			result = snprintf(to_send, SEND_BUF_SIZE, "@CSBR %d\r\n", val->val1);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			LOG_DBG("csbr %s\n", to_send);
			break;

		case SENSOR_ATTRIBUTE_CXD5605_FER:
			result = snprintf(to_send, SEND_BUF_SIZE, "@FER\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			drv_data->version[0] = 0;
			drv_data->cxd5605_cmd_data.ver.major = 0;
			drv_data->cxd5605_cmd_data.ver.minor = 0;
			drv_data->cxd5605_cmd_data.ver.patch = 0;
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GALG:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GALG\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GALS:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GALS\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GEMG:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GEMG\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GEMS:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GEMS\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GNS:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GNS 0x%02X\r\n", val->val1);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GPOE:
			lat_deg = val[0].val1;
			lat_min = val[0].val2;

			lat_sec = val[1].val1;
			lon_deg = val[1].val2;

			lon_min = val[2].val1;
			lon_sec = val[2].val2;

			result = snprintf(to_send, SEND_BUF_SIZE, "@GPOE %d %d %d %d %d %d\r\n", lat_deg, lat_min, lat_sec, lon_deg, lon_min, lon_sec);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GPOS:
			lat_deg = val[0].val1;
			lat_min = val[0].val2;
			lat_sec = val[1].val1;

			result = snprintf(to_send, SEND_BUF_SIZE, "@GPOS %d %d %d\r\n", lat_deg, lat_min, lat_sec);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GPTC:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GPTC\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GSOP:
			lat_deg = val[0].val1;
			lat_min = val[0].val2;
			lat_sec = val[1].val1;
			result = snprintf(to_send, SEND_BUF_SIZE, "@GSOP %d %d %d\r\n", lat_deg, lat_min, lat_sec);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GSP:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GSP\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GSR:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GSR\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GSW:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GSW\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GTCX:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GTCX %d\r\n", val->val1);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GTE:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GTE\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GTIM:
			year = val[0].val1;
			month = val[0].val2;
			day = val[1].val1;
			hour = val[1].val2;
			min = val[2].val1;
			sec = val[2].val2;

			result = snprintf(to_send, SEND_BUF_SIZE, "@GTIM %d %d %d %d %d %d\r\n", year, month, day, hour, min, sec);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GTR:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GTR\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GTS:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GTIM %d %d %d %d\r\n", val->val1, 0, 0, 0);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_GUSE:
			result = snprintf(to_send, SEND_BUF_SIZE, "@GUSE %d\r\n", val->val1);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_LALG:
			result = snprintf(to_send, SEND_BUF_SIZE, "@LALG\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;
		
		case SENSOR_ATTRIBUTE_CXD5605_LALS:
			result = snprintf(to_send, SEND_BUF_SIZE, "@LALS\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;
		
		case SENSOR_ATTRIBUTE_CXD5605_LEMG:
			result = snprintf(to_send, SEND_BUF_SIZE, "@LEMG\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_LEMS:
			result = snprintf(to_send, SEND_BUF_SIZE, "@LEMS\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_QALG:
			result = snprintf(to_send, SEND_BUF_SIZE, "@QALG\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;


		case SENSOR_ATTRIBUTE_CXD5605_QALS:
			result = snprintf(to_send, SEND_BUF_SIZE, "@QALS\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_QEMG:
			result = snprintf(to_send, SEND_BUF_SIZE, "@QEMG\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_QEMS:
			result = snprintf(to_send, SEND_BUF_SIZE, "@QEMS\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_SLP:
			result = snprintf(to_send, SEND_BUF_SIZE, "@SLP %d\r\n", val->val1);
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_VER:
			result = snprintf(to_send, SEND_BUF_SIZE, "@VER\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_ERASE:
			result = snprintf(to_send, SEND_BUF_SIZE, "@FER\r\n");
			if (result > SEND_BUF_SIZE || result < 0) {
				LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
				return result;
			}
			drv_data->version[0] = 0;
			drv_data->cxd5605_cmd_data.ver.major = 0;
			drv_data->cxd5605_cmd_data.ver.minor = 0;
			drv_data->cxd5605_cmd_data.ver.patch = 0;
			break;
		
		case SENSOR_ATTRIBUTE_CXD5605_CEPW:
			drv_data->cepw_packet_num = 0;
			if (fs_open(&(drv_data->cxdfile), "/tmo/filelle1.bin", FS_O_READ) != 0) {
				LOG_ERR("Could not open file %s", "/tmo/filelle1.bin");
			} else {
				result = snprintf(to_send, SEND_BUF_SIZE, "@CEPW %d\r\n", drv_data->cepw_packet_num);
				if (result > SEND_BUF_SIZE || result < 0) {
					LOG_ERR("[%s:%d] to_send buffer error %d", __FILE__, __LINE__, result);
					return result;
				}
			}
			break;

		case SENSOR_ATTRIBUTE_CXD5605_CALLBACK:
			init(dev);
			setup_interrupts(dev);
			return 0; 
			break;

	default:
		return -ENOTSUP;
	}

	result = write_bytes(dev, CXD5605_ADDRESS, to_send, strlen(to_send));
	if (result < 0) {
		return result;
	}

	return 0;
}

static const struct sensor_driver_api cxd5605_driver_api = 
{
	.attr_set = cxd5605_attr_set,
	.attr_get = cxd5605_attr_get,
	.channel_get = cxd5605_channel_get,
};

/** @brief Setup 1PPS and Alert interrupt
 *
 *  @param dev device structure
 *
 *  @return 0 if successful, negative errno code if failure
 *
 */
int setup_interrupts(const struct device *dev)
{
	int result;
	struct cxd5605_data *drv_data = dev->data;
	const struct cxd5605_config *config = dev->config;
	const struct gpio_dt_spec *alert_gpio = &config->alert_gpio;
	const struct gpio_dt_spec *int_gpio = &config->int_gpio;

	if (!device_is_ready(alert_gpio->port)) {
		LOG_ERR("cxd5605: gpio controller %s not ready",
			alert_gpio->port->name);
		return -ENODEV;
	}

	result = gpio_pin_configure_dt(alert_gpio, GPIO_INPUT);

	if (result < 0) {
		return result;
	}

	gpio_init_callback(&drv_data->data_ready_gpio_cb,
			   callback,
			   BIT(alert_gpio->pin));

	result = gpio_add_callback(alert_gpio->port,
				   &drv_data->data_ready_gpio_cb);

	if (result < 0) {
		return result;
	}

	result = gpio_pin_interrupt_configure_dt(alert_gpio,
						 GPIO_INT_EDGE_RISING);

	if (result < 0) {
		return result;
	}

	/* setup 1pps interrupt */
	result = gpio_pin_configure_dt(int_gpio, GPIO_INPUT);

	if (result < 0) {
		return result;
	}

	gpio_init_callback(&drv_data->one_pps_gpio_cb,
			   callback_1pps,
			   BIT(int_gpio->pin));

	result = gpio_add_callback(int_gpio->port,
				   &drv_data->one_pps_gpio_cb);

	if (result < 0) {
		return result;
	}

	result = gpio_pin_interrupt_configure_dt(int_gpio,
						 GPIO_INT_EDGE_RISING);

	if (result < 0) {
		return result;
	}

	return 0;
}

#define CXD5605_DEFINE(inst)						   \
	static struct cxd5605_data cxd5605_prv_data_##inst;		   \
	static struct cxd5605_config cxd5605_config_##inst = {	   	   \
		.i2c_spec = I2C_DT_SPEC_INST_GET(inst),			   \
		.alert_gpio = GPIO_DT_SPEC_INST_GET_OR(inst,		   \
						       alert_gpios, { 0 }),\
		.int_gpio = GPIO_DT_SPEC_INST_GET_OR(inst,		   \
						       int_gpios, { 0 })   \
	};								   \
	DEVICE_DT_INST_DEFINE(inst,					   \
			      &init,				   	   \
			      NULL,					   \
			      &cxd5605_prv_data_##inst,			   \
			      &cxd5605_config_##inst,			   \
			      POST_KERNEL,				   \
			      CONFIG_SENSOR_INIT_PRIORITY,		   \
			      &cxd5605_driver_api);

DT_INST_FOREACH_STATUS_OKAY(CXD5605_DEFINE)

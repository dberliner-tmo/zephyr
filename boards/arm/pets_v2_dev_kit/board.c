/*
 * Copyright (c) 2018 Christian Taedcke
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <init.h>
#include "board.h"
#include <drivers/gpio.h>
#include <sys/printk.h>

// This is currently used to turn on the "virtual serial port" by toggling the enable line
// remove this on the final silabs board?

static int pets_v2_dev_kit(const struct device *dev)
{
	const struct device *bce_dev; /* Board Controller Enable Gpio Device */

	ARG_UNUSED(dev);

	/* Enable the board controller to be able to use the serial port */
	bce_dev = device_get_binding(BC_ENABLE_GPIO_NAME);

	if (!bce_dev) {
		printk("Board controller gpio port was not found!\n");
		return -ENODEV;
	}

	gpio_pin_configure(bce_dev, BC_ENABLE_GPIO_PIN, GPIO_OUTPUT_HIGH);

	return 0;
}

/* needs to be done after GPIO driver init */
SYS_INIT(pets_v2_dev_kit, POST_KERNEL,
	 CONFIG_KERNEL_INIT_PRIORITY_DEVICE);

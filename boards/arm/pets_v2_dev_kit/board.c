#include <init.h>
#include "board.h"
#include <drivers/gpio.h>
#include <sys/printk.h>

static int pets_v2_dev_kit(const struct device *dev)
{
    ARG_UNUSED(dev);

    // Reset and bring up RS9116W
    const struct device *radio_gpio_dev = device_get_binding(RADIO_GPIO_NAME);

    if (!radio_gpio_dev) {
        printk("Board controller gpio port was not found!\n");
        return -ENODEV;
    }

    // RS9116W startup sequence:
    //     set WAKE, POC, and RESET to high
    //     wait 10 msec
    //     set POC and RESET to low
    //     wait 10 msec
    //     set POC to HIGH
    //     wait 10 msec
    //     set RESET to HIGH
    //     wait 1 sec for it to complete start
    gpio_pin_configure(radio_gpio_dev, RADIO_WAKE_GPIO_PIN, GPIO_OUTPUT_HIGH);
    gpio_pin_configure(radio_gpio_dev, RADIO_POC_GPIO_PIN, GPIO_OUTPUT_HIGH);
    gpio_pin_configure(radio_gpio_dev, RADIO_RESET_GPIO_PIN, GPIO_OUTPUT_HIGH);
    k_msleep(10);
    gpio_pin_configure(radio_gpio_dev, RADIO_POC_GPIO_PIN, GPIO_OUTPUT_LOW);
    gpio_pin_configure(radio_gpio_dev, RADIO_RESET_GPIO_PIN, GPIO_OUTPUT_LOW);
    k_msleep(10);
    gpio_pin_configure(radio_gpio_dev, RADIO_POC_GPIO_PIN, GPIO_OUTPUT_HIGH);
    k_msleep(10);
    gpio_pin_configure(radio_gpio_dev, RADIO_RESET_GPIO_PIN, GPIO_OUTPUT_HIGH);
    k_msleep(1000);

    return 0;
}

/* Call the function above, needs to be done after GPIO driver init */
SYS_INIT(pets_v2_dev_kit, POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEVICE);

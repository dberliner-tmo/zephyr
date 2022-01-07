/*
 * Copyright (c) 2018, NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <init.h>
#include <fsl_iomuxc.h>
#include <fsl_gpio.h>
#include <soc.h>
#include <logging/log.h>

LOG_MODULE_REGISTER(mimxrt1064_evk, LOG_LEVEL_INF);

#if DT_NODE_HAS_STATUS(DT_NODELABEL(enet), okay) && CONFIG_NET_L2_ETHERNET
static gpio_pin_config_t enet_gpio_config = {
	.direction = kGPIO_DigitalOutput,
	.outputLogic = 0,
	.interruptMode = kGPIO_NoIntmode
};
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(usdhc1), okay) && CONFIG_DISK_DRIVER_SDMMC

/*Drive Strength Field: R0(260 Ohm @ 3.3V, 150 Ohm@1.8V, 240 Ohm for DDR)
 *Speed Field: medium(100MHz)
 *Open Drain Enable Field: Open Drain Disabled
 *Pull / Keep Enable Field: Pull/Keeper Enabled
 *Pull / Keep Select Field: Pull
 *Pull Up / Down Config. Field: 47K Ohm Pull Up
 *Hyst. Enable Field: Hysteresis Enabled.
 */

static void mimxrt1064_evk_usdhc_pinmux(uint16_t nusdhc, bool init, uint32_t speed,
					uint32_t strength)
{
	uint32_t cmd_data = IOMUXC_SW_PAD_CTL_PAD_SPEED(speed) |
			 IOMUXC_SW_PAD_CTL_PAD_SRE_MASK |
			 IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			 IOMUXC_SW_PAD_CTL_PAD_PUE_MASK |
			 IOMUXC_SW_PAD_CTL_PAD_HYS_MASK |
			 IOMUXC_SW_PAD_CTL_PAD_PUS(1) |
			 IOMUXC_SW_PAD_CTL_PAD_DSE(strength);

	uint32_t clk = IOMUXC_SW_PAD_CTL_PAD_SPEED(speed) |
		    IOMUXC_SW_PAD_CTL_PAD_SRE_MASK |
		    IOMUXC_SW_PAD_CTL_PAD_HYS_MASK |
		    IOMUXC_SW_PAD_CTL_PAD_PUS(0) |
		    IOMUXC_SW_PAD_CTL_PAD_DSE(strength);

	if (nusdhc != 0) {
		LOG_ERR("Invalid USDHC index");
		return;
	}

	if (init) {
		IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_05_GPIO1_IO05, 0U);

		/* SD_CD */
		IOMUXC_SetPinMux(IOMUXC_GPIO_B1_12_GPIO2_IO28, 0U);
		IOMUXC_SetPinMux(IOMUXC_GPIO_B1_14_USDHC1_VSELECT, 0U);
		IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_00_USDHC1_CMD, 0U);
		IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_01_USDHC1_CLK, 0U);
		IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_02_USDHC1_DATA0, 0U);
		IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_03_USDHC1_DATA1, 0U);
		IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_04_USDHC1_DATA2, 0U);
		IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_05_USDHC1_DATA3, 0U);

		IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_05_GPIO1_IO05, 0x10B0u);

		/* SD0_CD_SW */
		IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_12_GPIO2_IO28, 0x017089u);

		/* SD0_VSELECT */
		IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_14_USDHC1_VSELECT,
				    0x0170A1u);
	}

	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_00_USDHC1_CMD, cmd_data);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_01_USDHC1_CLK, clk);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_02_USDHC1_DATA0, cmd_data);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_03_USDHC1_DATA1, cmd_data);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_04_USDHC1_DATA2, cmd_data);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_05_USDHC1_DATA3, cmd_data);
}
#endif

static int mimxrt1064_evk_init(const struct device *dev)
{
	ARG_UNUSED(dev);

	CLOCK_EnableClock(kCLOCK_Iomuxc);
	CLOCK_EnableClock(kCLOCK_IomuxcSnvs);

#if DT_NODE_HAS_PROP(DT_INST(0, focaltech_ft5336), int_gpios)
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_11_GPIO1_IO11, 0);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_11_GPIO1_IO11,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));
#endif

#if !CONFIG_NET_L2_ETHERNET
	/* Shared GPIO between USER_LED and ENET_RST */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_09_GPIO1_IO09, 0);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_09_GPIO1_IO09,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

	/* SW0 */
	IOMUXC_SetPinMux(IOMUXC_SNVS_WAKEUP_GPIO5_IO00, 0);
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(lpuart1), okay) && CONFIG_SERIAL
	/* LPUART1 TX/RX */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_12_LPUART1_TX, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_13_LPUART1_RX, 0);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_12_LPUART1_TX,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_13_LPUART1_RX,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(lpuart3), okay) && CONFIG_SERIAL
	/* LPUART3 TX/RX */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_06_LPUART3_TX, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_07_LPUART3_RX, 0);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B1_06_LPUART3_TX,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B1_07_LPUART3_RX,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(lcdif), okay) && CONFIG_DISPLAY
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_00_LCD_CLK, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_01_LCD_ENABLE, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_02_LCD_HSYNC, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_03_LCD_VSYNC, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_04_LCD_DATA00, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_05_LCD_DATA01, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_06_LCD_DATA02, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_07_LCD_DATA03, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_08_LCD_DATA04, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_09_LCD_DATA05, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_10_LCD_DATA06, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_11_LCD_DATA07, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_12_LCD_DATA08, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_13_LCD_DATA09, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_14_LCD_DATA10, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B0_15_LCD_DATA11, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_00_LCD_DATA12, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_01_LCD_DATA13, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_02_LCD_DATA14, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_03_LCD_DATA15, 0);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_00_LCD_CLK, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_01_LCD_ENABLE, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_02_LCD_HSYNC, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_03_LCD_VSYNC, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_04_LCD_DATA00, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_05_LCD_DATA01, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_06_LCD_DATA02, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_07_LCD_DATA03, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_08_LCD_DATA04, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_09_LCD_DATA05, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_10_LCD_DATA06, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_11_LCD_DATA07, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_12_LCD_DATA08, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_13_LCD_DATA09, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_14_LCD_DATA10, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B0_15_LCD_DATA11, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_00_LCD_DATA12, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_01_LCD_DATA13, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_02_LCD_DATA14, 0x01B0B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_03_LCD_DATA15, 0x01B0B0u);

	/* LCD Reset */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_02_GPIO1_IO02, 0);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_02_GPIO1_IO02, 0x10B0u);

	/* LCD Backlight */
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_15_GPIO2_IO31, 0);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_15_GPIO2_IO31, 0x10B0u);

	gpio_pin_config_t config = {
		kGPIO_DigitalOutput, 0,
	};

	config.outputLogic = 1;
	GPIO_PinInit(GPIO2, 31, &config);
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(lpi2c1), okay) && CONFIG_I2C
	/* LPI2C1 SCL, SDA */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_00_LPI2C1_SCL, 1);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_01_LPI2C1_SDA, 1);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B1_00_LPI2C1_SCL,
			    IOMUXC_SW_PAD_CTL_PAD_PUS(3) |
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_ODE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B1_01_LPI2C1_SDA,
			    IOMUXC_SW_PAD_CTL_PAD_PUS(3) |
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_ODE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(enet), okay) && CONFIG_NET_L2_ETHERNET
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_09_GPIO1_IO09, 0U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_10_GPIO1_IO10, 0U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_04_ENET_RX_DATA00, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_05_ENET_RX_DATA01, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_06_ENET_RX_EN, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_07_ENET_TX_DATA00, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_08_ENET_TX_DATA01, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_09_ENET_TX_EN, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_10_ENET_REF_CLK, 1);
	IOMUXC_SetPinMux(IOMUXC_GPIO_B1_11_ENET_RX_ER, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_EMC_40_ENET_MDC, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_EMC_41_ENET_MDIO, 0);

	/* Shared GPIO between USER_LED and ENET_RST */
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_09_GPIO1_IO09, 0xB0A9u);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_10_GPIO1_IO10, 0xB0A9u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_04_ENET_RX_DATA00, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_05_ENET_RX_DATA01, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_06_ENET_RX_EN, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_07_ENET_TX_DATA00, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_08_ENET_TX_DATA01, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_09_ENET_TX_EN, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_10_ENET_REF_CLK, 0x31);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_B1_11_ENET_RX_ER, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_EMC_40_ENET_MDC, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_EMC_41_ENET_MDIO, 0xB829);

	IOMUXC_EnableMode(IOMUXC_GPR, kIOMUXC_GPR_ENET1TxClkOutputDir, true);

	/* Intialize ENET_INT GPIO */
	GPIO_PinInit(GPIO1, 9, &enet_gpio_config);
	GPIO_PinInit(GPIO1, 10, &enet_gpio_config);

	/* pull up the ENET_INT before RESET. */
	GPIO_WritePinOutput(GPIO1, 10, 1);
	GPIO_WritePinOutput(GPIO1, 9, 0);
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(flexpwm2_pwm3), okay) && CONFIG_PWM
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_09_FLEXPWM2_PWMA03, 0);
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(csi), okay) && CONFIG_VIDEO
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_04_GPIO1_IO04, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_04_CSI_PIXCLK, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_05_CSI_MCLK, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_06_CSI_VSYNC, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_07_CSI_HSYNC, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_08_CSI_DATA09, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_09_CSI_DATA08, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_10_CSI_DATA07, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_11_CSI_DATA06, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_12_CSI_DATA05, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_13_CSI_DATA04, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_14_CSI_DATA03, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_15_CSI_DATA02, 0);
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(flexcan1), okay) && CONFIG_CAN
	/* FLEXCAN1 TX, RX */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_08_FLEXCAN1_TX, 1);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_09_FLEXCAN1_RX, 1);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B1_08_FLEXCAN1_TX, 0x10B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B1_09_FLEXCAN1_RX, 0x10B0u);
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(flexcan2), okay) && CONFIG_CAN
	/* FLEXCAN2 TX, RX */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_14_FLEXCAN2_TX, 1);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_15_FLEXCAN2_RX, 1);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_14_FLEXCAN2_TX, 0x10B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_15_FLEXCAN2_RX, 0x10B0u);
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(flexcan3), okay) && CONFIG_CAN
	/* FLEXCAN3 TX, RX */
	IOMUXC_SetPinMux(IOMUXC_GPIO_EMC_36_FLEXCAN3_TX, 1);
	IOMUXC_SetPinMux(IOMUXC_GPIO_EMC_37_FLEXCAN3_RX, 1);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_EMC_36_FLEXCAN3_TX, 0x10B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_EMC_37_FLEXCAN3_RX, 0x10B0u);
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(usdhc1), okay) && CONFIG_DISK_DRIVER_SDMMC
	mimxrt1064_evk_usdhc_pinmux(0, true, 2, 1);
	imxrt_usdhc_pinmux_cb_register(mimxrt1064_evk_usdhc_pinmux);
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(flexspi), okay) && CONFIG_FLASH
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B1_05_FLEXSPIA_DQS, 1U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B1_06_FLEXSPIA_SS0_B, 1U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B1_07_FLEXSPIA_SCLK, 1U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B1_08_FLEXSPIA_DATA00, 1U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B1_09_FLEXSPIA_DATA01, 1U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B1_10_FLEXSPIA_DATA02, 1U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B1_11_FLEXSPIA_DATA03, 1U);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B1_05_FLEXSPIA_DQS, 0x10F1U);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B1_06_FLEXSPIA_SS0_B, 0x10F1U);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B1_07_FLEXSPIA_SCLK, 0x10F1U);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B1_08_FLEXSPIA_DATA00, 0x10F1U);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B1_09_FLEXSPIA_DATA01, 0x10F1U);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B1_10_FLEXSPIA_DATA02, 0x10F1U);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B1_11_FLEXSPIA_DATA03, 0x10F1U);
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(lpspi1), okay) && CONFIG_SPI
#if DT_NODE_HAS_STATUS(DT_NODELABEL(usdhc1), okay) && CONFIG_DISK_DRIVER_SDMMC
	#error "SPI and SDMMC pins conflict on this board." \
		"Please disable one via KConfig or device tree"
#else
	/* LPSPI1 SCK, SDO, SDI, PCS0 */
	/* Expose these pins by connecting R278, R279, R280, and R281 on evk board */
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_00_LPSPI1_SCK, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_01_LPSPI1_PCS0, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_02_LPSPI1_SDO, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_03_LPSPI1_SDI, 0);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_00_LPSPI1_SCK,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_01_LPSPI1_PCS0,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_02_LPSPI1_SDO,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_03_LPSPI1_SDI,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));
#endif
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(lpspi3), okay) && CONFIG_SPI
	/* LPSPI3 SCK, SDO, SDI, PCS0 */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_00_LPSPI3_SCK, 0U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_01_LPSPI3_SDO, 0U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_02_LPSPI3_SDI, 0U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_03_LPSPI3_PCS0, 0U);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_00_LPSPI3_SCK,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_01_LPSPI3_SDO,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_02_LPSPI3_SDI,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_03_LPSPI3_PCS0,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(adc1), okay) && CONFIG_ADC
	/* ADC1 Input 0 */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_11_GPIO1_IO27, 0U);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B1_11_GPIO1_IO27,
			IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			IOMUXC_SW_PAD_CTL_PAD_DSE(6));
	/* ADC1 Input 15 */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_10_GPIO1_IO26, 0U);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B1_10_GPIO1_IO26,
			IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			IOMUXC_SW_PAD_CTL_PAD_DSE(6));
#endif

	return 0;
}

#if DT_NODE_HAS_STATUS(DT_NODELABEL(enet), okay) && CONFIG_NET_L2_ETHERNET
static int mimxrt1064_evk_phy_reset(const struct device *dev)
{
	/* RESET PHY chip. */
	k_busy_wait(USEC_PER_MSEC * 10U);
	GPIO_WritePinOutput(GPIO1, 9, 1);

	return 0;
}
#endif

SYS_INIT(mimxrt1064_evk_init, PRE_KERNEL_1, 0);
#if DT_NODE_HAS_STATUS(DT_NODELABEL(enet), okay) && CONFIG_NET_L2_ETHERNET
SYS_INIT(mimxrt1064_evk_phy_reset, POST_KERNEL, CONFIG_PHY_INIT_PRIORITY);
#endif

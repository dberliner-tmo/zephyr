/*
 *
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include <soc.h>
#include <stm32_ll_bus.h>
#include <stm32_ll_pwr.h>
#include <stm32_ll_rcc.h>
#include <stm32_ll_utils.h>
#include <stm32_ll_system.h>
#include <drivers/clock_control.h>
#include <sys/util.h>
#include <stm32_ll_utils.h>
#include <drivers/clock_control/stm32_clock_control.h>

/* Macros to fill up prescaler values */
#define z_ahb_prescaler(v) LL_RCC_SYSCLK_DIV_ ## v
#define ahb_prescaler(v) z_ahb_prescaler(v)

#define z_apb1_prescaler(v) LL_RCC_APB1_DIV_ ## v
#define apb1_prescaler(v) z_apb1_prescaler(v)

#define z_apb2_prescaler(v) LL_RCC_APB2_DIV_ ## v
#define apb2_prescaler(v) z_apb2_prescaler(v)

#define z_apb3_prescaler(v) LL_RCC_APB3_DIV_ ## v
#define apb3_prescaler(v) z_apb3_prescaler(v)


static uint32_t get_bus_clock(uint32_t clock, uint32_t prescaler)
{
	return clock / prescaler;
}

static uint32_t get_msis_frequency(void)
{
	return __LL_RCC_CALC_MSIS_FREQ(LL_RCC_MSIRANGESEL_RUN,
				STM32_MSIS_RANGE << RCC_ICSCR1_MSISRANGE_Pos);
}

__unused
static uint32_t get_pllsrc_frequency(void)
{

	if (IS_ENABLED(STM32_PLL_SRC_HSI)) {
		return STM32_HSI_FREQ;
	} else if (IS_ENABLED(STM32_PLL_SRC_HSE)) {
		return STM32_HSE_FREQ;
	} else if (IS_ENABLED(STM32_PLL_SRC_MSIS)) {
		return get_msis_frequency();
	}

	__ASSERT(0, "No PLL Source configured");
	return 0;
}

static uint32_t get_startup_frequency(void)
{
	switch (LL_RCC_GetSysClkSource()) {
	case LL_RCC_SYS_CLKSOURCE_STATUS_MSIS:
		return get_msis_frequency();
	case LL_RCC_SYS_CLKSOURCE_STATUS_HSI:
		return STM32_HSI_FREQ;
	default:
		__ASSERT(0, "Unexpected startup freq");
		return 0;
	}
}

static inline int stm32_clock_control_on(const struct device *dev,
					 clock_control_subsys_t sub_system)
{
	struct stm32_pclken *pclken = (struct stm32_pclken *)(sub_system);
	volatile uint32_t *reg;
	uint32_t reg_val;

	ARG_UNUSED(dev);

	if (IN_RANGE(pclken->bus, STM32_PERIPH_BUS_MIN, STM32_PERIPH_BUS_MAX) == 0) {
		/* Attemp to toggle a wrong periph clock bit */
		return -ENOTSUP;
	}

	reg = (uint32_t *)(DT_REG_ADDR(DT_NODELABEL(rcc)) + pclken->bus);
	reg_val = *reg;
	reg_val |= pclken->enr;
	*reg = reg_val;

	return 0;
}

static inline int stm32_clock_control_off(const struct device *dev,
					  clock_control_subsys_t sub_system)
{
	struct stm32_pclken *pclken = (struct stm32_pclken *)(sub_system);
	volatile uint32_t *reg;
	uint32_t reg_val;

	ARG_UNUSED(dev);

	if (IN_RANGE(pclken->bus, STM32_PERIPH_BUS_MIN, STM32_PERIPH_BUS_MAX) == 0) {
		/* Attemp to toggle a wrong periph clock bit */
		return -ENOTSUP;
	}

	reg = (uint32_t *)(DT_REG_ADDR(DT_NODELABEL(rcc)) + pclken->bus);
	reg_val = *reg;
	reg_val &= ~pclken->enr;
	*reg = reg_val;

	return 0;
}

static int stm32_clock_control_get_subsys_rate(const struct device *dev,
					       clock_control_subsys_t sys,
					       uint32_t *rate)
{
	struct stm32_pclken *pclken = (struct stm32_pclken *)(sys);

	if (IN_RANGE(pclken->bus, STM32_PERIPH_BUS_MIN, STM32_PERIPH_BUS_MAX) == 0) {
		/* Attemp to toggle a wrong periph clock bit */
		return -ENOTSUP;
	}

	/*
	 * Get AHB Clock (= SystemCoreClock = SYSCLK/prescaler)
	 * SystemCoreClock is preferred to CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC
	 * since it will be updated after clock configuration and hence
	 * more likely to contain actual clock speed
	 */
	uint32_t ahb_clock = SystemCoreClock;
	uint32_t apb1_clock = get_bus_clock(ahb_clock, STM32_APB1_PRESCALER);
	uint32_t apb2_clock = get_bus_clock(ahb_clock, STM32_APB2_PRESCALER);
	uint32_t apb3_clock = get_bus_clock(ahb_clock, STM32_APB3_PRESCALER);

	ARG_UNUSED(dev);

	switch (pclken->bus) {
	case STM32_CLOCK_BUS_AHB1:
	case STM32_CLOCK_BUS_AHB2:
	case STM32_CLOCK_BUS_AHB2_2:
	case STM32_CLOCK_BUS_AHB3:
		*rate = ahb_clock;
		break;
	case STM32_CLOCK_BUS_APB1:
	case STM32_CLOCK_BUS_APB1_2:
		*rate = apb1_clock;
		break;
	case STM32_CLOCK_BUS_APB2:
		*rate = apb2_clock;
		break;
	case STM32_CLOCK_BUS_APB3:
		*rate = apb3_clock;
		break;
	default:
		return -ENOTSUP;
	}

	return 0;
}

static struct clock_control_driver_api stm32_clock_control_api = {
	.on = stm32_clock_control_on,
	.off = stm32_clock_control_off,
	.get_rate = stm32_clock_control_get_subsys_rate,
};

__unused
static int get_vco_input_range(uint32_t m_div, uint32_t *range)
{
	uint32_t vco_freq;

	vco_freq = get_pllsrc_frequency() / m_div;

	if (MHZ(4) <= vco_freq && vco_freq <= MHZ(8)) {
		*range = LL_RCC_PLLINPUTRANGE_4_8;
	} else if (MHZ(8) < vco_freq && vco_freq <= MHZ(16)) {
		*range = LL_RCC_PLLINPUTRANGE_8_16;
	} else {
		return -ERANGE;
	}

	return 0;
}

static void set_regu_voltage(uint32_t hclk_freq)
{
	if (hclk_freq < MHZ(25)) {
		LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE4);
	} else if (hclk_freq < MHZ(55)) {
		LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE3);
	} else if (hclk_freq < MHZ(110)) {
		LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE2);
	} else {
		LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE1);
	}
	while (LL_PWR_IsActiveFlag_VOS() == 0) {
	}
}

__unused
static void clock_switch_to_hsi(void)
{
	/* Enable HSI if not enabled */
	if (LL_RCC_HSI_IsReady() != 1) {
		/* Enable HSI */
		LL_RCC_HSI_Enable();
		while (LL_RCC_HSI_IsReady() != 1) {
		/* Wait for HSI ready */
		}
	}

	LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);

	/* Set HSI as SYSCLCK source */
	LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_HSI);
	while (LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_HSI) {
	}
}

__unused
static int set_up_plls(void)
{
#if defined(STM32_PLL_ENABLED)
	int r;
	uint32_t vco_input_range;

	/*
	 * Switch to HSI and disable the PLL before configuration.
	 * (Switching to HSI makes sure we have a SYSCLK source in
	 * case we're currently running from the PLL we're about to
	 * turn off and reconfigure.)
	 */
	clock_switch_to_hsi();

	LL_RCC_PLL1_Disable();

	/* Configure PLL source */
	/* Can be HSE , HSI  MSI */
	if (IS_ENABLED(STM32_PLL_SRC_HSE)) {
		/* Main PLL configuration and activation */
		LL_RCC_PLL1_SetMainSource(LL_RCC_PLL1SOURCE_HSE);
	} else if (IS_ENABLED(STM32_PLL_SRC_MSIS)) {
		/* Main PLL configuration and activation */
		LL_RCC_PLL1_SetMainSource(LL_RCC_PLL1SOURCE_MSIS);
	} else if (IS_ENABLED(STM32_PLL_SRC_HSI)) {
		/* Main PLL configuration and activation */
		LL_RCC_PLL1_SetMainSource(LL_RCC_PLL1SOURCE_HSI);
	} else {
		return -ENOTSUP;
	}

	r = get_vco_input_range(STM32_PLL_M_DIVISOR, &vco_input_range);
	if (r < 0) {
		return r;
	}

	LL_RCC_PLL1_SetDivider(STM32_PLL_M_DIVISOR);

	LL_RCC_PLL1_SetVCOInputRange(vco_input_range);

	LL_RCC_PLL1_SetN(STM32_PLL_N_MULTIPLIER);

	LL_RCC_PLL1FRACN_Disable();

	if (IS_ENABLED(STM32_PLL_P_ENABLED)) {
		LL_RCC_PLL1_SetP(STM32_PLL_P_DIVISOR);
		LL_RCC_PLL1_EnableDomain_SAI();
	}

	if (IS_ENABLED(STM32_PLL_Q_ENABLED)) {
		LL_RCC_PLL1_SetQ(STM32_PLL_Q_DIVISOR);
		LL_RCC_PLL1_EnableDomain_48M();
	}

	if (IS_ENABLED(STM32_PLL_R_ENABLED)) {
		LL_RCC_PLL1_SetR(STM32_PLL_R_DIVISOR);
		LL_RCC_PLL1_EnableDomain_SYS();
	}

	LL_RCC_PLL1_Enable();
	while (LL_RCC_PLL1_IsReady() != 1U) {
	}

#else
	/* Init PLL source to None */
	LL_RCC_PLL1_SetMainSource(LL_RCC_PLL1SOURCE_NONE);

#endif /* STM32_PLL_ENABLED */

	return 0;
}

static void set_up_fixed_clock_sources(void)
{

	if (IS_ENABLED(STM32_HSE_ENABLED)) {
		/* Check if need to enable HSE bypass feature or not */
		if (IS_ENABLED(STM32_HSE_BYPASS)) {
			LL_RCC_HSE_EnableBypass();
		} else {
			LL_RCC_HSE_DisableBypass();
		}

		/* Enable HSE */
		LL_RCC_HSE_Enable();
		while (LL_RCC_HSE_IsReady() != 1) {
		/* Wait for HSE ready */
		}
	}

	if (IS_ENABLED(STM32_HSI_ENABLED)) {
		/* Enable HSI if not enabled */
		if (LL_RCC_HSI_IsReady() != 1) {
			/* Enable HSI */
			LL_RCC_HSI_Enable();
			while (LL_RCC_HSI_IsReady() != 1) {
			/* Wait for HSI ready */
			}
		}
	}

	if (IS_ENABLED(STM32_LSE_ENABLED)) {
		/* Enable the power interface clock */
		LL_AHB3_GRP1_EnableClock(LL_AHB3_GRP1_PERIPH_PWR);

		if (!LL_PWR_IsEnabledBkUpAccess()) {
			/* Enable write access to Backup domain */
			LL_PWR_EnableBkUpAccess();
			while (!LL_PWR_IsEnabledBkUpAccess()) {
				/* Wait for Backup domain access */
			}
		}

		/* Enable LSE Oscillator */
		LL_RCC_LSE_Enable();
		/* Wait for LSE ready */
		while (!LL_RCC_LSE_IsReady()) {
		}

		/* Enable LSESYS additionnally */
		LL_RCC_LSE_EnablePropagation();
		/* Wait till LSESYS is ready */
		while (!LL_RCC_LSESYS_IsReady()) {
		}

		LL_PWR_DisableBkUpAccess();
	}

	if (IS_ENABLED(STM32_MSIS_ENABLED)) {
		/* Set MSIS Range */
		LL_RCC_MSI_EnableRangeSelection();

		LL_RCC_MSIS_SetRange(STM32_MSIS_RANGE << RCC_ICSCR1_MSISRANGE_Pos);

		if (IS_ENABLED(STM32_MSIS_PLL_MODE)) {
			__ASSERT(STM32_LSE_ENABLED,
				"MSIS Hardware auto calibration needs LSE clock activation");
			/* Enable MSI hardware auto calibration */
			LL_RCC_SetMSIPLLMode(LL_RCC_PLLMODE_MSIS);
			LL_RCC_MSI_EnablePLLMode();
		}

		/* Enable MSIS */
		LL_RCC_MSIS_Enable();

		/* Wait till MSIS is ready */
		while (LL_RCC_MSIS_IsReady() != 1) {
		}
	}

	if (IS_ENABLED(STM32_MSIK_ENABLED)) {
		/* Set MSIK Range */
		LL_RCC_MSI_EnableRangeSelection();

		LL_RCC_MSIK_SetRange(STM32_MSIK_RANGE << RCC_ICSCR1_MSIKRANGE_Pos);

		if (IS_ENABLED(STM32_MSIK_PLL_MODE)) {
			__ASSERT(STM32_LSE_ENABLED,
				"MSIK Hardware auto calibration needs LSE clock activation");
			/* Enable MSI hardware auto calibration */
			LL_RCC_SetMSIPLLMode(LL_RCC_PLLMODE_MSIK);
			LL_RCC_MSI_EnablePLLMode();
		}

		if (IS_ENABLED(STM32_MSIS_ENABLED)) {
			__ASSERT((STM32_MSIK_PLL_MODE == STM32_MSIS_PLL_MODE),
				"Please check MSIS/MSIK config consistency");
		}

		/* Enable MSIK */
		LL_RCC_MSIK_Enable();

		/* Wait till MSIK is ready */
		while (LL_RCC_MSIK_IsReady() != 1) {
		}
	}

	if (IS_ENABLED(STM32_LSI_ENABLED)) {
		/* Enable LSI oscillator */
		LL_RCC_LSI_Enable();
		while (LL_RCC_LSI_IsReady() != 1) {
		}
	}

}

int stm32_clock_control_init(const struct device *dev)
{
	uint32_t old_hclk_freq = 0;
	int r = 0;

	ARG_UNUSED(dev);

	/* Current hclk value */
	old_hclk_freq = __LL_RCC_CALC_HCLK_FREQ(get_startup_frequency(), LL_RCC_GetAHBPrescaler());

	/* Set up indiviual enabled clocks */
	set_up_fixed_clock_sources();

	/* Set up PLLs */
	r = set_up_plls();
	if (r < 0) {
		return r;
	}

	/* Set voltage regulator to comply with targeted system frequency */
	set_regu_voltage(CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC);

	/* Set flash latency */
	/* If freq increases, set flash latency before any clock setting */
	if (old_hclk_freq < CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC) {
		LL_SetFlashLatency(CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC);
	}

	/* Set peripheral busses prescalers */
	LL_RCC_SetAHBPrescaler(ahb_prescaler(STM32_AHB_PRESCALER));
	LL_RCC_SetAPB1Prescaler(apb1_prescaler(STM32_APB1_PRESCALER));
	LL_RCC_SetAPB2Prescaler(apb2_prescaler(STM32_APB2_PRESCALER));
	LL_RCC_SetAPB3Prescaler(apb3_prescaler(STM32_APB3_PRESCALER));

	if (IS_ENABLED(STM32_SYSCLK_SRC_PLL)) {
		/* Set PLL1 as System Clock Source */
		LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_PLL1);
		while (LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_PLL1) {
		}
	} else if (IS_ENABLED(STM32_SYSCLK_SRC_HSE)) {
		/* Set HSE as SYSCLCK source */
		LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_HSE);
		while (LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_HSE) {
		}
	} else if (IS_ENABLED(STM32_SYSCLK_SRC_MSIS)) {
		/* Set MSIS as SYSCLCK source */
		LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_MSIS);
		while (LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_MSIS) {
		}
	} else if (IS_ENABLED(STM32_SYSCLK_SRC_HSI)) {
		/* Set HSI as SYSCLCK source */
		LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_HSI);
		while (LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_HSI) {
		}
	} else {
		return -ENOTSUP;
	}

	/* Set FLASH latency */
	/* If freq not increased, set flash latency after all clock setting */
	if (old_hclk_freq >= CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC) {
		LL_SetFlashLatency(CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC);
	}

	/* Update CMSIS variable */
	SystemCoreClock = CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC;

	return 0;
}

/**
 * @brief RCC device, note that priority is intentionally set to 1 so
 * that the device init runs just after SOC init
 */
DEVICE_DT_DEFINE(DT_NODELABEL(rcc),
		    &stm32_clock_control_init,
		    NULL,
		    NULL, NULL,
		    PRE_KERNEL_1,
		    CONFIG_CLOCK_CONTROL_INIT_PRIORITY,
		    &stm32_clock_control_api);

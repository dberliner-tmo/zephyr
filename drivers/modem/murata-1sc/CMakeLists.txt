# SPDX-License-Identifier: Apache-2.0

zephyr_library()

include_directories(${ZEPHYR_BASE}/drivers/modem)

if(CONFIG_MODEM_MURATA_1SC)
	zephyr_library_include_directories(${ZEPHYR_BASE}/subsys/net/ip)
	zephyr_library_sources(murata-1sc.c)
	zephyr_library_sources(strnstr.c)
endif()

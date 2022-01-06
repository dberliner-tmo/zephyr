# SPDX-License-Identifier: Apache-2.0
list(APPEND ZEPHYR_EXTRA_MODULES
  ${CMAKE_CURRENT_SOURCE_DIR}/../../drivers/sensor/tmp108
  )
  
cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(thermometer)

FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})

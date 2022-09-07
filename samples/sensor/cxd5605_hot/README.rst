.. gnss-step-3:

GNSS firmware hot start test
###########

Overview
********

This is an example of how you implement hot/warm starts for the CXD5605
chip.  It should help you take advantage of this feature in your code.

Building and Running
********************

This has been built for the dev edge board.  It takes the normal build command as
in the following:

west build -b tmo_dev_edge zephyr/samples/sensor/cxd5605_hot -DBOARD_ROOT=tmo-zephyr-sdk/

This sample is a standalone application.  You build it using the above 
command and flash it.  The GNSS chip firmware verification test will start.
You should see the output below.  If there are errors they will be printed out.

Sample Output
=============

GNSS Firmware verification test v0.1
Reading NMEA sentences
20047,2f945cd,136E
[VER] Done
[GSOP] Done
[BSSL] Done
[GCD] Done
[WUP] Done
$GPGGA,000001.00,,,,,0,00,,,,,,,*49
$GPGLL,,,,,000001.00,V,N*4B
$GPGSA,A,1,,,,,,,,,,,,,,,,*32
$GPGNS,000001.00,,,,,NN,00,,,,,,,,V*18
$GPRMC,000001.00,V,,,,,,,060180,,,N,V*09
$GPVTG,,T,,M,,N,,K,N*2C
$GPZDA,000001.00,06,01,1980,,*60


Title: TMO Shell

Description:

A sample of net interface connections for TCP/UDP with Modem and Wifi

--------------------------------------------------------------------------------

Requirements
************

- Modem card and RS9116W and WiFi plus wiseconnect-wifi-bt-sdk. The sample has been tested with Murata-1sc modem card with rs9116w, Wifi.
  The sample has been tested with pets-v2-dev platform


Building and Running Project:

This project can be built:

    west build -b pets_v2_dev_kit samples/hello_world/ -- -DBOARD_ROOT=/home/al/zephyrproject/zephyr-tmo-sdk

Sample of operation commands:

uart:~$ tmo ifaces 
1: murata,1sc
2: RS9116W_0

uart:~$ tmo udp create 1
z_fdtable_call_ioctl, request= 261
Created socket 1
sock conn GOOD!

uart:~$ tmo tcp connect 0 50.47.117.63 30000
sock conn GOOD!


uart:~$ tmo sockets 
Open sockets: 
0: iface=0x200005e4 proto=TCP CONNECTED,
1: iface=0x200005e4 proto=UDP CONNECTED, 

uart:~$ tmo tcp sendb 0 150
modem_cmd_send returned 0

uart:~$ tmo tcp recvb 0 1500
recv'ed 150



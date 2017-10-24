#!/bin/bash

service networking stop
sleep 2
echo 0 > /sys/devices/platform/soc/3f980000.usb/buspower
sleep 3
echo 1 > /sys/devices/platform/soc/3f980000.usb/buspower
sleep 2
service networking start

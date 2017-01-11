#!/bin/bash

:<<!
******NOTICE******
MUST set SDK_PATH & BIN_PATH firstly!!!
example:
export SDK_PATH=~/esp_iot_sdk_freertos
export BIN_PATH=~/esp8266_bin
!

echo "gen_misc.sh version 20150911"
echo ""

if [ $SDK_PATH ]; then
    echo "SDK_PATH:"
    echo "$SDK_PATH"
    echo ""
else
    echo "ERROR: Please export SDK_PATH in gen_misc.sh firstly, exit!!!"
    exit
fi

if [ $BIN_PATH ]; then
    echo "BIN_PATH:"
    echo "$BIN_PATH"
    echo ""
else
    echo "ERROR: Please export BIN_PATH in gen_misc.sh firstly, exit!!!"
    exit
fi

echo ""

echo "Please follow below steps(1-5) to generate specific bin(s):"
echo "STEP 1: use boot_v1.2+ by default"
boot=new

echo "boot mode: $boot"

echo ""

echo "start..."
echo ""

make clean


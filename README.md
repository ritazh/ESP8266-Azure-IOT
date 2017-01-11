# ESP8266_RTOS_SDK_with_Azure_IOT_C_SDK


The [ESP8266](https://en.wikipedia.org/wiki/ESP8266) is a low-cost Wi-Fi chip with full TCP/IP stack and MCU (Micro Controller Unit) capability produced by Espressif Systems. The [ESP8266 RTOS SDK](https://github.com/espressif/ESP8266_RTOS_SDK) is based on FreeRTOS. This repo integrates ESP8266 RTOS SDK with the Azure IoT C SDK to stream data to from ESP8266 to Azure IoT using MQTT protocol.

## Installation / Dependencies

Get Build Environment
- Follow this [guide](https://espressif.com/en/support/explore/get-started/esp8266/getting-started-guide)
- Under section 3.3. ESP8266 Toolkit, download VirtualBox and the lubuntu image.
- Make sure to share a local folder with the VM

Get esptool.py on your host machine:
- Follow this [guide](https://github.com/espressif/esptool)

Clone this repo within the shared folder on your host:
	git clone https://github.com/ritazh/ESP8266-Azure-IOT

## Update Variables

Update the following files within this solution:

/examples/project_template/user/user_main.c
Update these values with your own wifi ssid and password for ESP8266 to connect to

```
uint8 ssid[] =
uint8 password[] =
```

/examples/project_template/user/gen_misc4.sh
Update these variables to the path of the shared folder on the VM

```
export SDK_PATH=~/esp_iot_sdk_freertos
export BIN_PATH=~/esp8266_bin
```
   
## Compile

Now you are ready to compile
From the VM, run the following command from a terminal:
`./gen_misc4.sh`


Once compliation is completed successfully, you should see something that looks like the following:

```
bin crc: 1a38d19
Support boot_v1.4 and +
Generate user1.4096.new.6.bin successully in BIN_PATH
boot.bin------------>0x00000
user1.4096.new.6.bin--->0x01000
!!!
```
## Flash

Now you are ready to flash the binaries to your ESP8266. From your host machine, cd into `/bin`. Run the following command on the host to flash the binaries to ESP8266 using:

```
esptool.py --port /dev/cu.SLAB_USBtoUART  write_flash --flash_freq 40m --flash_mode qio --flash_size 32m-c1 0x1000 ./upgrade/user1.4096.new.6.bin 0x0 ./boot_v1.5.bin 0x3FC000 ./esp_init_data_default.bin 0x3FE000 ./blank.bin
```

/*
 * ESPRSSIF MIT License
 *
 * Copyright (c) 2015 <ESPRESSIF SYSTEMS (SHANGHAI) PTE LTD>
 *
 * Permission is hereby granted for use on ESPRESSIF SYSTEMS ESP8266 only, in which case,
 * it is free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "esp_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "lwip/opt.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "openssl/ssl_compat-1.0.h"
#include "iothub_client_sample_mqtt.h"
#include "lwip/apps/sntp.h"
#include "lwip/apps/sntp_time.h"

#define OPENSSL_DEMO_THREAD_NAME "ssl_demo"
#define OPENSSL_DEMO_THREAD_STACK_WORDS 1024*2
#define OPENSSL_DEMO_THREAD_PRORIOTY 6

#define OPENSSL_DEMO_FRAGMENT_SIZE 5120

#define OPENSSL_DEMO_LOCAL_TCP_PORT 1000

#define LogError printf

static os_timer_t timer;

LOCAL void ICACHE_FLASH_ATTR mqtt_sample()
{
    iothub_client_sample_mqtt_run();
    vTaskDelete(NULL);
}

LOCAL void ICACHE_FLASH_ATTR wait_for_connection_ready(uint8 flag)
{
    unsigned char ret = 0;
    struct ip_info ipconfig;
    xTaskHandle openssl_handle;
    os_timer_disarm(&timer);
    ret = wifi_station_get_connect_status();

    os_printf("ret %d\n", ret);

    if(ret == STATION_GOT_IP){
    	printf("azure iot program starts %d\n", system_get_free_heap_size());
        xTaskCreate(mqtt_sample,
                      OPENSSL_DEMO_THREAD_NAME,
                      OPENSSL_DEMO_THREAD_STACK_WORDS,
                      NULL,
                      OPENSSL_DEMO_THREAD_PRORIOTY,
                      &openssl_handle);

    }else{
    	os_timer_disarm(&timer);
    	os_timer_setfn(&timer, (os_timer_func_t *)wait_for_connection_ready, NULL);
    	os_timer_arm(&timer, 2000, 0);            
	}
}

LOCAL void ICACHE_FLASH_ATTR configWiFi()
{
    uint8 ssid[] = {'s','s','i','d'};
    uint8 password[] = {'p','a','s','s','w','o','r','d'}; 

    struct station_config sta_conf;
    wifi_set_opmode(STATION_MODE);
    memset(sta_conf.ssid, 0, 32);
    memset(sta_conf.password, 0, 64);
    memset(sta_conf.bssid, 0, 6);
    memcpy(sta_conf.ssid, ssid, sizeof(ssid));
    memcpy(sta_conf.password, password, sizeof(password));
    sta_conf.bssid_set = 0;
    wifi_station_set_config(&sta_conf);

    os_timer_disarm(&timer);
    os_timer_setfn(&timer, (os_timer_func_t *)wait_for_connection_ready, NULL);
    os_timer_arm(&timer, 2000, 0);
}

/******************************************************************************
 * FunctionName : user_init
 * Description  : entry of user application, init user function here
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
void user_init(void)
{
	//mac host doesn't like 74880.  uart_init doesn't work, use uart_div_modify
	uart_div_modify(0, UART_CLK_FREQ / 115200);
    printf("SDK version:%s\n", system_get_sdk_version());
    //set system time
    //set_time();
    //lwip_connection_test();
    configWiFi();
    //iothub_client_sample_amqp_run();
}

int _gettimeofday_r(struct _reent r, struct timeval tv, void *tz) {
return 0;
}

int _getpid_r()
{
	return 0;
}

void _kill_r()
{
}


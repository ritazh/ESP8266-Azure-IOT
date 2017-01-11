#ifndef _SSL_OPT_H_
#define _SSL_OPT_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* mbedtls include */
#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include "esp_common.h"

static void *os_zalloc(int size){

	void *p = malloc(size);
	memset(p, 0, size);
	return p;
}
#define ssl_print os_printf
#define ssl_mem_zalloc os_zalloc
#define ssl_mem_malloc malloc
#define ssl_mem_free free

#define ssl_memcpy memcpy

#define SSL_MUTEX_DEF(x) int x
#define SSL_MUTEX_INIT(x)

#define SSL_NULL NULL

#define SSL_SPEED_UP() 
#define SSL_SPEED_DOWN() 

#endif

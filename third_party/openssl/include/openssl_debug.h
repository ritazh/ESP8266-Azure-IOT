#ifndef _SSL_DEBUG_H_
#define _SSL_DEBUG_H_

#include "openssl_def.h"

#define OPENSSL_DEBUG_ENBALE 0
#define OPENSSL_DEBUG_LEVEL 0

#if OPENSSL_DEBUG_ENBALE
    #define OPENSSL_PRINT printf
#else
    #define OPENSSL_PRINT(...)
#endif

#define OPENSSL_ERR(err, go, ...) { OPENSSL_PRINT(__VA_ARGS__); ret = err; goto go; }
#define OPENSSL_RET(go, ...) { OPENSSL_PRINT(__VA_ARGS__); goto go; }

#define OPENSSL_DEBUG(level, ...) { if (level > OPENSSL_DEBUG_ENBALE) OPENSSL_PRINT(__VA_ARGS__); }

#endif

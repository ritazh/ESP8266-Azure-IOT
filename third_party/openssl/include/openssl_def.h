#ifndef _OPENSSL_DEF_H_
#define _OPENSSL_DEF_H_

#include "openssl_opt.h"\

/*
{
*/
#define SSL_MAX_FRAG_LEN_NONE               0
#define SSL_MAX_FRAG_LEN_512                512
#define SSL_MAX_FRAG_LEN_1024               1024
#define SSL_MAX_FRAG_LEN_2048               2048
#define SSL_MAX_FRAG_LEN_4096               4096
#define SSL_MAX_FRAG_LEN_8192               8192

#define SSL_MIN_FRAG_LEN                    SSL_MAX_FRAG_LEN_2048
#define SSL_MAX_FRAG_LEN                    SSL_MAX_FRAG_LEN_8192
#define SSL_DEFAULT_FRAG_LEN                SSL_MAX_FRAG_LEN_2048

#define SSL_DISPLAY_CERTS                   (1 << 0)
#define SSL_NO_DEFAULT_KEY                  (1 << 1)

#define SSL_SERVER_VERIFY_LATER             (1 << 2)
#define SSL_CLIENT_AUTHENTICATION           (1 << 3)


#define SSL_SEND_DATA_MAX_LENGTH            1460 //one MSS length

#define OPENSSL_CRT_MAX_LENGTH              4096

enum ssl_obj {
    SSL_OBJ_X509_CACERT = 0,
    SSL_OBJ_X509_CERT,
    SSL_OBJ_RSA_KEY,

    SSL_OBJ_MAX
};

enum ssl_endpoint {
    SSL_ENDPOINT_CLIENT = 0,
    SSL_ENDPOINT_SERVER,
};

/*
}
*/

#endif

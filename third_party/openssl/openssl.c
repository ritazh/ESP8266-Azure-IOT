/******************************************************************************
 * Copyright 2016-2017 Espressif Systems (Wuxi)
 *
 * FileName: ssc_mbedtls.c
 *
 * Description: SSC mbedtls command
 *
 * Modification history:
 *     2016/6/27,    create.    dongheng
 *******************************************************************************/
#include "openssl.h"
#include "openssl_debug.h"

#define MBED_SSL_SET_ERRNO(ssl, error) \
{ \
    ssl->err = (error); \
    ret = -1; \
}

/*******************************************************************************/
/*******************************************************************************/

unsigned int max_content_len;

/*******************************************************************************/
/*******************************************************************************/

/*
 * SSL_libary_init - initialize the SSL supporting library
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, you may see the mbedtls error code
 */
int SSL_libary_init(void)
{
    return 0;
}

/*
 * SSL_new - create a SSL
 *
 * @param ssl_ctx - the SSL context which includes the SSL parameter
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, you may see the mbedtls error code
 */
struct mbed_ssl* SSL_new(struct ssl_ctx *ssl_ctx)
{
    int ret;
    struct mbed_ssl *mbed_ssl;
    struct ssl_fd *ssl_fd;

    int endpoint;
    const char *pers;

    struct ssl_method *method;

    if (!ssl_ctx)
        OPENSSL_RET(failed1, "ssl_ctx:NULL\n");

    mbed_ssl = (struct mbed_ssl *)ssl_mem_zalloc(sizeof(struct mbed_ssl));
    if (!mbed_ssl)
        OPENSSL_RET(failed1, "ssl_self_alloc:[1]\n");

    ssl_fd = (struct ssl_fd *)ssl_mem_zalloc(sizeof(struct ssl_fd));
    if (!ssl_fd)
        OPENSSL_RET(failed2, "ssl_self_alloc:[2]\n");

    mbedtls_net_init(&ssl_fd->fd);
    mbedtls_net_init(&ssl_fd->cl_fd);

    mbedtls_ssl_config_init(&ssl_fd->conf);
    mbedtls_ctr_drbg_init(&ssl_fd->ctr_drbg);
    mbedtls_entropy_init(&ssl_fd->entropy);
    mbedtls_ssl_init(&ssl_fd->ssl);

    method = ssl_ctx->method;
    if (method->endpoint == SSL_ENDPOINT_SERVER) {
        pers = "server";
        endpoint = MBEDTLS_SSL_IS_SERVER;
    } else {
        pers = "client";
        endpoint = MBEDTLS_SSL_IS_CLIENT;
    }

    ret = mbedtls_ctr_drbg_seed(&ssl_fd->ctr_drbg, mbedtls_entropy_func, &ssl_fd->entropy, (const unsigned char *)pers, strlen(pers));
    if (ret)
        OPENSSL_ERR(ret, failed3, "mbedtls_ctr_drbg_seed:[%d]\n", ret);

    ret = mbedtls_ssl_config_defaults(&ssl_fd->conf, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret)
        OPENSSL_ERR(ret, failed4, "mbedtls_ssl_config_defaults:[%d]\n", ret);

    mbedtls_ssl_conf_rng(&ssl_fd->conf, mbedtls_ctr_drbg_random, &ssl_fd->ctr_drbg);
    mbedtls_ssl_conf_dbg(&ssl_fd->conf, NULL, NULL);

    if (SSL_CTX_VERIFY(ssl_ctx)) {
        struct ssl_ctx_verify *ctx_verify = &ssl_ctx->verify;

        if (SSL_CTX_USE_CA(ssl_ctx)) {
            mbedtls_ssl_conf_ca_chain(&ssl_fd->conf, ctx_verify->ca_crt, NULL);
            mbedtls_ssl_conf_authmode(&ssl_fd->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        }

        if (SSL_CTX_USE_PK(ssl_ctx)) {
            ret = mbedtls_ssl_conf_own_cert(&ssl_fd->conf, ctx_verify->own_crt, ctx_verify->pk);
            if (ret)
                OPENSSL_ERR(ret, failed5, "mbedtls_ssl_conf_own_cert:[%d]\n", ret);
        }
    } else {
        mbedtls_ssl_conf_authmode(&ssl_fd->conf, MBEDTLS_SSL_VERIFY_NONE);
    }

    ret = mbedtls_ssl_setup(&ssl_fd->ssl, &ssl_fd->conf);
    if (ret)
        OPENSSL_ERR(ret, failed5, "mbedtls_ssl_setup:[-0x%02x]\n", -ret);
    mbedtls_ssl_set_bio(&ssl_fd->ssl, &ssl_fd->fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbed_ssl->ssl_ctx = ssl_ctx;
    mbed_ssl->ssl_fd = ssl_fd;

    return mbed_ssl;

failed5:
    mbedtls_ssl_config_free(&ssl_fd->conf);
failed4:
    mbedtls_ctr_drbg_free(&ssl_fd->ctr_drbg);
failed3:
    mbedtls_entropy_free(&ssl_fd->entropy);
    ssl_mem_free(ssl_fd);
failed2:
    ssl_mem_free(mbed_ssl);
failed1:
    return NULL;
}

/*
 * SSL_set_fd - set the socket file description to the SSL
 *
 * @param mbed_ssl - the SSL point which has been "SSL_new"
 * @param fd  - socket file description
 *
 * @return the result
 *     result = 1  : successfully
 *     result <= 0 : error, SSL is NULL or socket file description is NULL
 */
int SSL_set_fd(struct mbed_ssl *mbed_ssl, int fd)
{
    int ret;

    if (!mbed_ssl || fd < 0) OPENSSL_ERR(0, go_failed1, "SSL_set_fd\n");

    mbed_ssl->ssl_fd->fd.fd = fd;

    return 1;

go_failed1:
    return ret;
}

/*
 * SSL_set_rfd - set the read only socket file description to the SSL
 *
 * @param mbed_ssl - the SSL point which has been "SSL_new"
 * @param fd  - socket file description
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, SSL is NULL or socket file description is NULL
 */
int SSL_set_rfd(struct mbed_ssl *mbed_ssl, int fd)
{
    return SSL_set_fd(mbed_ssl, fd);
}

/*
 * SSL_set_wfd - set the write only socket file description to the SSL
 *
 * @param mbed_ssl - the SSL point which has been "SSL_new"
 * @param fd  - socket file description
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, SSL is NULL or socket file description is NULL
 */
int SSL_set_wfd(struct mbed_ssl *mbed_ssl, int fd)
{
    return SSL_set_fd(mbed_ssl, fd);
}

/*
 * SSL_shutdown - shutdown the connection to the remote
 *
 * @param mbed_ssl - the SSL point which has been connected or accepted
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, you may see the mbedtls error code
 */
int SSL_shutdown(struct mbed_ssl *mbed_ssl)
{
    int ret;
    struct ssl_fd *ssl_fd;

    if (!mbed_ssl) OPENSSL_ERR(-1, go_failed1, "ssl_shutdown\n");

    ssl_fd = mbed_ssl->ssl_fd;
    if (ssl_fd->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) return 0;

    mbedtls_ssl_close_notify(&ssl_fd->ssl);

    return 0;

go_failed1:
    return ret;
}

/*
 * SSL_free - free the SSL
 *
 * @param mbed_ssl - the SSL point which has been "SSL_new"
 *
 * @return none
 */
void SSL_free(struct mbed_ssl *mbed_ssl)
{
    int ret;
    struct ssl_fd *ssl_fd;

    if (!mbed_ssl) return ;

    ssl_fd = mbed_ssl->ssl_fd;
    mbedtls_entropy_free(&ssl_fd->entropy);
    mbedtls_ctr_drbg_free(&ssl_fd->ctr_drbg);
    mbedtls_ssl_config_free(&ssl_fd->conf);
    mbedtls_ssl_free(&ssl_fd->ssl);
    ssl_mem_free(ssl_fd);

    ssl_mem_free(mbed_ssl);
}

/*
 * SSL_connect - connect to the remote SSL server
 *
 * @param mbed_ssl - the SSL point which has been "SSL_new"
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_connect(struct mbed_ssl *mbed_ssl)
{
    int ret;
    struct ssl_fd *ssl_fd;

    if (!mbed_ssl) OPENSSL_ERR(-1, go_failed1, "ssl_connect\n");

    SSL_SPEED_UP();
    ssl_fd = mbed_ssl->ssl_fd;
    while((ret = mbedtls_ssl_handshake(&ssl_fd->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            OPENSSL_ERR(ret, go_failed2, "mbedtls_ssl_handshake:[-0x%x]\n", -ret);
        }
    }
    SSL_SPEED_DOWN();

    return 0;

go_failed2:
go_failed1:
    return ret;
}

/*
 * SSL_accept - accept the remote connection
 *
 * @param mbed_ssl - the SSL point which has been "SSL_new"
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_accept(struct mbed_ssl *mbed_ssl)
{
    int ret;
    struct ssl_fd *ssl_fd;

    if (!mbed_ssl) OPENSSL_ERR(-1, go_failed1, "ssl_connect\n");

    SSL_SPEED_UP();
    ssl_fd = mbed_ssl->ssl_fd;
    while((ret = mbedtls_ssl_handshake(&ssl_fd->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            OPENSSL_ERR(ret, go_failed2, "mbedtls_ssl_handshake:[-0x%x]\n", -ret);
        }
    }
    SSL_SPEED_DOWN();

    return 0;

go_failed2:
go_failed1:
    return ret;
}

/*
 * SSL_read - read data from remote
 *
 * @param mbed_ssl - the SSL point which has been connected
 * @param buffer - the received data point
 * @param len - the received data length
 *
 * @return the result
 *     result > 0 : the length of the received data
 *     result = 0 : the connect is closed
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_read(struct mbed_ssl *mbed_ssl, void *buffer, int len)
{
    int ret;
    struct ssl_fd *ssl_fd;

    if (!mbed_ssl || !buffer || !len) OPENSSL_ERR(-1, go_failed1, "ssl_read\n");

    ssl_fd = mbed_ssl->ssl_fd;
    ret = mbedtls_ssl_read(&ssl_fd->ssl, buffer, len);
    if (ret < 0) OPENSSL_ERR(ret, go_failed2, "mbedtls_ssl_read\n");

    return ret;

go_failed2:
    MBED_SSL_SET_ERRNO(mbed_ssl, ret);
go_failed1:
    return ret;
}

/*
 * SSL_write - send the data to remote
 *
 * @param mbed_ssl - the SSL point which has been connected
 * @param buffer - the send data point
 * @param len - the send data length
 *
 * @return the result
 *     result > 0 : the length of the written data
 *     result = 0 : the connect is closed
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_write(struct mbed_ssl *mbed_ssl, const void *buffer, int len)
{
    int ret;
    int send_bytes;
    const unsigned char *pbuf;
    struct ssl_fd *ssl_fd;

    if (!mbed_ssl || !buffer || !len) return -1;

    ssl_fd = mbed_ssl->ssl_fd;
    send_bytes = len;
    pbuf = (const unsigned char *)buffer;

    do {
        int bytes;

        if (send_bytes > SSL_SEND_DATA_MAX_LENGTH)
            bytes = SSL_SEND_DATA_MAX_LENGTH;
        else
            bytes = send_bytes;

        ret = mbedtls_ssl_write(&ssl_fd->ssl, pbuf, bytes);
        if (ret > 0) {
            pbuf += ret;
            send_bytes -= ret;
        }
    } while (ret > 0 && send_bytes);

    if (ret < 0)
        MBED_SSL_SET_ERRNO(mbed_ssl, ret);

    return ret;
}

/*
 * SSL_get_verify_result - get the verifying result of the SSL certification
 *
 * @param mbed_ssl - the SSL point
 *
 * @return the result of verifying
 *     result = 0 : successful
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_get_verify_result(struct mbed_ssl *mbed_ssl)
{
    return 0;
}

/*
 * SSL_pending - get the SSL message bytes in the receive buffer
 *
 * @param mbed_ssl - the SSL point
 *
 * @return the result of verifying
 *     result >= 0 : the message bytes
 *     result < 0  : error, you can see the mbedtls error code
 */
int SSL_pending(const struct mbed_ssl *mbed_ssl)
{
    int ret;
    struct ssl_fd *ssl_fd;

    if (!mbed_ssl) OPENSSL_ERR(-1, go_failed1, "SSL_pending\n");

    ssl_fd = mbed_ssl->ssl_fd;
    ret = mbedtls_ssl_get_bytes_avail(&ssl_fd->ssl);

    return ret;

go_failed1:
    return ret;
}

/*
 * SSL_get_verify_depth - get the certification verify depth
 *
 * @param mbed_ssl - the SSL point
 *
 * @return the result of verifying
 *     result > 0 : the message bytes
 *     result = 0 : not set depth
 *     result < 0  : error, you can see the mbedtls error code
 */
int SSL_get_verify_depth(const struct mbed_ssl *mbed_ssl)
{
    int ret;
    struct ssl_fd *ssl_fd;

    if (!mbed_ssl) OPENSSL_ERR(-1, go_failed1, "SSL_get_verify_depth\n");

    return 0;

go_failed1:
    return ret;
}

/*
 * SSL_get_verify_depth - set the certification verify depth
 *
 * @param mbed_ssl - the SSL point
 * @param depth    - certification verify depth
 *
 * @return none
 */
void SSL_set_verify_depth(struct mbed_ssl *mbed_ssl, int depth)
{
    int ret;
    struct ssl_fd *ssl_fd;

    if (!mbed_ssl) OPENSSL_ERR(-1, go_failed1, "SSL_set_verify_depth\n");

    return ;

go_failed1:
    return ;
}

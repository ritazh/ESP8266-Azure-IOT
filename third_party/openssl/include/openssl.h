#ifndef _OPENSSL_H_
#define _OPENSSL_H_

#include "openssl_ctx.h"

/*******************************************************************************/
struct ssl_fd
{
    /* local socket file description */
    mbedtls_net_context fd;
    /* remote client socket file description */
    mbedtls_net_context cl_fd;

    mbedtls_ssl_config conf;

    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ssl_context ssl;

    mbedtls_entropy_context entropy;
};

struct mbed_ssl
{
    struct ssl_fd   *ssl_fd;

    struct ssl_ctx  *ssl_ctx;

    int err;

    SSL_MUTEX_DEF(mutex);
};

/*
 * SSL_libary_init - initialize the SSL supporting library
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, you may see the mbedtls error code
 */
int SSL_libary_init(void);

/*
 * SSL_new - create a SSL
 *
 * @param ssl_ctx - the SSL context which includes the SSL parameter
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, you may see the mbedtls error code
 */
struct mbed_ssl* SSL_new(struct ssl_ctx *ssl_ctx);

/*
 * SSL_connect - connect to the remote SSL server
 *
 * @param ssl - the SSL point which has been "SSL_new"
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_connect(struct mbed_ssl *mbed_ssl);

/*
 * SSL_get_verify_result - get the verifying result of the SSL certification
 *
 * @param ssl - the SSL point
 *
 * @return the result of verifying
 *     result = 0 : successful
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_get_verify_result(struct mbed_ssl *mbed_ssl);

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
int SSL_set_fd(struct mbed_ssl *mbed_ssl, int fd);

/*
 * SSL_set_rfd - set the read only socket file description to the SSL
 *
 * @param mbed_ssl - the SSL point which has been "SSL_new"
 * @param fd  - socket file description
 *
 * @return the result
 *     result = 1  : successfully
 *     result <= 0 : error, SSL is NULL or socket file description is NULL
 */
int SSL_set_rfd(struct mbed_ssl *mbed_ssl, int fd);

/*
 * SSL_set_wfd - set the write only socket file description to the SSL
 *
 * @param mbed_ssl - the SSL point which has been "SSL_new"
 * @param fd  - socket file description
 *
 * @return the result
 *     result = 1  : successfully
 *     result <= 0 : error, SSL is NULL or socket file description is NULL
 */
int SSL_set_wfd(struct mbed_ssl *mbed_ssl, int fd);

/*
 * SSL_free - free the SSL
 *
 * @param mbed_ssl - the SSL point which has been "SSL_new"
 *
 * @return none
 */
void SSL_free(struct mbed_ssl *mbed_ssl);

/*
 * SSL_accept - accept the remote connection
 *
 * @param ssl - the SSL point which has been "SSL_new"
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_accept(struct mbed_ssl *mbed_ssl);

/*
 * SSL_read - read data from remote
 *
 * @param ssl - the SSL point which has been connected
 * @param buffer - the received data point
 * @param len - the received data length
 *
 * @return the result
 *     result > 0 : the length of the received data
 *     result = 0 : the connect is closed
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_read(struct mbed_ssl *mbed_ssl, void *buffer, int len);

/*
 * SSL_write - send the data to remote
 *
 * @param ssl - the SSL point which has been connected
 * @param buffer - the send data point
 * @param len - the send data length
 *
 * @return the result of verifying
 *     result > 0 : the length of the written data
 *     result = 0 : the connect is closed
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_write(struct mbed_ssl *mbed_ssl, const void *buffer, int len);

/*
 * SSL_shutdown - shutdown the connection to the remote
 *
 * @param ssl - the SSL point which has been connected or accepted
 *
 * @return the result
 *     result = 0 : shutdown successfully
 *     result < 0 : error, you may see the mbedtls error code
 */
int SSL_shutdown(struct mbed_ssl *mbed_ssl);

/*
 * SSL_pending - get the SSL message bytes in the receive buffer
 *
 * @param mbed_ssl - the SSL point
 *
 * @return the result of verifying
 *     result >= 0 : the message bytes
 *     result < 0  : error, you can see the mbedtls error code
 */
int SSL_pending(const struct mbed_ssl *mbed_ssl);

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
int SSL_get_verify_depth(const struct mbed_ssl *mbed_ssl);

/*
 * SSL_get_verify_depth - set the certification verify depth
 *
 * @param mbed_ssl - the SSL point
 * @param depth    - certification verify depth
 *
 * @return none
 */
void SSL_set_verify_depth(struct mbed_ssl *mbed_ssl, int depth);

#endif

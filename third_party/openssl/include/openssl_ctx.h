#ifndef __SSL_CTX_H__
#define __SSL_CTX_H__

#include "openssl_def.h"

#define SSL_CTX_VERIFY(ctx) \
    (ctx->verify.own_crt || \
     ctx->verify.ca_crt || \
     ctx->verify.pk)

#define SSL_CTX_USE_CA(ctx) (ctx->verify.ca_crt)

#define SSL_CTX_USE_PK(ctx) (ctx->verify.own_crt && ctx->verify.pk)

struct ssl_method {
	int endpoint;
};

struct ssl_ctx_verify
{
    mbedtls_x509_crt *own_crt;

    mbedtls_x509_crt *ca_crt;

    mbedtls_pk_context *pk;
};

struct ssl_ctx
{
	unsigned char opt;

	/************************************/

	struct ssl_ctx_verify verify;

	struct ssl_method *method;
};

/*
 * SSL_CTX_new - create a SSL context
 *
 * @param method - the SSL context configuration file
 *
 * @return the context point, if create failed return NULL
 */
struct ssl_ctx* SSL_CTX_new(struct ssl_method *method);

/*
 * SSL_CTX_free - free a SSL context
 *
 * @param method - the SSL context point
 *
 * @return none
 */
void SSL_CTX_free(struct ssl_ctx *ctx);

/*
 * SSL_CTX_set_option - set the option of the SSL context
 *
 * @param ctx - the SSL context
 *
 * @return the result of verifying
 *     result = 0 : successful
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_CTX_set_option(struct ssl_ctx *ctx, int opt);

/*
 * SSL_set_fragment - set the global SSL fragment size
 *
 * @param ssl_ctx - the SSL context point
 * @param frag - fragment size
 *
 * @return the result of verifying
 *     result = 0 : successful
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_set_fragment(struct ssl_ctx *ctx, unsigned int frag);

/*
 * SSL_CTX_use_PrivateKey - set the private key
 *
 * @param ctx  - the SSL context
 * @param buf  - the data point
 * @param len  - the data length
 * @param type - the data type
 *     attribute is always 0;
 *
 * @return the result of verifying
 *     result = 0 : successful
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_CTX_use_PrivateKey(struct ssl_ctx *ctx, const char *buf, int len, int type);

/*
 * SSL_CTX_use_certificate - set the client own key
 *
 * @param ctx  - the SSL context
 * @param buf  - the data point
 * @param len  - the data length
 * @param type - the data type
 *     attribute is always 0;
 *
 * @return the result of verifying
 *     result = 0 : successful
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_CTX_use_certificate(struct ssl_ctx *ctx, const char *buf, int len, int type);

/*
 * SSL_CTX_use_verify_certificate - set the CA certificate
 *
 * @param ctx  - the SSL context
 * @param buf  - the data point
 * @param len  - the data length
 * @param type - the data type
 *     attribute is always 0;
 *
 * @return the result of verifying
 *     result = 0 : successful
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_CTX_use_verify_certificate(struct ssl_ctx *ctx, const char *buf, int len, int type);

/*
 * SSLv23_client_method - create the target SSL context client method
 *
 * @return the SSLV2.3 version SSL context client method
 */
struct ssl_method* SSLv23_client_method(void);

/*
 * TLSv1_client_method - create the target SSL context client method
 *
 * @return the TLSV1.0 version SSL context client method
 */
struct ssl_method* TLSv1_client_method(void);

/*
 * SSLv3_client_method - create the target SSL context client method
 *
 * @return the SSLV3.0 version SSL context client method
 */
struct ssl_method* SSLv3_client_method(void);

/*
 * TLSv1_1_client_method - create the target SSL context client method
 *
 * @return the TLSV1.1 version SSL context client method
 */
struct ssl_method* TLSv1_1_client_method(void);

/*
 * TLSv1_2_client_method- create the target SSL context client method
 *
 * @return the TLSV1.2 version SSL context client method
 */
struct ssl_method* TLSv1_2_client_method(void);

/*
 * SSLv23_server_method - create the target SSL context server method
 *
 * @return the SSLV2.3 version SSL context server method
 */
struct ssl_method* SSLv23_server_method(void);

/*
 * TLSv1_1_server_method - create the target SSL context server method
 *
 * @return the TLSV1.1 version SSL context server method
 */
struct ssl_method* TLSv1_1_server_method(void);

/*
 * TLSv1_2_server_method - create the target SSL context server method
 *
 * @return the TLSV1.2 version SSL context server method
 */
struct ssl_method* TLSv1_2_server_method(void);

/*
 * TLSv1_server_method - create the target SSL context server method
 *
 * @return the TLSV1.0 version SSL context server method
 */
struct ssl_method* TLSv1_server_method(void);

/*
 * SSLv3_server_method - create the target SSL context server method
 *
 * @return the SSLV3.0 version SSL context server method
 */
struct ssl_method* SSLv3_server_method(void);

#endif

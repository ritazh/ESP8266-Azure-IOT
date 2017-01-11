#include "openssl_ctx.h"
#include "openssl_debug.h"

extern unsigned int max_content_len;

/*******************************************************************************/
/*******************************************************************************/

/*
 * SSL_CTX_new - create a SSL context
 *
 * @param method - the SSL context configuration file
 *
 * @return the context point, if create failed return NULL
 */
struct ssl_ctx* SSL_CTX_new(struct ssl_method *method)
{
    int ret;
    struct ssl_ctx *ctx;
    struct ssl_ctx_verify *verify;

    if (!method) OPENSSL_ERR(-1, go_failed1, "ssl_ctx_new:method\n");

    ctx = (struct ssl_ctx *)ssl_mem_zalloc(sizeof(struct ssl_ctx));
    if (!ctx) OPENSSL_ERR(-2, go_failed2, "ssl_ctx_new:ctx\n");

    ctx->method = method;
    max_content_len = SSL_DEFAULT_FRAG_LEN;

    return ctx;

go_failed2:
go_failed1:
    return SSL_NULL;
}

/*
 * SSL_CTX_free - free a SSL context
 *
 * @param method - the SSL context point
 *
 * @return none
 */
void SSL_CTX_free(struct ssl_ctx *ctx)
{
    struct ssl_ctx_verify *verify;

    if (!ctx) return ;

    verify = &ctx->verify;

    if (verify->ca_crt) {
        mbedtls_x509_crt_free(verify->ca_crt);
        ssl_mem_free(verify->ca_crt);
    }

    if (verify->own_crt) {
        mbedtls_x509_crt_free(verify->own_crt);
        ssl_mem_free(verify->own_crt);
    }

    if (verify->pk) {
        mbedtls_pk_free(verify->pk);
        ssl_mem_free(verify->pk);
    }

    ssl_mem_free(ctx->method);
    ssl_mem_free(ctx);
}

/*
 * SSL_CTX_set_option - set the option of the SSL context
 *
 * @param ctx - the SSL context
 *
 * @return the result of verifying
 *     result = 0 : successful
 *     result < 0 : error, you can see the mbedtls error code
 */
int SSL_CTX_set_option(struct ssl_ctx *ctx, int opt)
{
    ctx->opt = opt;

    return 0;
}

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
int SSL_set_fragment(struct ssl_ctx *ctx, unsigned int frag)
{
    int ret;

    if (frag < SSL_MIN_FRAG_LEN || frag > SSL_MAX_FRAG_LEN)
        OPENSSL_ERR(-1, go_failed1, "ssl_fragment_length_negotiation\n");

    max_content_len = frag;

    return 0;

go_failed1:
    return ret;
}

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
int SSL_CTX_use_PrivateKey(struct ssl_ctx *ctx, const char *buf, int len, int type)
{
    int ret;
    struct ssl_ctx_verify *verify;
    char *pbuf;

    if (!ctx || !buf || !len || ctx->verify.pk) return -1;

    if (!(pbuf = ssl_mem_malloc(len + 1)))
        OPENSSL_ERR(-2, failed1, "SSL_CTX_use_PrivateKey:[PBUF]\n");
    ssl_memcpy(pbuf, buf, len);
    pbuf[len] = '\0';

    verify = &ctx->verify;
    if (!(verify->pk = ssl_mem_malloc(sizeof(mbedtls_x509_crt))))
        OPENSSL_ERR(-3, failed2, "SSL_CTX_use_PrivateKey:[PK]\n");
    mbedtls_pk_init(verify->pk);

    ret = mbedtls_pk_parse_key(verify->pk, pbuf, len, NULL, 0);
    if (ret)
        OPENSSL_ERR(ret, failed3, "mbedtls_pk_parse_key\n");

    ssl_mem_free(pbuf);

    return 0;

failed3:
    ssl_mem_free(verify->pk);
failed2:
    ssl_mem_free(pbuf);
failed1:
    return ret;
}

/*
 * SSL_CTX_use_certificate - set the client own certificate
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
int SSL_CTX_use_certificate(struct ssl_ctx *ctx, const char *buf, int len, int type)
{
    int ret;
    struct ssl_ctx_verify *verify;
    char *pbuf;

    if (!ctx || !buf || !len || ctx->verify.own_crt) return -1;

    if (!(pbuf = ssl_mem_malloc(len + 1)))
        OPENSSL_ERR(-2, failed1, "SSL_CTX_use_certificate:[PBUF]\n");
    ssl_memcpy(pbuf, buf, len);
    pbuf[len] = '\0';

    verify = &ctx->verify;
    if (!(verify->own_crt = ssl_mem_malloc(sizeof(mbedtls_x509_crt))))
        OPENSSL_ERR(-3, failed2, "SSL_CTX_use_certificate:[own_crt]\n");
    mbedtls_x509_crt_init(verify->own_crt);

    ret = mbedtls_x509_crt_parse(verify->own_crt, pbuf, len);
    if (ret)
        OPENSSL_ERR(ret, failed3, "mbedtls_x509_crt_parse\n");

    ssl_mem_free(pbuf);

    return 0;

failed3:
    ssl_mem_free(verify->own_crt);
failed2:
    ssl_mem_free(pbuf);
failed1:
    return ret;
}

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
int SSL_CTX_use_verify_certificate(struct ssl_ctx *ctx, const char *buf, int len, int type)
{
    int ret;
    struct ssl_ctx_verify *verify;
    char *pbuf;

    if (!ctx || !buf || !len || ctx->verify.ca_crt) return -1;

    if (!(pbuf = ssl_mem_malloc(len + 1)))
        OPENSSL_ERR(-2, failed1, "SSL_CTX_use_verify_certificate:[PBUF]\n");
    ssl_memcpy(pbuf, buf, len);
    pbuf[len] = '\0';

    verify = &ctx->verify;
    if (!(verify->ca_crt = ssl_mem_malloc(sizeof(mbedtls_x509_crt))))
        OPENSSL_ERR(-3, failed2, "SSL_CTX_use_verify_certificate:[ca_crt]\n");
    mbedtls_x509_crt_init(verify->ca_crt);

    ret = mbedtls_x509_crt_parse(verify->ca_crt, pbuf, len);
    if (ret)
        OPENSSL_ERR(ret, failed3, "mbedtls_x509_crt_parse\n");

    ssl_mem_free(pbuf);

    return 0;

failed3:
    ssl_mem_free(verify->ca_crt);
failed2:
    ssl_mem_free(pbuf);
failed1:
    return ret;
}

/*
 * TLSv1_client_method - create the target SSL context client method
 *
 * @return the SSLV2.3 version SSL context client method
 */
struct ssl_method* SSLv23_client_method(void)
{
    return 0;
}

/*
 * TLSv1_2_client_method- create the target SSL context client method
 *
 * @return the TLSV1.2 version SSL context client method
 */
struct ssl_method* TLSv1_2_client_method(void)
{
    struct ssl_method *method;

    method = (struct ssl_method *)ssl_mem_zalloc(sizeof(struct ssl_method));
    if (method) {
        method->endpoint = SSL_ENDPOINT_CLIENT;
    }
    return method;
}

/*
 * TLSv1_client_method - create the target SSL context client method
 *
 * @return the TLSV1.1 version SSL context client method
 */
struct ssl_method* TLSv1_1_client_method(void)
{
    struct ssl_method *method;

    method = (struct ssl_method *)ssl_mem_zalloc(sizeof(struct ssl_method));
    if (method) {
        method->endpoint = SSL_ENDPOINT_CLIENT;
    }
    return method;
}

/*
 * TLSv1_client_method - create the target SSL context client method
 *
 * @return the TLSV1.0 version SSL context client method
 */
struct ssl_method* TLSv1_client_method(void)
{
    struct ssl_method *method;

    method = (struct ssl_method *)ssl_mem_zalloc(sizeof(struct ssl_method));
    if (method) {
        method->endpoint = SSL_ENDPOINT_CLIENT;
    }
    return method;
}

/*
 * TLSv1_client_method - create the target SSL context client method
 *
 * @return the SSLV3.0 version SSL context client method
 */
struct ssl_method* SSLv3_client_method(void)
{
    return NULL;
}

/*
 * TLSv1_1_server_method - create the target SSL context server method
 *
 * @return the SSLV2.3 version SSL context server method
 */
struct ssl_method* SSLv23_server_method(void)
{
    return NULL;
}

/*
 * TLSv1_1_server_method - create the target SSL context server method
 *
 * @return the TLSV1.1 version SSL context server method
 */
struct ssl_method* TLSv1_1_server_method(void)
{
    struct ssl_method *method;

    method = (struct ssl_method *)ssl_mem_zalloc(sizeof(struct ssl_method));
    if (method) {
        method->endpoint = SSL_ENDPOINT_SERVER;
    }
    return method;
}

/*
 * TLSv1_2_server_method - create the target SSL context server method
 *
 * @return the TLSV1.2 version SSL context server method
 */
struct ssl_method* TLSv1_2_server_method(void)
{
    struct ssl_method *method;

    method = (struct ssl_method *)ssl_mem_zalloc(sizeof(struct ssl_method));
    if (method) {
        method->endpoint = SSL_ENDPOINT_SERVER;
    }
    return method;
}

/*
 * TLSv1_1_server_method - create the target SSL context server method
 *
 * @return the TLSV1.0 version SSL context server method
 */
struct ssl_method* TLSv1_server_method(void)
{
    struct ssl_method *method;

    method = (struct ssl_method *)ssl_mem_zalloc(sizeof(struct ssl_method));
    if (method) {
        method->endpoint = SSL_ENDPOINT_SERVER;
    }
    return method;
}

/*
 * TLSv1_1_server_method - create the target SSL context server method
 *
 * @return the SSLV3.0 version SSL context server method
 */
struct ssl_method* SSLv3_server_method(void)
{
    return NULL;
}


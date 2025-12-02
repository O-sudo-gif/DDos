# TCP ACK Flood Tool

A high-performance TCP ACK flood tool written in C, designed for network stress testing and research purposes. This tool generates spoofed TCP ACK packets with SACK (Selective Acknowledgment) blocks to test network infrastructure resilience.

## ⚠️ DISCLAIMER

**This tool is for educational and authorized testing purposes only.** Unauthorized use against systems you do not own or have explicit permission to test is illegal and may result in criminal prosecution. The authors and contributors are not responsible for any misuse of this software.

## Features

- **Raw Socket Implementation**: Uses raw sockets for direct packet crafting at the kernel level
- **IP Spoofing**: Generates spoofed source IPs from various network ranges
- **SACK Support**: Implements TCP Selective Acknowledgment (SACK) blocks for enhanced packet complexity
- **Multi-threading**: Supports up to 10,000 concurrent threads for maximum throughput
- **Rate Limiting**: Built-in token bucket rate limiter for controlled packet generation
- **SOCKS5 Proxy Support**: Optional proxy support for routing traffic through SOCKS5 proxies
- **Connection State Tracking**: Maintains connection state for realistic packet sequences
- **Real-time Statistics**: Live monitoring of packets per second (PPS), bandwidth, and connection stats
- **Optimized Performance**: Efficient memory management and socket pooling

## Requirements

- **Operating System**: Linux (tested on Ubuntu 20.04+, Debian 10+, CentOS 7+)
- **Privileges**: Root access required (for raw sockets)
- **Compiler**: GCC with C99 support
- **Libraries**: pthread (usually included with glibc)
- **Kernel**: Linux kernel 2.6+ (for raw socket support)

## Installation

### Clone the Repository

```bash
git clone https://github.com/o-sudo-gif/tcp-ack-flood.git
cd tcp-ack-flood
```

### Compile

```bash
make
```

Or manually:

```bash
gcc -o ack ack.c -lpthread -O3 -Wall
```

### Install (Optional)

```bash
sudo make install
```

This will copy the binary to `/usr/local/bin/ack`.

## Usage

### Basic Syntax

```bash
sudo ./ack <target_ip> <target_port> <threads> <duration> <max_pps> [--socks5]
```

### Parameters

| Parameter     | Description                         | Example           |
|---------------|-------------------------------------|-------------------|
| `target_ip`   | Target server IP address            | `192.168.1.100`   |
| `target_port` | Target TCP port                     | `80`, `443`, `22` |
| `threads`     | Number of worker threads (1-10000)  | `300`             |
| `duration`    | Attack duration in seconds          | `60`              |
| `max_pps`     | Maximum packets per second          | `100000`          |
| `--socks5`    | (Optional) Enable SOCKS5 proxy mode | `--socks5`        |

### Examples

#### Basic ACK Flood

```bash
sudo ./ack 192.168.1.100 80 300 60 100000
```

This command:
- Targets `192.168.1.100:80`
- Uses 300 threads
- Runs for 60 seconds
- Limits to 100,000 packets per second

#### With SOCKS5 Proxies

1. Create a `socks5.txt` file with proxy list:
```
proxy1.example.com:1080:username:password
proxy2.example.com:1080
192.168.1.50:1080:user:pass
```

2. Run with proxy support:
```bash
sudo ./ack 192.168.1.100 443 500 120 200000 --socks5
```

#### High-Intensity Attack

```bash
sudo ./ack 10.0.0.1 22 1000 300 500000
```

**Warning**: High thread counts (>500) and PPS rates (>200k) may cause system instability.

## Working Logic

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Main Process                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Thread Pool  │  │ Rate Limiter │  │ Stats Thread │   │
│  │ (1-10000)    │  │ (Token       │  │ (Monitoring) │   │
│  │              │  │  Bucket)     │  │              │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         │                  │                  │         │
│         └──────────────────┼──────────────────┘         │
│                            │                            │
└────────────────────────────┼────────────────────────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
         ┌──────▼──────┐          ┌───────▼──────┐
         │ Raw Socket  │          │ SOCKS5 Proxy │
         │  Mode       │          │   Mode       │
         │             │          │              │
         │ - IP Spoof  │          │ - Proxy      │
         │ - Direct    │          │   Rotation   │
         │   Packet    │          │ - HTTP/SSH   │
         │   Crafting  │          │   Payloads   │
         └─────────────┘          └──────────────┘
```

### Packet Generation Flow

1. **Initialization Phase**
   - Disables reverse path filtering (`rp_filter`)
   - Increases file descriptor limits
   - Initializes rate limiter (token bucket algorithm)
   - Loads SOCKS5 proxies (if enabled)
   - Creates worker thread pool

2. **Thread Execution**
   Each worker thread:
   - Creates up to 10,000 raw sockets
   - Generates spoofed source IPs
   - Maintains connection state tracking
   - Crafts TCP ACK packets with:
     - 60-byte TCP header (data offset = 15)
     - 40 bytes of TCP options (MSS, Window Scaling, Timestamp, SACK_PERM, SACK blocks)
     - 1420 bytes of payload (0xFF pattern)
   - Calculates IP and TCP checksums
   - Sends packets via `sendto()` with `MSG_DONTWAIT`

3. **Packet Structure**

```
┌─────────────────────────────────────────────────────────┐
│ IP Header (20 bytes)                                    │
│ - Version: 4                                            │
│ - IHL: 5                                                │
│ - TTL: 64/128/255                                       │
│ - Protocol: TCP (6)                                     │
│ - Source: Spoofed IP                                    │
│ - Destination: Target IP                                │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│ TCP Header (60 bytes)                                   │
│ - Source Port: Random (32768-65535)                     │
│ - Destination Port: Target Port                         │
│ - Flags: ACK=1, SYN=0, FIN=0, RST=0, PSH=0, URG=0       │
│ - Sequence Number: Calculated                           │
│ - Acknowledgment Number: Calculated                     │
│ - Window Size: 16384-65535                              │
│ - Data Offset: 15 (60 bytes)                            │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│ TCP Options (40 bytes)                                  │
│ - MSS (4 bytes): 1300-1460                              │
│ - Window Scaling (3 bytes): 7-14                        │
│ - Timestamp (10 bytes): Current time                    │
│ - SACK_PERM (2 bytes)                                   │
│ - SACK Blocks (10 bytes each, 1-3 blocks)               │
│ - NOP padding                                           │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│ Payload (1420 bytes)                                    │
│ - Pattern: 0xFF 0xFF 0xFF ... (all 0xFF)                │
└─────────────────────────────────────────────────────────┘
Total Packet Size: ~1500 bytes
```

4. **IP Spoofing Algorithm**

The tool generates spoofed IPs using a rotation algorithm:
- Uses thread ID, iteration count, and time as seed
- Distributes across 120 different IP class ranges
- Includes private ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- Includes various public IP ranges for diversity
- Rotates IPs per burst to avoid detection

5. **Connection State Tracking**

For each unique (source_ip, source_port) pair:
- Maintains sequence and acknowledgment numbers
- Tracks window size evolution
- Stores TTL value
- Updates packet count
- Uses hash table for O(1) lookup

6. **Rate Limiting**

Token bucket algorithm:
- Maximum tokens = `max_pps`
- Refill rate = `max_pps` per second
- Each packet consumes 1 token
- Threads sleep when tokens exhausted

7. **SOCKS5 Proxy Mode**

When `--socks5` flag is used:
- Loads proxies from `socks5.txt`
- Rotates through proxy list
- Establishes TCP connections through proxies
- Sends HTTP or SSH payloads (depending on target port)
- Tracks proxy failures and auto-rotates

### Key Algorithms

#### Checksum Calculation

```c
// IP Header Checksum
iph->check = 0;
iph->check = checksum_tcp_packet((unsigned short *) datagram, IP_HDR_LEN);

// TCP Checksum (with pseudo-header)
psh.source_address = spoofed_ip;
psh.dest_address = target_ip;
psh.tcp_length = TCP_TOTAL_LEN_WITH_PAYLOAD;
tcph->check = checksum_tcp_packet((unsigned short*) pseudogram_buffer, PSEUDO_SIZE_WITH_PAYLOAD);
```

#### Sequence Number Generation

```c
// Base sequence from time and thread ID
uint32_t base_seq = (time_base * 2500000) + (thread_id * 100000000) + random(10000000, 500000000);

// Increment per packet
seq_val = base_seq + (burst * 1460);
ack_val = base_ack + (burst * 2920);
```

#### SACK Block Generation

```c
// Generate 1-3 SACK blocks
uint32_t sle = ack_val + random(1460, 14600);  // Start Left Edge
uint32_t sre = sle + random(1460, 7300);       // Start Right Edge
```

## Technical Details

### Performance Characteristics

- **Throughput**: Up to 500,000+ PPS (depending on hardware)
- **Latency**: Sub-millisecond packet generation
- **Memory**: ~50MB per 1000 threads
- **CPU**: Multi-core utilization via pthreads

### Socket Configuration

- **Raw Sockets**: `PF_INET, SOCK_RAW, IPPROTO_TCP`
- **Buffer Sizes**: 1GB send/recv buffers
- **Non-blocking**: All sockets use `O_NONBLOCK`
- **IP_HDRINCL**: Enabled for manual IP header construction

### Thread Safety

- Atomic operations for counters (`__sync_add_and_fetch`)
- Mutex locks for rate limiter
- Thread-local storage for connection states
- Cleanup handlers for graceful shutdown

## Statistics Output

The tool provides real-time statistics:

```
[LIVE] PPS: 125000 | Sent: 7500000 | Failed: 1250 | Mbps: 150.00
```

- **PPS**: Packets per second
- **Sent**: Total packets sent
- **Failed**: Failed send attempts
- **Conn**: Active proxy connections (if using proxies)
- **ProxyFail**: Proxy connection failures
- **Mbps**: Estimated bandwidth usage

## Troubleshooting

### Permission Denied

```bash
# Ensure running as root
sudo ./ack <target> <port> <threads> <duration> <pps>
```

### No Packets Sent

1. Check if reverse path filtering is disabled:
```bash
cat /proc/sys/net/ipv4/conf/all/rp_filter
# Should be 0
```

2. Verify network interface:
```bash
ip link show
```

3. Check firewall rules:
```bash
iptables -L -n
```

### Low Performance

1. Increase thread count (if CPU allows)
2. Increase `max_pps` limit
3. Check system limits:
```bash
ulimit -n
# Should be high (1048576+)
```

4. Monitor system resources:
```bash
htop
# Watch CPU and memory usage
```

### SOCKS5 Proxy Issues

1. Verify proxy format in `socks5.txt`:
```
ip:port
ip:port:username:password
```

2. Test proxy connectivity:
```bash
curl --socks5 proxy_ip:port http://example.com
```

3. Check proxy authentication (if required)

## Build Options

### Debug Build

```bash
gcc -o ack ack.c -lpthread -g -Wall -DDEBUG
```

### Optimized Build (Default)

```bash
gcc -o ack ack.c -lpthread -O3 -march=native
```

### Static Build

```bash
gcc -o ack ack.c -lpthread -static -O3
```

## File Structure

```
.
├── ack.c              # Main source code
├── README.md          # This file
├── Makefile           # Build configuration
├── .gitignore         # Git ignore rules
└── socks5.txt         # SOCKS5 proxy list (optional)
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is provided "as-is" for educational purposes. Use at your own risk.

## References

- [RFC 793 - TCP Protocol](https://tools.ietf.org/html/rfc793)
- [RFC 2018 - TCP Selective Acknowledgment](https://tools.ietf.org/html/rfc2018)
- [Linux Raw Sockets](https://man7.org/linux/man-pages/man7/raw.7.html)
- [SOCKS5 Protocol](https://tools.ietf.org/html/rfc1928)

## Support

For issues and questions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review the troubleshooting section

---

**Remember**: Only use this tool on systems you own or have explicit written permission to test. Unauthorized network attacks are illegal.


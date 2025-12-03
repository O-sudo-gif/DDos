# DDoS Methods & Protection Repository

> **Multi-vector TCP flood attack implementations with comprehensive bypass techniques and protection strategies**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://www.kernel.org/)
[![Language: C](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Status: Active](https://img.shields.io/badge/Status-Active-green.svg)]()

---

## ⚠️ **LEGAL DISCLAIMER**

**This repository is for educational and authorized security testing purposes ONLY.**

- **Unauthorized use** of these tools against systems you do not own or have explicit written permission to test is **illegal** and may result in criminal prosecution
- The authors and contributors are **not responsible** for any misuse of this software
- Use these tools **responsibly** and only on systems you own or have explicit authorization to test
- **Penetration testing** requires written authorization from the system owner

**By using this software, you agree to use it legally and ethically.**

---

## 📋 Table of Contents

- [Overview](#overview)
- [What's Included](#whats-included)
- [TCP ACK Flood Attack](#tcp-ack-flood-attack)
- [Protection Strategies](#protection-strategies)
- [Quick Start](#quick-start)
- [Documentation](#documentation)
- [Detection & Analysis](#detection--analysis)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

---

## 🎯 Overview

This repository provides **multi-vector TCP flood attack** implementations along with detailed **protection guides** to help security professionals:

- **Understand** how TCP flood attacks work
- **Test** network infrastructure resilience against TCP floods
- **Implement** effective countermeasures and detection
- **Learn** about attack signatures and protection methods

**Current Releases:**
- ✅ TCP ACK Flood (`ack.c`) - Fully implemented with protection guides
- ✅ TCP SYN Flood (`syn.c`) - Fully implemented with documentation
- ✅ TCP-AMP: SYN-ACK Flood + BGP Amplification (`amp.c`) - Fully implemented
- ✅ **TCP-RAPE: Multi-Vector TCP Attack** (`rape.c`) - v2.0.0 with clever bypass techniques
- ✅ **HTTP-STORM: HTTP/2 Load Testing Tool** (`http-storm.js`) - v2.0 Enhanced for 100k+ req/s

> **Note:** More attack methods will be added incrementally as updates to this repository.

---

## 📦 What's Included

- ✅ **ack.c** - High-performance TCP ACK flood implementation
- ✅ **syn.c** - High-performance TCP SYN flood implementation
- ✅ **amp.c** - High-performance TCP SYN-ACK flood with BGP amplification
- ✅ **rape.c** - Multi-vector TCP attack with clever bypass techniques (v2.0.0)
- ✅ **http-storm.js** - HTTP/2 and HTTP/1.1 load testing tool (v2.0 Enhanced)
- ✅ **Protection Guides** - Comprehensive defense strategies (English & Greek)
- ✅ **Signature-Based Detection** - Methods to identify and block attacks
- ✅ **Architecture Documentation** - Technical implementation details
- ✅ **Usage Examples** - Practical scenarios and use cases
- ✅ **Build System** - Makefile for easy compilation

---

## 📁 Repository Structure

```
Methods/
├── L4/
│   └── TCP/
│       ├── ACK/                               # TCP ACK Flood Attack
│       │   ├── ack.c                          # Attack implementation
│       │   ├── README.md                      # Attack documentation
│       │   ├── ARCHITECTURE.md                # Technical architecture
│       │   ├── USAGE_EXAMPLES.md              # Usage examples
│       │   ├── Makefile                       # Build configuration
│       │   ├── LICENSE                        # MIT License
│       │   ├── socks5.txt.example             # SOCKS5 proxy example
│       │   ├── .gitignore                     # Git ignore rules
│       │   └── PROTECTION/                    # Protection guides
│       │       └── SIGNATURE_BASED_PROTECTION_GR.md  # Signature-based protection (Greek)
│       │
│       ├── SYN/                               # TCP SYN Flood Attack
│       │   ├── syn.c                          # Attack implementation
│       │   ├── README.md                      # Attack documentation
│       │   ├── ARCHITECTURE.md                # Technical architecture
│       │   ├── USAGE_EXAMPLES.md              # Usage examples
│       │   ├── Makefile                       # Build configuration
│       │   ├── LICENSE                        # MIT License
│       │   ├── socks5.txt.example             # SOCKS5 proxy example
│       │   ├── .gitignore                     # Git ignore rules
│       │   └── PROTECTION/                    # Protection guides
│       │       ├── README.md                  # Protection overview
│       │       └── SIGNATURE_BASED_PROTECTION_GR.md  # Signature-based protection (Greek)
│       │
│       ├── AMP/                               # TCP-AMP: SYN-ACK Flood + BGP Amplification
│       │   ├── amp.c                          # Attack implementation
│       │   ├── README.md                      # Attack documentation
│       │   ├── ARCHITECTURE.md                # Technical architecture
│       │   ├── USAGE_EXAMPLES.md              # Usage examples
│       │   ├── Makefile                       # Build configuration
│       │   ├── LICENSE                        # MIT License
│       │   ├── socks5.txt.example             # SOCKS5 proxy example
│       │   ├── .gitignore                     # Git ignore rules
│       │   └── PROTECTION/                    # Protection guides
│       │       └── SIGNATURE_BASED_PROTECTION_GR.md  # Signature-based protection (Greek)
│       │
│       └── RAPE/                              # TCP-RAPE: Multi-Vector TCP Attack
│           ├── rape.c                        # Attack implementation
│           ├── README.md                      # Attack documentation
│           ├── USAGE_EXAMPLES.md              # Usage examples
│           ├── CHANGELOG.md                   # Version history
│           ├── CONTRIBUTING.md                # Contribution guidelines
│           ├── SECURITY.md                    # Security policy
│           ├── DEPLOYMENT.md                  # Deployment instructions
│           ├── Makefile                       # Build configuration
│           ├── LICENSE                        # MIT License
│           └── .gitignore                     # Git ignore rules
│
└── L7/                                        # Layer 7 (Application) Attacks
    └── HTTP-STORM/                            # HTTP/2 Load Testing Tool
        ├── PROTECTION/                        # Protection guides
        │   ├── PROTECTION_GUIDE.md            # Sophisticated protection
        │   └── README.md                      # Protection overview  
        ├── http-storm.js                      # HTTP/2 load testing implementation
        ├── README.md                          # Comprehensive documentation
        ├── package.json                       # Node.js dependencies
        └── .gitignore                         # Git ignore rules
│
└── README.md                                  # This file
```

---

## 🔥 TCP Flood Attacks

### TCP ACK Flood Attack

#### Description

The **TCP ACK Flood** attack sends a flood of TCP ACK (Acknowledgment) packets with spoofed source IPs and SACK (Selective Acknowledgment) blocks to overwhelm the target server.

### How It Works

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Attacker  │────────▶│  Spoofed    │────────▶│   Target    │
│             │         │     IPs      │         │   Server    │
└─────────────┘         └──────────────┘         └─────────────┘
     │                         │                        │
     │ 1. Generate spoofed IPs │                        │
     │ 2. Craft ACK packets    │                        │
     │ 3. Add SACK blocks      │                        │
     │ 4. Send flood           │──────────────────────▶│
     │                         │                        │
     │                         │                        │
     │                         │      Resource          │
     │                         │      Exhaustion        │
     │                         │◀───────────────────────│
```

### Key Characteristics

- ✅ **Raw Socket Implementation** - Direct packet crafting at kernel level
- ✅ **IP Spoofing** - Generates spoofed source IPs across multiple ranges
- ✅ **SACK Support** - Implements TCP Selective Acknowledgment blocks
- ✅ **Multi-threading** - Supports up to 10,000 concurrent threads
- ✅ **Rate Limiting** - Built-in token bucket rate limiter
- ✅ **SOCKS5 Proxy Support** - Optional proxy routing for anonymity
- ✅ **Connection State Tracking** - Maintains state for realistic sequences
- ✅ **High Performance** - Up to 500,000+ PPS on modern hardware

#### Attack Signatures

The attack can be identified by these unique signatures:

1. **TCP Data Offset = 15** (60 bytes header) - Very unusual in legitimate traffic
2. **40 bytes TCP Options** - Specific pattern (MSS → Window → Timestamp → SACK_PERM → SACK blocks)
3. **0xFF Payload Pattern** - 1420 bytes all set to 0xFF
4. **Pure ACK Packets** - Only ACK flag set, no SYN/FIN/RST

#### Impact

- ⚠️ **Resource Exhaustion** - Server processes invalid ACK packets
- ⚠️ **Bandwidth Consumption** - High packet rate consumes network bandwidth
- ⚠️ **Service Degradation** - Can cause slowdowns or complete outage
- ⚠️ **Connection Queue Overflow** - May fill connection tracking tables

### TCP SYN Flood Attack

#### Description

The **TCP SYN Flood** attack sends a flood of TCP SYN (Synchronize) packets with spoofed source IPs and random TCP options to exhaust the target server's connection queue.

#### How It Works

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Attacker  │────────▶│  Spoofed    │────────▶│   Target    │
│             │         │     IPs      │         │   Server    │
└─────────────┘         └──────────────┘         └─────────────┘
     │                         │                        │
     │ 1. Generate spoofed IPs │                        │
     │ 2. Craft SYN packets    │                        │
     │ 3. Add random TCP opts  │                        │
     │ 4. Send flood           │───────────────────────▶│
     │                         │                        │
     │                         │      Connection        │
     │                         │      Queue Exhaustion  │
     │                         │◀───────────────────────│
```

#### Key Characteristics

- ✅ **Raw Socket Implementation** - Direct packet crafting at kernel level
- ✅ **IP Spoofing** - Generates spoofed source IPs across multiple ranges
- ✅ **Random TCP Options** - MSS, Window Scale, Timestamp, SACK_PERM
- ✅ **Multi-threading** - Supports up to 10,000 concurrent threads
- ✅ **Rate Limiting** - Built-in rate limiter
- ✅ **SOCKS5 Proxy Support** - Optional proxy routing for anonymity
- ✅ **Connection State Tracking** - Maintains state for realistic sequences
- ✅ **High Performance** - Up to 500,000+ PPS on modern hardware

#### Attack Signatures

The attack can be identified by these characteristics:

1. **SYN Flag Only** - Only SYN flag set, no ACK/FIN/RST
2. **Random TCP Options** - Variable combinations of MSS, Window Scale, Timestamp
3. **No Payload** - Pure SYN packets (~40-80 bytes)
4. **High SYN Rate** - Unusually high rate of SYN packets

#### Impact

- ⚠️ **Connection Queue Exhaustion** - Fills server's SYN backlog
- ⚠️ **Resource Consumption** - Server allocates memory for each SYN
- ⚠️ **Service Degradation** - Legitimate connections may be rejected
- ⚠️ **SYN Timeout** - Server waits for ACK that never comes

### TCP-AMP: SYN-ACK Flood + BGP Amplification

#### Description

The **TCP-AMP (SYN-ACK Flood with BGP Amplification)** attack sends a flood of TCP SYN-ACK packets with optional BGP payloads to overwhelm the target server. When BGP amplification is enabled, the attack leverages BGP routers to amplify the attack traffic.

#### How It Works

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Attacker  │────────▶│  Spoofed    │────────▶│   Target    │
│             │         │     IPs      │         │   Server    │
└─────────────┘         └──────────────┘         └─────────────┘
     │                         │                        │
     │ 1. Generate spoofed IPs │                        │
     │ 2. Craft SYN-ACK packets│                        │
     │ 3. Add BGP payload (opt) │                       │
     │ 4. Send flood           │──────────────────────▶│
     │                         │                        │
     │                         │      Resource          │
     │                         │      Exhaustion        │
     │                         │◀───────────────────────│
```

#### Key Characteristics

- ✅ **Raw Socket Implementation** - Direct packet crafting at kernel level
- ✅ **SYN-ACK Packets** - Both SYN and ACK flags set (simulates established connection)
- ✅ **BGP Amplification** - Optional BGP payload for amplification attacks
- ✅ **IP Spoofing** - Generates spoofed source IPs across multiple ranges
- ✅ **Random TCP Options** - MSS, Window Scale, Timestamp, SACK_PERM
- ✅ **Multi-threading** - Supports up to 10,000 concurrent threads
- ✅ **Rate Limiting** - Built-in rate limiter
- ✅ **SOCKS5 Proxy Support** - Optional proxy routing for anonymity
- ✅ **Connection State Tracking** - Maintains state for realistic sequences
- ✅ **High Performance** - Up to 500,000+ PPS on modern hardware

#### Attack Signatures

The attack can be identified by these characteristics:

1. **SYN-ACK Flags** - Both SYN and ACK flags set
2. **BGP Payload** - 79 bytes BGP OPEN message (if `--bgp` flag enabled)
3. **BGP Marker** - 16 bytes of 0xFF (BGP authentication marker)
4. **Packet Size** - ~60 bytes (without BGP), ~140 bytes (with BGP)
5. **Random TCP Options** - Variable combinations of MSS, Window Scale, Timestamp

#### Impact

- ⚠️ **Resource Exhaustion** - Server processes invalid SYN-ACK packets
- ⚠️ **Bandwidth Consumption** - High packet rate consumes network bandwidth
- ⚠️ **BGP Amplification** - BGP routers respond with large UPDATE messages
- ⚠️ **Service Degradation** - Can cause slowdowns or complete outage
- ⚠️ **Connection Confusion** - SYN-ACK packets may confuse connection state machines

### TCP-RAPE: Multi-Vector TCP Attack

#### Description

The **TCP-RAPE (Multi-Vector TCP Attack)** is a comprehensive attack tool that combines multiple TCP flood techniques simultaneously to maximize server impact. It implements various attack vectors including SYN, ACK, FIN, RST, PSH, URG, SYN-ACK, FIN-ACK, and mixed flag combinations.

#### How It Works

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Attacker  │────────▶│  Spoofed    │────────▶│   Target    │
│             │         │     IPs      │         │   Server    │
└─────────────┘         └──────────────┘         └─────────────┘
     │                         │                        │
     │ 1. Generate spoofed IPs │                        │
     │ 2. Rotate attack types  │                        │
     │ 3. Apply bypass techs   │                        │
     │ 4. Send multi-vector    │──────────────────────▶│
     │    flood                │                        │
     │                         │      Multi-Vector      │
     │                         │      Resource          │
     │                         │      Exhaustion        │
     │                         │◀───────────────────────│
```

#### Key Characteristics

- ✅ **Multi-Vector Attack** - Rotates through SYN, ACK, FIN, RST, PSH, URG, SYN-ACK, FIN-ACK, MIXED
- ✅ **Clever Bypass Techniques** - Variable TCP options (0-20 bytes), variable header size, SYN-first simulation
- ✅ **Elite Bypass Mode** - Full connection simulation for advanced protection systems (Cloudflare, AWS Shield)
- ✅ **Stealth Mode** - Maximum bypass with HTTP payloads, OS fingerprinting, human timing patterns
- ✅ **IP Spoofing** - Generates spoofed source IPs across multiple ranges
- ✅ **Variable Payload Sizes** - Random payload generation to avoid pattern detection
- ✅ **IP ID Patterns Per Connection** - Incremental IP IDs matching real OS behavior
- ✅ **SACK Blocks** - Includes SACK_PERM and SACK blocks for established connections
- ✅ **Rate Limiting Bypass** - Variable micro-delays (10-100μs) to avoid detection
- ✅ **Multi-threading** - Supports up to 10,000 concurrent threads per worker
- ✅ **High Performance** - Up to 500,000+ PPS on modern hardware
- ✅ **Real-time Statistics** - Live monitoring of all packet types

#### Attack Signatures

The attack can be identified by these characteristics:

1. **Variable TCP Options (0-20 bytes)** - Clever bypass technique to avoid 40-byte detection
2. **Variable TCP Header Size (doff 5-15)** - Dynamic header size instead of fixed
3. **SYN-First Patterns** - SYN packets before data packets (30-40% chance)
4. **Variable Payload Sizes** - Most ACK packets have no payload (70% chance)
5. **IP ID Patterns** - Incremental IP IDs per connection hash
6. **SACK Blocks** - Rare SACK blocks in established connections (5% chance)
7. **Multiple Attack Types** - Rotation through SYN, ACK, FIN, RST, PSH, URG, etc.

#### Impact

- ⚠️ **Connection Queue Exhaustion** - SYN floods fill connection backlog
- ⚠️ **Resource Exhaustion** - CPU and memory consumption from multiple attack vectors
- ⚠️ **Service Degradation** - Slowdown or complete outage
- ⚠️ **State Machine Confusion** - Mixed flags confuse TCP state tracking
- ⚠️ **Bypass Capabilities** - Can evade advanced protection systems with elite/stealth modes

### HTTP-STORM: HTTP/2 Load Testing Tool

#### Description

The **HTTP-STORM** tool is a high-performance HTTP/2 and HTTP/1.1 load testing tool designed for stress testing web applications, APIs, and CDN infrastructure. It supports both HTTP/2 and HTTP/1.1 protocols with advanced features like proxy rotation, custom headers, and intelligent rate limiting.

#### How It Works

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Master    │────────▶│   Workers    │───────▶│   Target    │
│  Process    │         │  (Cluster)   │         │   Server    │
└─────────────┘         └──────────────┘         └─────────────┘
     │                         │                        │
     │ 1. Parse arguments      │                        │
     │ 2. Load proxy list      │                        │
     │ 3. Spawn workers        │                        │
     │                         │                        │
     │                         │ 1. Select proxy        │
     │                         │ 2. Establish TLS       │
     │                         │ 3. Negotiate protocol  │
     │                         │ 4. Send requests       │──────────────────▶|
     │                         │                        │                    │
     │                         │                        │      HTTP/2        │
     │                         │                        │      Multiplex     │
     │                         │                        │◀──────────────────│
```

#### Key Characteristics

- ✅ **HTTP/2 Support** - Full HTTP/2 protocol implementation with HPACK compression
- ✅ **HTTP/1.1 Support** - Traditional HTTP/1.1 with Keep-Alive connections
- ✅ **Mixed Protocol Mode** - Automatically switches between HTTP/2 and HTTP/1.1
- ✅ **Proxy Rotation** - SOCKS5/HTTP proxy support with automatic rotation
- ✅ **High Performance** - Optimized for 100,000+ requests per second
- ✅ **Multi-threaded** - Cluster-based architecture for maximum throughput
- ✅ **Custom Headers** - Full control over HTTP headers and user agents
- ✅ **Rate Limiting** - Intelligent rate limiting with randomization
- ✅ **Bot Fight Mode** - Cloudflare challenge bypass with cookie generation
- ✅ **Debug Mode** - Real-time status code monitoring

#### Attack Signatures

The tool can be identified by these characteristics:

1. **High Request Rate** - Unusually high requests per second
2. **HTTP/2 Settings** - Specific HTTP/2 connection settings
3. **Header Patterns** - Consistent header patterns
4. **Proxy IPs** - Known proxy IP addresses
5. **User-Agent Patterns** - Repeated user-agent strings

#### Impact

- ⚠️ **Resource Exhaustion** - Server processes high volume of requests
- ⚠️ **Bandwidth Consumption** - High request rate consumes network bandwidth
- ⚠️ **Service Degradation** - Can cause slowdowns or complete outage
- ⚠️ **Rate Limit Bypass** - Can bypass rate limiting with randomization

---

## 🛡️ Protection Strategies

### Multi-Layer Defense Approach

Effective DDoS protection requires **multiple layers** of defense:

```
┌─────────────────────────────────────────┐
│  Layer 1: Network-Level Filtering       │
│  - iptables/nftables rules              │
│  - Rate limiting                        │
│  - GeoIP filtering                      │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│  Layer 2: Signature-Based Detection     │
│  - Packet pattern matching              │
│  - Deep packet inspection               │
│  - Behavioral analysis                  │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│  Layer 3: Application-Level Protection  │
│  - WAF (Web Application Firewall)       │
│  - Request validation                   │
│  - Rate limiting per endpoint           │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│  Layer 4: DDoS Protection Services      │
│  - Cloudflare, AWS Shield               │
│  - On-premise mitigation appliances     │
└─────────────────────────────────────────┘
```

### Protection Techniques

#### 1. **Signature-Based Filtering**

Identify and block packets matching known attack signatures:

- **TCP Header Analysis:** Detect unusual header sizes (e.g., doff=15)
- **Payload Patterns:** Match specific payload signatures (e.g., 0xFF patterns)
- **Option Analysis:** Detect suspicious TCP option combinations

**Example:** See `L4/TCP/SIGNATURE_BASED_PROTECTION_GR.md`

#### 2. **Rate Limiting**

Limit the number of packets/connections per IP:

```bash
# iptables rate limiting
iptables -A INPUT -p tcp --tcp-flags ACK ACK \
    -m limit --limit 50/sec --limit-burst 100 \
    -j ACCEPT
```

#### 3. **Connection State Validation**

Only accept packets from established connections:

```bash
# Only allow established connections
iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 10/sec -j ACCEPT
```

#### 4. **SYN Cookies**

Protect against SYN floods:

```bash
# Enable SYN cookies
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
```

#### 5. **Kernel Hardening**

Optimize kernel parameters:

```bash
# Increase connection tracking
sysctl -w net.netfilter.nf_conntrack_max=1000000

# Reduce SYN retries
sysctl -w net.ipv4.tcp_syn_retries=2
sysctl -w net.ipv4.tcp_synack_retries=2
```

#### 6. **Monitoring & Alerting**

Implement real-time monitoring:

- **Traffic Analysis:** Monitor packet rates, connection counts
- **Anomaly Detection:** Identify unusual patterns
- **Automated Response:** Auto-block suspicious IPs

---

## 🚀 Quick Start

### Prerequisites

- **Operating System:** Linux (Ubuntu 20.04+, Debian 10+, CentOS 7+)
- **Privileges:** Root access (for raw sockets)
- **Compiler:** GCC with C99 support
- **Libraries:** pthread (usually included)

### Building

```bash
# Clone repository
git clone https://github.com/yourusername/ddos-methods.git
cd ddos-methods/Methods/L4/TCP

# Build ACK flood tool
cd ACK
make

# Build SYN flood tool
cd ../SYN
make

# Build AMP (SYN-ACK + BGP) tool
cd ../AMP
make

# Build RAPE (Multi-Vector) tool
cd ../RAPE
make

# Or manually compile
gcc -o ack ack.c -lpthread -O3 -Wall
gcc -o syn syn.c -lpthread -O3 -Wall
gcc -o rape rape.c -lpthread -O3 -Wall -Wno-unused-result
```

### Usage

#### TCP ACK Flood

```bash
# Basic syntax (requires root)
sudo ./ack <target_ip> <target_port> <threads> <duration> <max_pps> [--socks5]

# Example: Basic ACK flood
sudo ./ack 192.168.1.100 80 300 60 100000

# Example: With SOCKS5 proxies
sudo ./ack 192.168.1.100 443 500 120 200000 --socks5
```

#### TCP SYN Flood

```bash
# Basic syntax (requires root)
sudo ./syn <target_ip> <target_port> <threads> <duration> <max_pps> [--socks5]

# Example: Basic SYN flood
sudo ./syn 192.168.1.100 80 300 60 100000

# Example: With SOCKS5 proxies
sudo ./syn 192.168.1.100 443 500 120 200000 --socks5
```

#### TCP-RAPE: Multi-Vector Attack

```bash
# Basic syntax (requires root)
sudo ./rape <target_ip> <target_port> <threads> <duration> <max_pps> [attack_mode] [--elite] [--stealth]

# Example: All attack types (rotates through SYN, ACK, FIN, RST, etc.)
sudo ./rape 192.168.1.100 80 500 60 200000 all

# Example: Elite mode (bypass advanced protections)
sudo ./rape 192.168.1.100 80 500 300 200000 all --elite

# Example: Stealth mode (maximum bypass)
sudo ./rape 192.168.1.100 80 500 300 200000 all --stealth

# Example: SYN flood only
sudo ./rape 192.168.1.100 80 300 60 100000 syn

# Example: ACK flood only
sudo ./rape 192.168.1.100 443 300 60 100000 ack
```

#### HTTP-STORM: HTTP/2 Load Testing

```bash
# Basic syntax (Node.js required)
node http-storm.js <METHOD> <TARGET> <TIME> <THREADS> <RATELIMIT> <PROXYFILE> [OPTIONS]

# Example: Basic HTTP/2 load test
node http-storm.js GET "https://example.com" 120 32 90 proxy.txt

# Example: Advanced configuration with all features
node http-storm.js GET "https://example.com?q=%RAND%" 120 32 90 proxy.txt \
  --query 1 \
  --cookie "session=abc123" \
  --delay 0 \
  --bfm true \
  --referer rand \
  --debug \
  --randrate \
  --full

# Example: POST request with data
node http-storm.js POST "https://api.example.com/login" 60 16 50 proxy.txt \
  --postdata "username=test&password=%RAND%" \
  --header "Content-Type:application/x-www-form-urlencoded"

# Example: HTTP/1.1 only mode
node http-storm.js GET "https://example.com" 120 32 90 proxy.txt --http 1

# Example: Mixed protocol mode
node http-storm.js GET "https://example.com" 120 32 90 proxy.txt --http mix
```

**Parameters:**
- `target_ip` - Target server IP address
- `target_port` - Target TCP port (e.g., 80, 443, 22)
- `threads` - Number of worker threads (1-10000, recommended: 200-500)
- `duration` - Attack duration in seconds
- `max_pps` - Maximum packets per second (e.g., 100000)
- `--socks5` - (Optional) Enable SOCKS5 proxy mode (requires `socks5.txt`)

**Example Output (ACK):**
```
[+] Starting 300 threads with PURE ACK FLOOD
[+] Target: 192.168.1.100:80
[+] Maximum PPS: 100000
[*] Attack: 100% ACK packets with SACK_PERM + SACK blocks (SLE & SRE)
[*] Rate limiter initialized: 100000 PPS (stable token bucket)
[*] Running for 60 seconds...

[LIVE] PPS: 98500 | Sent: 5910000 | Failed: 150 | Mbps: 78.80
```

**Example Output (SYN):**
```
[+] Starting 300 threads with PURE SYN FLOOD
[+] Target: 192.168.1.100:80
[+] Maximum PPS: 100000
[*] Attack: 100% SYN packets with random TCP options (MSS, Window Scale, Timestamp)
[*] Running for 60 seconds...

[LIVE] PPS: 98500 | Sent: 5910000 | Failed: 150 | Mbps: 7.88
```

**Example Output (RAPE - Multi-Vector):**
```
[+] TCP-RAPE: Multi-Vector TCP Attack Tool
[+] Target: 192.168.1.100:80
[+] Threads: 500
[+] Duration: 60 seconds
[+] Max PPS: 200000
[+] Attack Mode: ALL
[+] ELITE MODE: ENABLED (Full connection simulation, behavioral patterns, maximum bypass)
[*] MAXIMUM POWER MODE: 10,000 sockets per thread, 512MB buffers, zero delays, 10-20 packets/burst
[*] Starting attack...

[LIVE] PPS: 185000 | Total: 11100000 | SYN: 1230000 | ACK: 1230000 | FIN: 1230000 | RST: 1230000 | PSH: 1230000 | URG: 1230000 | MIXED: 1230000 | Mbps: 148.00
```

**Example Output (HTTP-STORM - HTTP/2):**
```
🌪️ HTTP-STORM v2.0 ENHANCED - Optimized for 200k+ req/s
📊 Threads: 32 | Proxies: 1000

[DEBUG MODE] Status Codes:
2024-01-01 12:00:00 { '200': 50000, '429': 100, '503': 50 }
```

### Testing Protection

1. **Set up protection rules** (see protection guides)
2. **Run attack** against your own test server
3. **Monitor** logs and statistics
4. **Verify** protection effectiveness
5. **Adjust** rules as needed

---

## 📚 Documentation

### Available Documentation

#### TCP ACK Flood

| Document                             | Description                                       | Location                                                 |
|--------------------------------------|---------------------------------------------------|----------------------------------------------------------|
| **README.md**                        | Attack overview, usage, and features              | `L4/TCP/ACK/README.md`                                   |
| **ARCHITECTURE.md**                  | Technical architecture and implementation details | `L4/TCP/ACK/ARCHITECTURE.md`                             |
| **SIGNATURE_BASED_PROTECTION_GR.md** | Signature-based protection guide (Greek)          | `L4/TCP/ACK/PROTECTION/SIGNATURE_BASED_PROTECTION_GR.md` |
| **USAGE_EXAMPLES.md**                | Practical usage examples and scenarios            | `L4/TCP/ACK/USAGE_EXAMPLES.md`                           |

#### TCP SYN Flood

| Document                             | Description                                       | Location                                                 |
|--------------------------------------|---------------------------------------------------|----------------------------------------------------------|
| **README.md**                        | Attack overview, usage, and features              | `L4/TCP/SYN/README.md`                                   |
| **ARCHITECTURE.md**                  | Technical architecture and implementation details | `L4/TCP/SYN/ARCHITECTURE.md`                             |
| **USAGE_EXAMPLES.md**                | Practical usage examples and scenarios            | `L4/TCP/SYN/USAGE_EXAMPLES.md`                           |
| **SIGNATURE_BASED_PROTECTION_GR.md** | Signature-based protection guide (Greek)          | `L4/TCP/SYN/PROTECTION/SIGNATURE_BASED_PROTECTION_GR.md` |

#### TCP-RAPE: Multi-Vector Attack

| Document              | Description                            | Location                        |
|-----------------------|----------------------------------------|---------------------------------|
| **README.md**         | Attack overview, usage, and features   | `L4/TCP/RAPE/README.md`         |
| **USAGE_EXAMPLES.md** | Practical usage examples and scenarios | `L4/TCP/RAPE/USAGE_EXAMPLES.md` |
| **CHANGELOG.md**      | Version history and changes            | `L4/TCP/RAPE/CHANGELOG.md`      |
| **CONTRIBUTING.md**   | Contribution guidelines                | `L4/TCP/RAPE/CONTRIBUTING.md`   |
| **SECURITY.md**       | Security policy                        | `L4/TCP/RAPE/SECURITY.md`       |

#### HTTP-STORM: HTTP/2 Flood Attack

| Document           | Description                                      | Location                        |
|--------------------|--------------------------------------------------|---------------------------------|
| **README.md**      | Comprehensive documentation, usage, and features | `L7/HTTP-STORM/README.md`       |
| **http-storm.js**  | HTTP/2 load testing implementation               | `L7/HTTP-STORM/http-storm.js`   |
| **package.json**   | Node.js dependencies                             | `L7/HTTP-STORM/package.json`    |
| **PROTECTION/**    | Comprehensive protection guides and strategies   | `L7/HTTP-STORM/PROTECTION/`     |

### Protection Guides

- **ACK Flood:** See `L4/TCP/ACK/README.md` and `L4/TCP/ACK/PROTECTION/SIGNATURE_BASED_PROTECTION_GR.md`
- **SYN Flood:** See `L4/TCP/SYN/README.md` and `L4/TCP/SYN/PROTECTION/SIGNATURE_BASED_PROTECTION_GR.md`
- **RAPE (Multi-Vector):** See `L4/TCP/RAPE/README.md` for comprehensive protection strategies
- **HTTP-STORM (HTTP/2):** See `L7/HTTP-STORM/PROTECTION/README.md` and `L7/HTTP-STORM/PROTECTION/PROTECTION_GUIDE.md` for comprehensive protection strategies

---

## 🔍 Detection & Analysis

### Attack Signatures

The ACK flood attack has unique signatures that can be detected:

1. **TCP Data Offset = 15** (60 bytes header) - Very rare in legitimate traffic
2. **40 bytes TCP Options** - Specific pattern:
   - MSS (4 bytes)
   - Window Scaling (3 bytes)
   - Timestamp (10 bytes)
   - SACK_PERM (2 bytes)
   - SACK blocks (10 bytes each, 1-3 blocks)
   - NOP padding
3. **0xFF Payload Pattern** - 1420 bytes all set to 0xFF
4. **Pure ACK Packets** - Only ACK flag set, no SYN/FIN/RST/PSH/URG

### Detection Tools

- **tcpdump** - Packet capture and analysis
- **Wireshark** - Deep packet inspection
- **Suricata/Snort** - IDS/IPS with custom rules
- **Custom Python scripts** - Deep packet inspection
- **eBPF/XDP** - Kernel-level filtering

### Monitoring Commands

```bash
# Monitor ACK packets
tcpdump -i eth0 -n 'tcp[tcpflags] & tcp-ack != 0'

# Detect ACK flood (high rate)
timeout 1 tcpdump -i eth0 -n 'tcp[tcpflags] & tcp-ack != 0 and tcp[tcpflags] & tcp-syn == 0' 2>/dev/null | wc -l

# Analyze top source IPs
tcpdump -i eth0 -n 'tcp[tcpflags] & tcp-ack != 0' | \
    awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head -10

# Check for signature (TCP doff=15)
tcpdump -i eth0 -n -c 1000 -w capture.pcap 'tcp'
tshark -r capture.pcap -T fields -e ip.src -e tcp.hdr_len | awk '$2 == 60'
```

---

## 🛠️ Protection Implementation

### Quick Protection Setup

```bash
# 1. Install dependencies
sudo apt-get install iptables-persistent

# 2. Apply protection rules
sudo iptables -A INPUT -p tcp --tcp-flags ACK ACK \
    -m state ! --state ESTABLISHED,RELATED \
    -m limit --limit 50/sec --limit-burst 100 \
    -j DROP

# 3. Enable SYN cookies
echo 1 | sudo tee /proc/sys/net/ipv4/tcp_syncookies

# 4. Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

### Advanced Protection

For production environments, consider:

1. **Hardware Solutions:**
   - DDoS mitigation appliances
   - Load balancers with DDoS protection

2. **Cloud Services:**
   - Cloudflare DDoS Protection
   - AWS Shield
   - Google Cloud Armor

3. **Custom Solutions:**
   - eBPF/XDP filters
   - Custom kernel modules
   - Distributed filtering

---

## 📊 Attack Statistics

| Metric                    | Value             |
|---------------------------|-------------------|
| **Layer**                 | L4 (Transport)    |
| **Protocol**              | TCP               |
| **Complexity**            | Medium            |
| **Detection Difficulty**  | Medium            |
| **Mitigation Difficulty** | Medium            |
| **Typical PPS**           | 100,000 - 500,000 |
| **Packet Size**           | ~1500 bytes       |
| **Thread Support**        | Up to 10,000      |

---

## 🤝 Contributing

Contributions are welcome! This repository will grow incrementally with new attack methods.

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/new-attack`)
3. **Add** your attack implementation with:
   - Source code
   - Protection guide
   - Documentation
   - Usage examples
4. **Test** thoroughly on your own infrastructure
5. **Document** your changes
6. **Submit** a pull request

### Contribution Areas

- ✅ **New Attack Methods** - Implement additional DDoS attack vectors
- ✅ **Protection Strategies** - Improve defense mechanisms
- ✅ **Detection Signatures** - Add new detection methods
- ✅ **Documentation** - Improve or translate documentation
- ✅ **Performance** - Optimize existing code
- ✅ **Testing** - Add test cases and validation

---

## 📝 Code of Conduct

- **Respect** others' work and contributions
- **Use** tools responsibly and legally
- **Report** security vulnerabilities responsibly
- **Follow** ethical hacking principles

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

**Important:** The license does not grant permission to use these tools illegally. Users are responsible for compliance with all applicable laws.

---

## 🙏 Acknowledgments

- Security researchers who documented attack methods
- Open-source community contributions
- Protection guide authors

---

## 📞 Support & Resources

### Getting Help

- **Issues:** Open an issue on GitHub
- **Documentation:** Check the documentation in each attack directory
- **Examples:** See `USAGE_EXAMPLES.md` files

### Additional Resources

- [RFC 793 - TCP Protocol](https://tools.ietf.org/html/rfc793)
- [OWASP DDoS Protection](https://owasp.org/www-community/attacks/Denial_of_Service)
- [CERT DDoS Guide](https://www.cert.org/)

---

## 🔐 Security Best Practices

### For Attackers (Authorized Testing Only)

1. ✅ Always get **written authorization**
2. ✅ Test on **isolated networks**
3. ✅ **Document** all activities
4. ✅ **Limit** attack intensity
5. ✅ **Monitor** target systems

### For Defenders

1. ✅ **Implement** multi-layer protection
2. ✅ **Monitor** network traffic continuously
3. ✅ **Update** protection rules regularly
4. ✅ **Test** defenses periodically
5. ✅ **Have** incident response plan

---

## 📈 Roadmap

### Current Releases

- ✅ **TCP ACK Flood** (`ack.c`) - Fully implemented with protection guides
- ✅ **TCP SYN Flood** (`syn.c`) - Fully implemented with documentation
- ✅ **TCP-AMP: SYN-ACK + BGP** (`amp.c`) - Fully implemented
- ✅ **TCP-RAPE: Multi-Vector** (`rape.c`) - v2.0.0 with clever bypass techniques
- ✅ **HTTP-STORM Flood Attack** (`rape.c`) - Fully optimised for max performance with clever bypass techniques to known Protections

### Planned Updates

More attack methods will be added incrementally:
- [ ] **UDP Flood** - UDP-based flood attacks
- [+] **HTTP Flood** - Layer 7 HTTP flood attacks
- [ ] **Slowloris** - Slow HTTP attack
- [ ] **DNS Amplification** - DNS amplification attack
- [ ] **NTP Amplification** - NTP amplification attack
- [ ] **Well Engineered Game Flood/DDos Attacks** - Protocol-specific attacks

### Future Enhancements

- [ ] Automated protection scripts
- [ ] Web-based monitoring dashboard
- [ ] Machine learning-based detection
- [ ] Distributed attack coordination
- [ ] Additional protection guides

---

## ⚡ Performance Benchmarks

Typical performance on modern hardware:

| Attack             | Threads | PPS/RPS   | CPU Usage | Memory      | Packet/Request Size |
|--------------------|---------|-----------|-----------|-------------|---------------------|
| ACK Flood          | 300     | 100k      | 40%       | 200MB       | ~1500 bytes         |
| SYN Flood          | 300     | 100k      | 35%       | 150MB       | ~40-80 bytes        |
| RAPE (All Mode)    | 500     | 200k      | 70%       | 400MB       | ~60-1500 bytes      |
| RAPE (Elite)       | 500     | 200k      | 70%       | 400MB       | ~60-1500 bytes      |
| RAPE (Stealth)     | 500     | 200k      | 70%       | 400MB       | ~60-1500 bytes      |
| HTTP-STORM (HTTP/2)| 32      | 50k-100k  | 40-60%    | 200-400MB   | Variable            |
| HTTP-STORM (--full)| 128     | 200k+     | 80-100%   | 800MB+      | Variable            |

*Results vary by hardware and network conditions*

---

## 🌍 Internationalization

Documentation available in:
- 🇬🇧 **English** - Primary language (README, ARCHITECTURE, USAGE_EXAMPLES)
- 🇬🇷 **Greek (Ελληνικά)** - Protection guides (SIGNATURE_BASED_PROTECTION_GR.md)

Contributions for additional languages welcome!

---

## ⚠️ Responsible Disclosure

If you discover a vulnerability in protection mechanisms:

1. **Do not** exploit it publicly
2. **Contact** repository maintainers privately
3. **Allow** time for fix implementation
4. **Follow** responsible disclosure practices

---

## 📌 Important Notes

- ⚠️ **Always test on your own infrastructure**
- ⚠️ **Never attack systems without authorization**
- ⚠️ **Understand local laws** regarding network attacks
- ⚠️ **Use responsibly** for security research and testing

---

**Remember:** With great power comes great responsibility. Use these tools ethically and legally.

---

<div align="center">

**Made with ❤️ for security research and education**

[⬆ Back to Top](#ddos-methods--protection-repository)

---

## 📌 Current Status

**Active Development** - Multiple TCP flood attack implementations are complete and ready for use.

**Available Attacks:**
- ✅ **TCP-ACK Flood** - Complete with protection guides
- ✅ **TCP-SYN Flood** - Complete with documentation
- ✅ **TCP-AMP: SYN-ACK + BGP** - Complete with documentation
- ✅ **TCP-RAPE: Multi-Vector** - v2.0.0 with clever bypass techniques (Elite & Stealth modes)
- ✅ **HTTP-STORM: HTTP/2 Load Testing** - v2.0 Enhanced for 100k+ req/s with HTTP/2 and HTTP/1.1 support

**Next Updates:**
- More attack methods will be added as separate updates
- Each new attack will include its own implementation and protection guide
- Repository structure will expand organically

**Stay tuned for updates!** 🚀

</div>


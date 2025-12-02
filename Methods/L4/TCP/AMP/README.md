# TCP-AMP: SYN-ACK Flood with BGP Amplification

> **High-performance TCP SYN-ACK flood tool with optional BGP amplification payload for network stress testing**

**License:** MIT  
**Platform:** Linux  
**Language:** C  
**Status:** Active

---

## ⚠️ **LEGAL DISCLAIMER**

**This repository is for educational and authorized security testing purposes ONLY.**

* **Unauthorized use** of these tools against systems you do not own or have explicit written permission to test is **illegal** and may result in criminal prosecution
* The authors and contributors are **not responsible** for any misuse of this software
* Use these tools **responsibly** and only on systems you own or have explicit authorization to test
* **Penetration testing** requires written authorization from the system owner

**By using this software, you agree to use it legally and ethically.**

---

## 📋 Table of Contents

* [Overview](#-overview)
* [What's Included](#-whats-included)
* [Features](#-features)
* [Attack Modes](#-attack-modes)
* [Quick Start](#-quick-start)
* [Usage](#-usage)
* [Building](#-building)
* [Documentation](#-documentation)
* [Protection Strategies](#-protection-strategies)
* [Detection & Analysis](#-detection--analysis)
* [Performance](#-performance)
* [BGP Amplification](#-bgp-amplification)
* [Contributing](#-contributing)
* [Roadmap](#-roadmap)
* [License](#-license)

---

## 🎯 Overview

**TCP-AMP** is a high-performance TCP SYN-ACK flood tool designed for network stress testing and research purposes. It generates spoofed TCP SYN-ACK packets with optional BGP amplification payloads to test network infrastructure resilience.

**Current Release:** TCP-AMP v1.0.0 - BGP Amplification Edition

> **Note:** This tool implements SYN-ACK flood attacks with optional BGP payload amplification for testing BGP router resilience.

---

## 📦 What's Included

* ✅ **amp.c** - High-performance SYN-ACK flood implementation
* ✅ **BGP Amplification** - Optional BGP payload support for amplification attacks
* ✅ **IP Spoofing** - Generates spoofed source IPs from various network ranges
* ✅ **SOCKS5 Proxy Support** - Optional proxy routing for traffic obfuscation
* ✅ **Connection State Tracking** - Maintains connection state for realistic packet sequences
* ✅ **Protection Guides** - Comprehensive defense strategies
* ✅ **Usage Examples** - Practical scenarios and use cases
* ✅ **Build System** - Makefile for easy compilation
* ✅ **Documentation** - Complete technical documentation

---

## 📁 Repository Structure

```
AMP/
├── amp.c                          # Main attack implementation
├── README.md                       # This file
├── USAGE_EXAMPLES.md               # Usage examples
├── ARCHITECTURE.md                 # Technical architecture
├── CHANGELOG.md                    # Version history
├── CONTRIBUTING.md                 # Contribution guidelines
├── SECURITY.md                     # Security policy
├── DEPLOYMENT.md                   # Deployment instructions
├── Makefile                        # Build configuration
├── LICENSE                         # MIT License
├── .gitignore                     # Git ignore rules
├── socks5.txt.example              # SOCKS5 proxy example
└── PROTECTION/                     # Protection guides
    ├── README.md                   # Protection overview
    └── SIGNATURE_BASED_PROTECTION_GR.md  # Signature-based protection (Greek)
```

---

## 🔥 Features

### Core Attack Capabilities

* ✅ **SYN-ACK Flood** - Generates TCP packets with both SYN and ACK flags set
* ✅ **BGP Amplification** - Optional BGP OPEN message payload (79 bytes) for amplification
* ✅ **IP Spoofing** - Generates spoofed source IPs across multiple network ranges
* ✅ **Random TCP Options** - Implements MSS, Window Scale, Timestamp, and SACK_PERM options
* ✅ **Multi-threading** - Supports up to 10,000 concurrent threads for maximum throughput
* ✅ **Rate Limiting** - Built-in rate limiter for controlled packet generation
* ✅ **SOCKS5 Proxy Support** - Optional proxy support for routing traffic through SOCKS5 proxies
* ✅ **Connection State Tracking** - Maintains connection state for realistic packet sequences
* ✅ **Real-time Statistics** - Live monitoring of packets per second (PPS), bandwidth, and connection stats
* ✅ **Optimized Performance** - Efficient memory management and socket pooling

### Advanced Techniques

* **Raw Socket Implementation** - Uses raw sockets for direct packet crafting at the kernel level
* **Variable TCP Options** - Random TCP options (MSS, Window Scale, Timestamp, SACK_PERM)
* **Realistic Packet Structure** - Properly formatted IP and TCP headers with correct checksums
* **BGP Payload Generation** - Realistic BGP OPEN messages for amplification attacks
* **Thread-Safe Operations** - Atomic counters and thread-local storage for safe concurrent execution
* **Socket Pooling** - Creates up to 5,000 raw sockets per thread for maximum throughput

---

## 🎮 Attack Modes

### Standard SYN-ACK Flood

Generates TCP SYN-ACK packets (both SYN=1 and ACK=1 flags set):

```bash
sudo ./amp <target_ip> <target_port> <threads> <duration> <max_pps>
```

### BGP Amplification Mode

Adds BGP OPEN message payload (79 bytes) for amplification attacks:

```bash
sudo ./amp <target_ip> 179 <threads> <duration> <max_pps> --bgp
```

**BGP Amplification:**
* Targets BGP port 179 (or any port with `--bgp` flag)
* Adds BGP OPEN message payload (79 bytes)
* Increases packet size from ~60 bytes to ~140 bytes
* Creates amplification effect (larger responses from BGP routers)
* Useful for testing BGP router resilience

### SOCKS5 Proxy Mode

Routes traffic through SOCKS5 proxies:

```bash
sudo ./amp <target_ip> <target_port> <threads> <duration> <max_pps> --socks5
```

### Combined Modes

BGP Amplification + SOCKS5 Proxy:

```bash
sudo ./amp <target_ip> 179 <threads> <duration> <max_pps> --socks5 --bgp
```

---

## 🚀 Quick Start

### Prerequisites

* Linux operating system
* GCC compiler
* Root privileges (for raw sockets)
* pthread library

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd Methods/L4/TCP/AMP

# Build
make

# (Optional) Install system-wide
sudo make install
```

### Basic Usage

```bash
sudo ./amp <target_ip> <target_port> <threads> <duration> <max_pps> [--socks5] [--bgp]
```

---

## 📖 Usage

### Basic Syntax

```bash
sudo ./amp <target_ip> <target_port> <threads> <duration> <max_pps> [--socks5] [--bgp]
```

### Parameters

| Parameter    | Description                                    | Example        |
|--------------|------------------------------------------------|----------------|
| `target_ip`  | Target server IP address                       | `192.168.1.100`|
| `target_port`| Target TCP port                                | `80`, `443`, `179` (BGP) |
| `threads`    | Number of worker threads (1-10000)            | `300`          |
| `duration`   | Attack duration in seconds                     | `60`           |
| `max_pps`    | Maximum packets per second                     | `100000`       |
| `--socks5`   | (Optional) Enable SOCKS5 proxy mode           | `--socks5`     |
| `--bgp`      | (Optional) Enable BGP amplification            | `--bgp`        |

### Examples

#### Basic SYN-ACK Flood

```bash
sudo ./amp 192.168.1.100 80 300 60 100000
```

This command:
* Targets `192.168.1.100:80`
* Uses 300 threads
* Runs for 60 seconds
* Limits to 100,000 packets per second
* Sends SYN-ACK packets (both SYN and ACK flags set)

#### With BGP Amplification

```bash
sudo ./amp 192.168.1.100 179 500 120 200000 --bgp
```

**BGP Amplification Mode:**
* Targets BGP port 179
* Adds BGP OPEN message payload (79 bytes)
* Increases packet size for amplification effect
* Useful for testing BGP router resilience
* **Note:** BGP payload is automatically added when `--bgp` flag is set

#### With SOCKS5 Proxies

1. Create a `socks5.txt` file with proxy list:
```
proxy1.example.com:1080:username:password
proxy2.example.com:1080
192.168.1.50:1080:user:pass
```

2. Run with proxy support:
```bash
sudo ./amp 192.168.1.100 443 500 120 200000 --socks5
```

#### Combined: BGP Amplification + SOCKS5

```bash
sudo ./amp 192.168.1.100 179 500 120 200000 --socks5 --bgp
```

#### High-Intensity Attack

```bash
sudo ./amp 10.0.0.1 22 1000 300 500000
```

**Warning**: High thread counts (>500) and PPS rates (>200k) may cause system instability.

For more examples, see [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md)

---

## 🔨 Building

### Quick Build

```bash
cd AMP
make
```

### Manual Build

```bash
gcc -O3 -Wall -pthread -o amp amp.c
```

### Clean Build Artifacts

```bash
make clean
```

**Note:** Requires root privileges for raw sockets.

---

## 📚 Documentation

| Document                                 | Description                                    | Location                    |
| ---------------------------------------- | ---------------------------------------------- | --------------------------- |
| **README.md**                            | Attack overview, usage, and features           | AMP/README.md               |
| **USAGE_EXAMPLES.md**                    | Practical usage examples and scenarios         | AMP/USAGE_EXAMPLES.md       |
| **ARCHITECTURE.md**                      | Technical architecture and implementation      | AMP/ARCHITECTURE.md         |
| **CHANGELOG.md**                         | Version history and changes                    | AMP/CHANGELOG.md            |
| **CONTRIBUTING.md**                      | Contribution guidelines                        | AMP/CONTRIBUTING.md         |
| **SECURITY.md**                          | Security policy and vulnerability reporting    | AMP/SECURITY.md             |
| **DEPLOYMENT.md**                        | Deployment instructions                        | AMP/DEPLOYMENT.md           |

---

## 🛡️ Protection Strategies

### Quick Protection Setup

```bash
# 1. Install dependencies
sudo apt-get install iptables-persistent

# 2. Apply protection rules
sudo iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK \
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
   * DDoS mitigation appliances
   * Load balancers with DDoS protection

2. **Cloud Services:**
   * Cloudflare DDoS Protection
   * AWS Shield
   * Google Cloud Armor

3. **Custom Solutions:**
   * eBPF/XDP filters
   * Custom kernel modules
   * Distributed filtering

### Protection Considerations

This tool is designed to test protection systems:

* ✅ Signature-based filtering (variable patterns)
* ✅ Rate limiting (variable delays)
* ✅ TCP state tracking (SYN-ACK packets)
* ✅ BGP router resilience (amplification attacks)

**For defenders:** Implement multi-layer protection including:
* Rate limiting per IP
* Connection state validation
* Anomaly detection
* DDoS protection services
* Behavioral analysis
* Machine learning-based detection

---

## 🔍 Detection & Analysis

### Attack Signatures

The SYN-ACK flood attack has unique signatures that can be detected:

1. **SYN-ACK Packets** - Both SYN and ACK flags set simultaneously
2. **BGP Payload** - 79-byte BGP OPEN messages (when `--bgp` flag is used)
3. **Spoofed Source IPs** - IPs from various network ranges
4. **High Packet Rate** - Sustained high PPS from multiple sources
5. **TCP Options** - MSS, Window Scale, Timestamp, SACK_PERM options

### Detection Tools

* **tcpdump** - Packet capture and analysis
* **Wireshark** - Deep packet inspection
* **Suricata/Snort** - IDS/IPS with custom rules
* **Custom Python scripts** - Deep packet inspection
* **eBPF/XDP** - Kernel-level filtering

### Monitoring Commands

```bash
# Monitor TCP SYN-ACK packets
tcpdump -i eth0 -n 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'

# Detect high packet rate
timeout 1 tcpdump -i eth0 -n 'tcp' 2>/dev/null | wc -l

# Analyze top source IPs
tcpdump -i eth0 -n 'tcp' | \
    awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head -10

# Check for BGP payloads
tcpdump -i eth0 -n -c 1000 -w capture.pcap 'tcp port 179'
tshark -r capture.pcap -T fields -e ip.src -e tcp.payload
```

---

## 📊 Performance

### Performance Benchmarks

Typical performance on modern hardware:

| Threads | PPS      | CPU Usage | Memory | BGP Payload |
|---------|----------|-----------|--------|-------------|
| 300     | 100k     | 45%       | 250MB  | No          |
| 500     | 200k     | 70%       | 400MB  | No          |
| 1000    | 400k     | 95%       | 800MB  | No          |
| 300     | 80k      | 50%       | 300MB  | Yes         |
| 500     | 150k     | 75%       | 500MB  | Yes         |
| 1000    | 300k     | 98%       | 1GB    | Yes         |

*Results vary by hardware and network conditions*

### Attack Statistics

| Metric                    | Value             |
| ------------------------- | ----------------- |
| **Layer**                 | L4 (Transport)    |
| **Protocol**              | TCP               |
| **Complexity**            | Medium            |
| **Detection Difficulty**  | Medium            |
| **Mitigation Difficulty** | Medium            |
| **Typical PPS**           | 100,000 - 500,000 |
| **Packet Size**           | ~60-140 bytes     |
| **Thread Support**        | Up to 10,000      |
| **Sockets Per Thread**    | Up to 5,000       |

---

## 🌐 BGP Amplification

### How BGP Amplification Works

1. **BGP Protocol**: Border Gateway Protocol (BGP) is used for routing between autonomous systems
2. **Amplification**: BGP routers can send large responses to small requests
3. **Attack Vector**: Spoofed SYN-ACK packets with BGP payloads trigger responses
4. **Amplification Factor**: BGP responses can be 10-100x larger than requests

### When to Use BGP Amplification

* **Target**: BGP routers (typically port 179)
* **Goal**: Amplify attack traffic using BGP protocol responses
* **Effect**: Larger responses consume more bandwidth on target

### BGP Payload Structure

The tool generates realistic BGP OPEN messages:

```
┌─────────────────────────────────────────────────────────┐
│ BGP Payload (79 bytes, if --bgp flag)                    │
│                                                           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ BGP Marker (16 bytes): 0xFF repeated                 │ │
│ │ Length (2 bytes): 79                                 │ │
│ │ Type: OPEN (1)                                       │ │
│ │ Version: 4                                           │ │
│ │ AS Number (2 bytes)                                  │ │
│ │ Hold Time (2 bytes)                                   │ │
│ │ BGP Identifier (4 bytes)                             │ │
│ │ Optional Parameters Length (1 byte)                  │ │
│ │ Optional Parameters (46 bytes)                       │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

* **Marker**: 16 bytes of 0xFF (BGP authentication)
* **Length**: Total message length (79 bytes)
* **Type**: OPEN message (type 1)
* **Version**: BGP version 4
* **AS Number**: Random autonomous system number
* **Hold Time**: 180 seconds (standard)
* **BGP Identifier**: Spoofed IP address
* **Optional Parameters**: BGP capabilities (multiprotocol extensions)

### Packet Structure

```
┌─────────────────────────────────────────────────────────┐
│ IP Header (20 bytes)                                     │
│ - Version: 4                                             │
│ - IHL: 5                                                 │
│ - TTL: 64/128/255 (realistic distribution)             │
│ - Protocol: TCP (6)                                      │
│ - Source: Spoofed IP                                     │
│ - Destination: Target IP                                │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│ TCP Header (20-60 bytes)                                 │
│ - Source Port: Random (1024-65535)                      │
│ - Destination Port: Target Port                         │
│ - Flags: SYN=1, ACK=1, FIN=0, RST=0, PSH=0, URG=0       │
│ - Sequence Number: Random/Calculated                     │
│ - Acknowledgment Number: Calculated (not 0)              │
│ - Window Size: 8192-65535                                │
│ - Data Offset: 5-15 (variable)                           │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│ TCP Options (0-40 bytes)                                 │
│ - MSS (4 bytes): 536, 1024, 1440, 1460, 1500            │
│ - Window Scaling (3 bytes): 0-14                        │
│ - Timestamp (10 bytes): Current time + random           │
│ - SACK_PERM (2 bytes)                                    │
│ - NOP padding (to align to 4-byte boundary)              │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│ BGP Payload (79 bytes, if --bgp flag)                    │
│ - BGP Marker (16 bytes): 0xFF repeated                   │
│ - Length (2 bytes): 79                                   │
│ - Type: OPEN (1)                                         │
│ - Version: 4                                             │
│ - AS Number (2 bytes)                                    │
│ - Hold Time (2 bytes)                                    │
│ - BGP Identifier (4 bytes)                               │
│ - Optional Parameters (46 bytes)                         │
└─────────────────────────────────────────────────────────┘
Total Packet Size: ~60-140 bytes (with BGP payload)
```

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Make** your changes
4. **Test** thoroughly
5. **Commit** with clear messages
6. **Push** to your fork
7. **Open** a Pull Request

### Contribution Areas

* ✅ **New Attack Methods** - Implement additional attack vectors
* ✅ **Bypass Techniques** - Improve evasion methods
* ✅ **Protection Strategies** - Improve defense mechanisms
* ✅ **Detection Signatures** - Add new detection methods
* ✅ **Documentation** - Improve or translate documentation
* ✅ **Performance** - Optimize existing code
* ✅ **Testing** - Add test cases and validation

---

## 📝 Code of Conduct

* **Respect** others' work and contributions
* **Use** tools responsibly and legally
* **Report** security vulnerabilities responsibly
* **Follow** ethical hacking principles

---

## 📈 Roadmap

### Current Release

* ✅ **TCP-AMP v1.0.0** - SYN-ACK flood with BGP amplification

### Planned Updates

* **Enhanced BGP Payloads** - Additional BGP message types
* **Performance Optimizations** - Further speed improvements
* **Additional Amplification Methods** - DNS, NTP, etc.
* **Protection Scripts** - Automated protection implementation
* **Monitoring Dashboard** - Web-based monitoring interface

### Future Enhancements

* Machine learning-based detection evasion
* Distributed attack coordination
* Additional protection guides
* Multi-language documentation

---

## 📄 License

This project is licensed under the **MIT License** - see the LICENSE file for details.

**Important:** The license does not grant permission to use these tools illegally. Users are responsible for compliance with all applicable laws.

---

## 🙏 Acknowledgments

* Security researchers who documented attack methods
* Open-source community contributions
* Protection guide authors
* Contributors to BGP protocol documentation

---

## 📞 Support & Resources

### Getting Help

* **Issues:** Open an issue on GitHub
* **Documentation:** Check the documentation files
* **Examples:** See `USAGE_EXAMPLES.md`

### Additional Resources

* [RFC 793 - TCP Protocol](https://tools.ietf.org/html/rfc793)
* [RFC 4271 - BGP Protocol](https://tools.ietf.org/html/rfc4271)
* [RFC 1323 - TCP Extensions](https://tools.ietf.org/html/rfc1323)
* [Linux Raw Sockets](https://man7.org/linux/man-pages/man7/raw.7.html)
* [SOCKS5 Protocol](https://tools.ietf.org/html/rfc1928)

---

## 🔧 Troubleshooting

### Permission Denied

```bash
# Ensure running as root
sudo ./amp <target> <port> <threads> <duration> <pps>
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

### BGP Amplification Not Working

1. Ensure `--bgp` flag is set
2. Target BGP port 179 for best results
3. Verify BGP payload is being added (check packet size)
4. BGP routers must be accessible and responding

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

---

**Remember**: Only use this tool on systems you own or have explicit written permission to test. Unauthorized network attacks are illegal.

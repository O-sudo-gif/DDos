# TCP-RAPE: Multi-Vector TCP Attack Tool

> **Multi-vector TCP flood attack implementation with comprehensive bypass techniques and protection strategies**

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
* [Bypass Techniques](#-bypass-techniques)
* [Quick Start](#-quick-start)
* [Usage](#-usage)
* [Building](#-building)
* [Documentation](#-documentation)
* [Protection Strategies](#-protection-strategies)
* [Detection & Analysis](#-detection--analysis)
* [Performance](#-performance)
* [Contributing](#-contributing)
* [Roadmap](#-roadmap)
* [License](#-license)

---

## 🎯 Overview

This repository provides a **multi-vector TCP attack tool** that combines multiple attack techniques to maximize server impact. The tool implements various TCP flood attacks simultaneously to overwhelm target servers.

**Current Release:** TCP-RAPE v2.0.0 - Clever Bypass Edition

> **Note:** This tool implements advanced bypass techniques inspired by modern attack methodologies to evade detection systems.

---

## 📦 What's Included

* ✅ **rape.c** - High-performance multi-vector TCP attack implementation
* ✅ **Elite Bypass Mode** - Full connection simulation for advanced protection systems
* ✅ **Stealth Mode** - Maximum bypass with HTTP payloads and OS fingerprinting
* ✅ **Clever Bypass Techniques** - Variable options, SYN-first simulation, IP ID patterns
* ✅ **Protection Guides** - Comprehensive defense strategies
* ✅ **Usage Examples** - Practical scenarios and use cases
* ✅ **Build System** - Makefile for easy compilation
* ✅ **Documentation** - Complete technical documentation

---

## 📁 Repository Structure

```
RAPE/
├── rape.c                          # Main attack implementation
├── README.md                       # This file
├── USAGE_EXAMPLES.md               # Usage examples
├── CHANGELOG.md                    # Version history
├── CONTRIBUTING.md                 # Contribution guidelines
├── SECURITY.md                     # Security policy
├── DEPLOYMENT.md                   # Deployment instructions
├── Makefile                        # Build configuration
├── LICENSE                         # MIT License
└── .gitignore                     # Git ignore rules
```

---

## 🔥 Features

### Multi-Vector Attack Capabilities

* ✅ **SYN Flood** - Connection queue exhaustion
* ✅ **ACK Flood** - Resource consumption attacks
* ✅ **FIN Flood** - Connection termination floods
* ✅ **RST Flood** - Connection reset attacks
* ✅ **PSH Flood** - Push flag floods
* ✅ **URG Flood** - Urgent flag floods
* ✅ **SYN-ACK Flood** - Combined SYN+ACK attacks
* ✅ **FIN-ACK Flood** - Combined FIN+ACK attacks
* ✅ **Mixed Flags** - Random flag combinations to confuse state machines
* ✅ **ALL Mode** - Rotates through all attack types automatically

### Advanced Techniques

* **IP Spoofing** - Generates spoofed source IPs across multiple ranges
* **Variable TCP Options (0-20 bytes)** - Clever bypass to avoid 40-byte detection patterns
* **Variable TCP Header Size (doff 5-15)** - Avoids fixed header size detection
* **SYN-First Simulation** - Establishes connection state before sending data packets
* **Rate Limiting Bypass** - Variable micro-delays (10-100μs) to avoid detection
* **IP ID Patterns Per Connection** - Incremental IP IDs matching real OS behavior
* **SACK Blocks** - Includes SACK_PERM and SACK blocks for established connections
* **Variable Payload Sizes** - Random payload generation to avoid pattern detection
* **Connection State Confusion** - Mixed flag combinations
* **Multi-threading** - Supports up to 10,000 concurrent threads per worker
* **Real-time Statistics** - Live monitoring of all packet types

### Clever Bypass Techniques (Inspired by ack.c)

The tool implements advanced bypass techniques designed to evade detection:

* ✅ **Variable TCP Options (0-20 bytes)** - Avoids 40-byte detection signatures
* ✅ **Variable TCP Header Size** - Dynamic doff (5-15) instead of fixed size
* ✅ **SYN-First Connection Establishment** - Sends SYN packets first (30-40% chance) to establish proper connection state
* ✅ **Variable Payload Sizes** - Most ACK packets have no payload (70% chance), variable sizes (0-1420 bytes)
* ✅ **Random Payload Regeneration** - Avoids 0xFF pattern detection
* ✅ **IP ID Patterns Per Connection** - Incremental IP IDs per connection hash
* ✅ **SACK Blocks for Established Connections** - Rarely includes SACK blocks (5% chance)
* ✅ **Rate Limiting Bypass** - Micro-delays (10-100μs) every 50-200 packets

---

## 🎮 Attack Modes

### `all` (Default)
Rotates through all attack types automatically:
* SYN → ACK → FIN → RST → PSH → URG → SYN-ACK → FIN-ACK → MIXED

### `syn`
Pure SYN flood attack - exhausts connection queue

### `ack`
ACK flood - consumes server resources processing ACK packets

### `fin`
FIN flood - attempts to close connections

### `rst`
RST flood - resets connections

### `psh`
PSH flood - push flag attacks

### `urg`
URG flood - urgent flag attacks

### `synack`
SYN-ACK flood - simulates established connections

### `finack`
FIN-ACK flood - connection termination attacks

### `mixed`
Random flag combinations - confuses TCP state machines

---

## 🛡️ Bypass Techniques

### Elite Mode (`--elite`)

Enables sophisticated bypass techniques designed to evade:

* ✅ **Cloudflare** - Full connection simulation, realistic patterns
* ✅ **AWS Shield** - Behavioral analysis bypass
* ✅ **Machine Learning Detection** - Human-like timing patterns
* ✅ **Behavioral Analysis** - Realistic connection lifecycles
* ✅ **Deep Packet Inspection** - Protocol-compliant packets
* ✅ **Stateful Firewalls** - Full 3-way handshake simulation
* ✅ **WAF (Web Application Firewall)** - Realistic payload patterns
* ✅ **Anomaly Detection** - Normal-looking traffic patterns

**Elite Mode Features:**
* Full 3-way handshake simulation (SYN → SYN-ACK → ACK)
* Connection state tracking (100,000+ concurrent connections)
* Realistic sequence number progression
* Behavioral timing patterns (human-like delays)
* TTL randomization based on IP ranges
* Window scaling that matches OS patterns
* Realistic payload patterns

### Stealth Mode (`--stealth`)

Maximum bypass mode (includes all Elite features +):

* ✅ **HTTP-like payloads** - Bypasses WAF and DPI
* ✅ **OS fingerprinting evasion** - TTL, ports, window sizes match real OS
* ✅ **Human timing patterns** - Burst patterns with pauses
* ✅ **Cloud/CDN IP ranges** - Uses AWS, Google, Cloudflare IP ranges
* ✅ **Retransmission simulation** - 1% retransmission rate
* ✅ **Keep-alive patterns** - Simulates persistent connections
* ✅ **Realistic packet distribution** - 70% ACK, 20% PSH, 2% FIN
* ✅ **Incremental IP IDs** - OS-specific IP ID patterns
* ✅ **QoS TOS values** - Realistic Type of Service bits

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
cd TCP/RAPE

# Build
make

# (Optional) Install system-wide
sudo make install
```

### Basic Usage

```bash
sudo ./rape <target_ip> <target_port> <threads> <duration> <max_pps> [attack_mode] [--elite] [--stealth]
```

---

## 📖 Usage

### Basic Syntax

```bash
sudo ./rape <target_ip> <target_port> <threads> <duration> <max_pps> [attack_mode] [--elite] [--stealth]
```

### Parameters

* `target_ip` - Target server IP address
* `target_port` - Target TCP port (e.g., 80, 443, 22)
* `threads` - Number of worker threads (1-10000, recommended: 300-500)
* `duration` - Attack duration in seconds
* `max_pps` - Maximum packets per second (e.g., 100000)
* `attack_mode` - (Optional) Attack type: `syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `synack`, `finack`, `mixed`, `all` (default: `all`)
* `--elite` - (Optional) Enable elite bypass mode for advanced protection systems
* `--stealth` - (Optional) Enable stealth mode for maximum bypass (includes elite features + HTTP payloads, OS fingerprinting)

### Examples

#### All-Attack Mode (Recommended)
```bash
# Rotates through all attack types automatically
sudo ./rape 192.168.1.100 80 500 60 200000 all
```

#### Elite Mode (Bypass Advanced Protections)
```bash
# Elite mode with full connection simulation
sudo ./rape 192.168.1.100 80 500 300 200000 all --elite
```

#### Stealth Mode (Maximum Bypass - Recommended)
```bash
# Stealth mode: Maximum bypass with HTTP payloads and OS fingerprinting
sudo ./rape 192.168.1.100 80 500 300 200000 all --stealth
```

#### SYN Flood Only
```bash
sudo ./rape 192.168.1.100 80 300 60 100000 syn
```

#### ACK Flood Only
```bash
sudo ./rape 192.168.1.100 443 300 60 100000 ack
```

#### Mixed Flags Attack
```bash
# Random flag combinations to confuse state machines
sudo ./rape 192.168.1.100 80 400 120 150000 mixed
```

#### High-Intensity Attack
```bash
sudo ./rape 192.168.1.100 80 1000 300 500000 all
```

For more examples, see [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md)

---

## 🔨 Building

### Quick Build
```bash
cd RAPE
make
```

### Manual Build
```bash
gcc -O3 -Wall -Wno-unused-result -pthread -o rape rape.c
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
| **README.md**                            | Attack overview, usage, and features           | RAPE/README.md              |
| **USAGE_EXAMPLES.md**                    | Practical usage examples and scenarios         | RAPE/USAGE_EXAMPLES.md      |
| **CHANGELOG.md**                         | Version history and changes                    | RAPE/CHANGELOG.md           |
| **CONTRIBUTING.md**                      | Contribution guidelines                        | RAPE/CONTRIBUTING.md        |
| **SECURITY.md**                          | Security policy and vulnerability reporting    | RAPE/SECURITY.md            |
| **DEPLOYMENT.md**                        | Deployment instructions                        | RAPE/DEPLOYMENT.md          |

---

## 🛡️ Protection Strategies

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

This tool is designed to bypass common protections:

* ✅ Signature-based filtering (variable patterns)
* ✅ Rate limiting (variable delays)
* ✅ TCP state tracking (mixed flags)
* ✅ Single-vector protections (multi-vector approach)
* ✅ **Elite Mode:** Advanced protection systems (Cloudflare, AWS Shield, ML detection)

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

The multi-vector attack has unique signatures that can be detected:

1. **Variable TCP Options (0-20 bytes)** - Clever bypass technique
2. **Variable TCP Header Size (doff 5-15)** - Dynamic header size
3. **SYN-First Patterns** - SYN packets before data packets
4. **Variable Payload Sizes** - Random payload generation
5. **IP ID Patterns** - Incremental IP IDs per connection
6. **SACK Blocks** - Rare SACK blocks in established connections
7. **Multiple Attack Types** - Rotation through SYN, ACK, FIN, RST, etc.

### Detection Tools

* **tcpdump** - Packet capture and analysis
* **Wireshark** - Deep packet inspection
* **Suricata/Snort** - IDS/IPS with custom rules
* **Custom Python scripts** - Deep packet inspection
* **eBPF/XDP** - Kernel-level filtering

### Monitoring Commands

```bash
# Monitor TCP packets
tcpdump -i eth0 -n 'tcp'

# Detect high packet rate
timeout 1 tcpdump -i eth0 -n 'tcp' 2>/dev/null | wc -l

# Analyze top source IPs
tcpdump -i eth0 -n 'tcp' | \
    awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head -10

# Check for variable TCP options
tcpdump -i eth0 -n -c 1000 -w capture.pcap 'tcp'
tshark -r capture.pcap -T fields -e ip.src -e tcp.options
```

---

## 📊 Performance

### Performance Benchmarks

Typical performance on modern hardware:

| Threads | PPS  | CPU Usage | Memory | Attack Types |
|---------|------|-----------|--------|--------------|
| 300     | 100k | 45%       | 250MB  | All          |
| 500     | 200k | 70%       | 400MB  | All          |
| 1000    | 400k | 95%       | 800MB  | All          |

*Results vary by hardware and network conditions*

### Attack Statistics

| Metric                    | Value             |
| ------------------------- | ----------------- |
| **Layer**                 | L4 (Transport)    |
| **Protocol**              | TCP               |
| **Complexity**            | High              |
| **Detection Difficulty**  | High (with bypass)|
| **Mitigation Difficulty** | High              |
| **Typical PPS**           | 100,000 - 500,000 |
| **Packet Size**           | ~60-1500 bytes    |
| **Thread Support**        | Up to 10,000      |
| **Sockets Per Thread**    | Up to 10,000      |

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

* ✅ **TCP-RAPE v2.0.0** - Multi-vector attack with clever bypass techniques

### Planned Updates

* **Enhanced Bypass Techniques** - Additional evasion methods
* **Performance Optimizations** - Further speed improvements
* **Additional Attack Modes** - New attack vectors
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
* Contributors to bypass techniques

---

## 📞 Support & Resources

### Getting Help

* **Issues:** Open an issue on GitHub
* **Documentation:** Check the documentation files
* **Examples:** See `USAGE_EXAMPLES.md`

### Additional Resources

* RFC 793 - TCP Protocol
* OWASP DDoS Protection
* CERT DDoS Guide

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

## ⚠️ Responsible Disclosure

If you discover a vulnerability in protection mechanisms:

1. **Do not** exploit it publicly
2. **Contact** repository maintainers privately
3. **Allow** time for fix implementation
4. **Follow** responsible disclosure practices

---

## 📌 Important Notes

* ⚠️ **Always test on your own infrastructure**
* ⚠️ **Never attack systems without authorization**
* ⚠️ **Understand local laws** regarding network attacks
* ⚠️ **Use responsibly** for security research and testing

---

**Remember:** With great power comes great responsibility. Use these tools ethically and legally.

---

**Made with ❤️ for security research and education**

⬆ [Back to Top](#-table-of-contents)

---

## 📌 Current Status

**Active Development** - TCP-RAPE v2.0.0 is complete and ready for use.

**Features:**
* Multi-vector attack capabilities
* Elite bypass mode for advanced protections
* Stealth mode for maximum bypass
* Clever bypass techniques inspired by modern methodologies

**Stay tuned for updates!** 🚀

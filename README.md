# DDoS Methods & Protection Repository

> **TCP ACK Flood attack implementation with comprehensive protection strategies**

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

This repository provides a **TCP ACK Flood attack** implementation along with detailed **protection guides** to help security professionals:

- **Understand** how TCP ACK flood attacks work
- **Test** network infrastructure resilience against ACK floods
- **Implement** effective countermeasures and detection
- **Learn** about attack signatures and protection methods

**Current Release:** TCP ACK Flood (`ack.c`)

> **Note:** More attack methods will be added incrementally as updates to this repository.

---

## 📦 What's Included

- ✅ **ack.c** - High-performance TCP ACK flood implementation
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
│       └── ACK/                               # TCP ACK Flood Attack
│           ├── ack.c                          # Attack implementation
│           ├── README.md                      # Attack documentation
│           ├── ARCHITECTURE.md                # Technical architecture
│           ├── USAGE_EXAMPLES.md              # Usage examples
│           ├── Makefile                       # Build configuration
│           ├── LICENSE                        # MIT License
│           ├── socks5.txt.example             # SOCKS5 proxy example
│           ├── .gitignore                     # Git ignore rules
│           └── PROTECTION/                    # Protection guides
│               └── SIGNATURE_BASED_PROTECTION_GR.md  # Signature-based protection (Greek)
│
└── README.md                                  # This file
```

---

## 🔥 TCP ACK Flood Attack

### Description

The **TCP ACK Flood** attack sends a flood of TCP ACK (Acknowledgment) packets with spoofed source IPs and SACK (Selective Acknowledgment) blocks to overwhelm the target server.

### How It Works

```
┌─────────────┐          ┌──────────────┐         ┌─────────────┐
│  Attacker   │────────▶│    Spoofed   │────────▶│   Target    │
│             │          │     IPs      │         │    Server   │
└─────────────┘          └──────────────┘         └─────────────┘
     │                         │                        │
     │ 1. Generate spoofed IPs │                        │
     │ 2. Craft ACK packets    │                        │
     │ 3. Add SACK blocks      │                        │
     │ 4. Send flood           │───────────────────────▶│
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

### Attack Signatures

The attack can be identified by these unique signatures:

1. **TCP Data Offset = 15** (60 bytes header) - Very unusual in legitimate traffic
2. **40 bytes TCP Options** - Specific pattern (MSS → Window → Timestamp → SACK_PERM → SACK blocks)
3. **0xFF Payload Pattern** - 1420 bytes all set to 0xFF
4. **Pure ACK Packets** - Only ACK flag set, no SYN/FIN/RST

### Impact

- ⚠️ **Resource Exhaustion** - Server processes invalid ACK packets
- ⚠️ **Bandwidth Consumption** - High packet rate consumes network bandwidth
- ⚠️ **Service Degradation** - Can cause slowdowns or complete outage
- ⚠️ **Connection Queue Overflow** - May fill connection tracking tables

---

## 🛡️ Protection Strategies

### Multi-Layer Defense Approach

Effective DDoS protection requires **multiple layers** of defense:

```
┌─────────────────────────────────────────┐
│  Layer 1: Network-Level Filtering      │
│  - iptables/nftables rules             │
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
│  - WAF (Web Application Firewall)      │
│  - Request validation                   │
│  - Rate limiting per endpoint           │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│  Layer 4: DDoS Protection Services     │
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
git clone https://github.com/o-sudo-gif/ddos-methods.git
cd ddos-methods/Methods/L4/TCP/ACK

# Build ACK flood tool
make

# Or manually compile
gcc -o ack ack.c -lpthread -O3 -Wall
```

### Usage

```bash
# Basic syntax (requires root)
sudo ./ack <target_ip> <target_port> <threads> <duration> <max_pps> [--socks5]

# Example: Basic ACK flood
sudo ./ack 192.168.1.100 80 300 60 100000

# Example: With SOCKS5 proxies
sudo ./ack 192.168.1.100 443 500 120 200000 --socks5
```

**Parameters:**
- `target_ip` - Target server IP address
- `target_port` - Target TCP port (e.g., 80, 443, 22)
- `threads` - Number of worker threads (1-10000, recommended: 200-500)
- `duration` - Attack duration in seconds
- `max_pps` - Maximum packets per second (e.g., 100000)
- `--socks5` - (Optional) Enable SOCKS5 proxy mode (requires `socks5.txt`)

**Example Output:**
```
[+] Starting 300 threads with PURE ACK FLOOD
[+] Target: 192.168.1.100:80
[+] Maximum PPS: 100000
[*] Attack: 100% ACK packets with SACK_PERM + SACK blocks (SLE & SRE)
[*] Rate limiter initialized: 100000 PPS (stable token bucket)
[*] Running for 60 seconds...

[LIVE] PPS: 98500 | Sent: 5910000 | Failed: 150 | Mbps: 78.80
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

The TCP ACK Flood implementation includes comprehensive documentation:

| Document                             | Description                                       | Location                                                 |
|--------------------------------------|---------------------------------------------------|----------------------------------------------------------|
| **README.md**                        | Attack overview, usage, and features              | `L4/TCP/ACK/README.md`                                   |
| **ARCHITECTURE.md**                  | Technical architecture and implementation details | `L4/TCP/ACK/ARCHITECTURE.md`                             |
| **SIGNATURE_BASED_PROTECTION_GR.md** | Signature-based protection guide (Greek)          | `L4/TCP/ACK/PROTECTION/SIGNATURE_BASED_PROTECTION_GR.md` |
| **USAGE_EXAMPLES.md**                | Practical usage examples and scenarios            | `L4/TCP/ACK/USAGE_EXAMPLES.md`                           |

### Protection Guides

- **English:** See `L4/TCP/ACK/README.md` for protection strategies
- **Greek (Ελληνικά):** See `L4/TCP/ACK/PROTECTION/SIGNATURE_BASED_PROTECTION_GR.md` for detailed protection guide

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

### Current Release

- ✅ **TCP ACK Flood** (`ack.c`) - Fully implemented with protection guides

### Planned Updates

More attack methods will be added incrementally:

- [ ] **TCP SYN Flood** - SYN flood attack implementation
- [ ] **UDP Flood** - UDP-based flood attacks
- [ ] **HTTP Flood** - Layer 7 HTTP flood attacks
- [ ] **Slowloris** - Slow HTTP attack
- [ ] **DNS Amplification** - DNS amplification attack
- [ ] **NTP Amplification** - NTP amplification attack

### Future Enhancements

- [ ] Automated protection scripts
- [ ] Web-based monitoring dashboard
- [ ] Machine learning-based detection
- [ ] Distributed attack coordination
- [ ] Additional protection guides

---

## ⚡ Performance Benchmarks

Typical performance on modern hardware:

| Attack    | Threads | PPS  | CPU Usage | Memory |
|-----------|---------|------|-----------|--------|
| ACK Flood | 300     | 100k | 40%       | 200MB  |


*Results vary by hardware and network conditions*

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

**Active Development** - TCP ACK Flood implementation is complete and ready for use.

**Next Updates:**
- More attack methods will be added as separate updates
- Each new attack will include its own implementation and protection guide
- Repository structure will expand organically

**Stay tuned for updates!** 🚀

</div>


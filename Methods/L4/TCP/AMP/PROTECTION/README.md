# Protection Guides

This directory contains protection guides and defense strategies for the TCP-AMP (SYN-ACK Flood + BGP Amplification) attack.

## Available Guides

### Signature-Based Protection (Greek)

**File:** `SIGNATURE_BASED_PROTECTION_GR.md`

Comprehensive guide in Greek (Ελληνικά) explaining how to implement signature-based filtering to protect against `amp.c` attacks.

**Topics covered:**
- Attack signatures identification
- BGP amplification detection
- iptables/nftables rules
- eBPF/XDP filters
- Python DPI scripts
- Suricata/Snort rules
- Complete protection scripts

## Protection Strategies

### 1. Signature-Based Filtering
The most effective method - identifies and blocks packets matching specific attack signatures:
- SYN-ACK flags (both SYN and ACK set)
- BGP payload (79 bytes BGP OPEN message)
- BGP marker (16 bytes 0xFF)
- BGP Type OPEN (0x01) and Version 4 (0x04)
- Packet size ~140 bytes (with BGP)

### 2. Rate Limiting
Limits SYN-ACK packets per second per IP address to prevent flooding.

### 3. BGP Router Hardening
Protects BGP routers from amplification attacks:
- BGP authentication (MD5)
- TTL security
- Rate limiting BGP connections
- BGP message validation

### 4. Connection State Validation
Only accepts packets from established TCP connections.

## Quick Protection Setup

```bash
# Block SYN-ACK packets with BGP payload
iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -m string --string "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    --algo bm --from 40 --to 60 \
    -m u32 --u32 "0>>22&0x3C@18&0xFF=0x01" \
    -j DROP

# Rate limit SYN-ACK packets
iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -m limit --limit 1000/sec --limit-burst 2000 \
    -j ACCEPT

iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -j DROP

# Protect BGP port 179
iptables -A INPUT -p tcp --dport 179 \
    -m limit --limit 10/min --limit-burst 5 \
    -j ACCEPT

iptables -A INPUT -p tcp --dport 179 -j DROP
```

For detailed protection guides, see the individual documentation files.


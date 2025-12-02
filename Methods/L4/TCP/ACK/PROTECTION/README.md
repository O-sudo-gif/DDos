# Protection Guides

This directory contains protection guides and defense strategies for the TCP ACK Flood attack.

## Available Guides

### Signature-Based Protection (Greek)

**File:** `SIGNATURE_BASED_PROTECTION_GR.md`

Comprehensive guide in Greek (Ελληνικά) explaining how to implement signature-based filtering to protect against `ack.c` attacks.

**Topics covered:**
- Attack signatures identification
- iptables/nftables rules
- eBPF/XDP filters
- Python DPI scripts
- Suricata/Snort rules
- Complete protection scripts

## Protection Strategies

### 1. Signature-Based Filtering
The most effective method - identifies and blocks packets matching specific attack signatures:
- TCP data offset = 15 (60 bytes header)
- 40 bytes TCP options pattern
- 0xFF payload pattern

### 2. Rate Limiting
Limits packets per second per IP address to prevent flooding.

### 3. Connection State Validation
Only accepts packets from established TCP connections.

### 4. Kernel Hardening
Optimizes kernel parameters for better resilience.

## Quick Protection Setup

```bash
# Block TCP packets with doff=15 (60 bytes header)
iptables -A INPUT -p tcp \
    -m u32 --u32 "0>>22&0x3C@12>>4&0xF=15" \
    -j DROP

# Block 0xFF payload pattern
iptables -A INPUT -p tcp \
    -m string --string "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    --algo bm --from 80 --to 1500 \
    -j DROP
```

For detailed protection guides, see the individual documentation files.


# Protection Guides

This directory contains protection guides and defense strategies for the TCP SYN Flood attack.

## Available Guides

### Signature-Based Protection (Greek)

**File:** `SIGNATURE_BASED_PROTECTION_GR.md`

Comprehensive guide in Greek (Ελληνικά) explaining how to implement signature-based filtering to protect against `syn.c` attacks.

**Topics covered:**
- Attack signatures identification
- iptables/nftables rules
- eBPF/XDP filters
- Python DPI scripts
- Suricata/Snort rules
- Complete protection scripts

## Protection Strategies

### 1. Rate Limiting (Primary Defense)
The most effective method for SYN floods - limits SYN packets per second:
- Legitimate traffic: ~10-100 SYN/sec per IP
- Attack traffic: 100k-500k SYN/sec total
- Recommended limit: 50 SYN/sec per IP

### 2. SYN Cookies
Kernel-level protection that prevents SYN backlog exhaustion:
```bash
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
```

### 3. Signature-Based Filtering
Identifies and blocks packets matching specific attack signatures:
- Large TCP options (doff > 10 = 40+ bytes header)
- MSS + Window Scale + Timestamp pattern
- Pure SYN packets with no payload

### 4. Connection State Validation
Only accepts packets from established TCP connections.

## Quick Protection Setup

```bash
# Rate limit SYN packets
iptables -A INPUT -p tcp --tcp-flags SYN SYN \
    -m limit --limit 50/sec --limit-burst 100 \
    -j ACCEPT

iptables -A INPUT -p tcp --tcp-flags SYN SYN \
    -j DROP

# Enable SYN cookies
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Block SYN with large TCP options (doff > 10)
iptables -A INPUT -p tcp --tcp-flags SYN SYN \
    -m u32 --u32 "0>>22&0x3C@12>>4&0xF>10" \
    -j DROP
```

For detailed protection guides, see the individual documentation files.


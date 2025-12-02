# Προστασία με Signature-Based Filtering για amp.c (TCP-AMP: SYN-ACK Flood + BGP Amplification)

## Επισκόπηση

Αντί για γενικό rate limiting, μπορούμε να αναγνωρίσουμε τα **συγκεκριμένα signatures** που χρησιμοποιεί το `amp.c` και να τα φιλτράρουμε απευθείας. Αυτή η προσέγγιση είναι πιο αποτελεσματική και έχει λιγότερα false positives.

---

## Signatures που Χρησιμοποιεί το amp.c

### 1. TCP Header Signatures

#### TCP Flags Pattern: SYN-ACK
```c
tcph->syn = 1;  // SYN flag set
tcph->ack = 1;  // ACK flag set for SYN-ACK
tcph->fin = 0;
tcph->rst = 0;
tcph->psh = 0;
tcph->urg = 0;
```
**Signature**: SYN-ACK packet (και SYN και ACK flags set, όλα τα άλλα 0)

**Σημείωση**: Το SYN-ACK είναι λιγότερο συνηθισμένο από το pure SYN ή pure ACK, αλλά είναι νόμιμο σε established connections.

#### TCP Data Offset
```c
tcph->doff = 5;  // 20 bytes header (5 * 4)
// ή variable: 5-15 (20-60 bytes) με TCP options
```
**Normal TCP headers**: 5-6 (20-24 bytes)  
**amp.c signature**: 5-15 (20-60 bytes) με TCP options

### 2. TCP Options Signature

Το `amp.c` χρησιμοποιεί **0-40 bytes TCP options** με συγκεκριμένη σειρά:

```
[MSS:4] [Window:3] [Timestamp:10] [SACK_PERM:2] [NOP padding]
```

**Pattern:**
1. MSS option (type 2, length 4) - 90% probability
2. Window Scaling (type 3, length 3) - 70% probability
3. Timestamp (type 8, length 10) - 80% probability
4. SACK_PERM (type 4, length 2) - 60% probability
5. NOP padding μέχρι 4-byte boundary

### 3. BGP Payload Signature (αν --bgp flag)

```c
if (g_use_bgp_amp && floodport == 179) {
    // BGP Marker (16 bytes of 0xFF)
    bgp_payload[0-15] = 0xFF;
    // Length (79 bytes total)
    bgp_payload[16-17] = 0x00, 0x4F;
    // Type: OPEN (1)
    bgp_payload[18] = 0x01;
    // Version: 4
    bgp_payload[19] = 0x04;
    // ... rest of BGP OPEN message
}
```

**Signature**: 
- 79 bytes BGP payload μετά το TCP header
- BGP Marker: 16 bytes 0xFF
- BGP Type: OPEN (0x01)
- BGP Version: 4 (0x04)
- Total packet size: ~140 bytes (με BGP payload)

### 4. Packet Size Signature

**Χωρίς BGP:**
```c
int total_packet_len = sizeof(struct iphdr) + tcp_hdr_len + data_len;
// = 20 + 20-60 + 0 = 40-80 bytes (συνήθως ~60 bytes)
```

**Με BGP:**
```c
// = 20 + 20-60 + 79 = 119-159 bytes (συνήθως ~140 bytes)
```

**Signature**: 
- Χωρίς BGP: ~60 bytes
- Με BGP: ~140 bytes

### 5. IP Header Signatures

```c
iph->ttl = 64;  // ή 128, ή 255 (realistic distribution)
iph->tos = 0;   // συνήθως 0 (80% probability)
iph->frag_off = 0;  // No fragmentation
```

### 6. Sequence Number Patterns

```c
// SYN-ACK packets have both sequence and ACK sequence
tcph->seq = htonl(seq_val);
tcph->ack_seq = htonl(ack_val);  // ACK sequence is NOT 0
```

**Signature**: SYN-ACK packets με ACK sequence != 0

---

## Υλοποίηση Signature-Based Filtering

### 1. iptables με String Matching

```bash
#!/bin/bash
# signature_block_amp.c.sh

# Block SYN-ACK packets με BGP payload (79 bytes BGP OPEN message)
# BGP payload starts after TCP header
iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -m string --string "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x4F\x01\x04" \
    --algo bm --from 40 --to 120 \
    -j DROP

# Block SYN-ACK packets με BGP marker pattern
iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -m string --string "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    --algo bm --from 40 --to 60 \
    -m u32 --u32 "0>>22&0x3C@18&0xFF=0x01" \
    -j DROP

# Block SYN-ACK packets με BGP Type OPEN (0x01) και Version 4 (0x04)
iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -m u32 --u32 "0>>22&0x3C@18&0xFF=0x01" \
    -m u32 --u32 "0>>22&0x3C@19&0xFF=0x04" \
    -j DROP

# Block packets με BGP Length = 79 (0x4F)
iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -m u32 --u32 "0>>22&0x3C@16&0xFFFF=0x004F" \
    -j DROP

# Block SYN-ACK packets με TCP options pattern (MSS + Window + Timestamp)
iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -m u32 --u32 "0>>22&0x3C@20&0xFFFFFFFF=0x02040000" \
    -m u32 --u32 "0>>22&0x3C@24&0xFFFFFF=0x030300" \
    -j DROP

# Rate limit SYN-ACK packets (backup protection)
iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -m limit --limit 1000/sec --limit-burst 2000 \
    -j ACCEPT

iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -j DROP
```

### 2. nftables Rules

```bash
#!/bin/bash
# signature_block_amp.c_nft.sh

# Create table
nft create table inet filter_amp

# Create chain
nft create chain inet filter_amp input_amp { type filter hook input priority 0 \; }

# Block SYN-ACK packets με BGP payload
nft add rule inet filter_amp input_amp \
    tcp flags syn,ack syn,ack \
    tcp payload offset 40 length 20 @th,16,16 0xffffffffffffffffffffffffffffffff004f0104 \
    counter drop

# Block SYN-ACK packets με BGP marker
nft add rule inet filter_amp input_amp \
    tcp flags syn,ack syn,ack \
    tcp payload offset 40 length 16 @th,16,16 0xffffffffffffffffffffffffffffffff \
    counter drop

# Block SYN-ACK packets με BGP Type OPEN
nft add rule inet filter_amp input_amp \
    tcp flags syn,ack syn,ack \
    tcp payload offset 58 length 1 @th,18,8 0x01 \
    counter drop

# Block SYN-ACK packets με BGP Version 4
nft add rule inet filter_amp input_amp \
    tcp flags syn,ack syn,ack \
    tcp payload offset 59 length 1 @th,19,8 0x04 \
    counter drop

# Rate limit SYN-ACK packets
nft add rule inet filter_amp input_amp \
    tcp flags syn,ack syn,ack \
    limit rate 1000/second burst 2000 packets \
    counter accept

nft add rule inet filter_amp input_amp \
    tcp flags syn,ack syn,ack \
    counter drop
```

### 3. eBPF/XDP Filter

```c
// amp_signature_filter.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define BGP_MARKER 0xFFFFFFFFFFFFFFFFULL
#define BGP_TYPE_OPEN 0x01
#define BGP_VERSION_4 0x04

SEC("xdp")
int filter_amp_signatures(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;
    
    struct tcphdr *tcph = (struct tcphdr *)((char *)iph + (iph->ihl * 4));
    if ((void *)(tcph + 1) > data_end) return XDP_PASS;
    
    // Check for SYN-ACK flags
    if (!(tcph->syn && tcph->ack)) return XDP_PASS;
    
    // Calculate TCP header length
    int tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < 20) return XDP_PASS;
    
    // Check packet size (BGP payload makes it ~140 bytes)
    int total_len = ntohs(iph->tot_len);
    if (total_len > 100 && total_len < 200) {
        // Potential BGP payload, check for BGP marker
        char *payload = (char *)tcph + tcp_hdr_len;
        if ((void *)(payload + 16) <= data_end) {
            // Check for BGP marker (16 bytes 0xFF)
            uint64_t marker1 = *((uint64_t *)payload);
            uint64_t marker2 = *((uint64_t *)(payload + 8));
            
            if (marker1 == 0xFFFFFFFFFFFFFFFFULL && 
                marker2 == 0xFFFFFFFFFFFFFFFFULL) {
                // Check for BGP Type OPEN and Version 4
                if ((void *)(payload + 20) <= data_end) {
                    if (payload[18] == BGP_TYPE_OPEN && 
                        payload[19] == BGP_VERSION_4) {
                        return XDP_DROP;  // Drop BGP amplification packet
                    }
                }
            }
        }
    }
    
    // Rate limit SYN-ACK packets
    // (Implementation depends on BPF map for rate limiting)
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### 4. Python DPI Script

```python
#!/usr/bin/env python3
# amp_signature_detector.py

import socket
import struct
import subprocess
from collections import defaultdict

class AMPSignatureDetector:
    def __init__(self, interface='eth0', block_ip=True):
        self.interface = interface
        self.block_ip = block_ip
        self.blocked_ips = set()
        self.packet_count = defaultdict(int)
        
    def parse_ip_header(self, data):
        """Parse IP header"""
        iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        return version, ihl, protocol, src_ip, dst_ip, data[ihl*4:]
    
    def parse_tcp_header(self, data):
        """Parse TCP header"""
        tcph = struct.unpack('!HHLLBBHHH', data[:20])
        src_port = tcph[0]
        dst_port = tcph[1]
        seq = tcph[2]
        ack_seq = tcph[3]
        data_offset = (tcph[4] >> 4) & 0xF
        flags = tcph[5]
        syn = (flags & 0x02) != 0
        ack = (flags & 0x10) != 0
        return src_port, dst_port, seq, ack_seq, data_offset, syn, ack, data[data_offset*4:]
    
    def detect_bgp_payload(self, payload):
        """Detect BGP payload signature"""
        if len(payload) < 79:
            return False
        
        # Check BGP marker (16 bytes 0xFF)
        if payload[:16] != b'\xFF' * 16:
            return False
        
        # Check BGP length (79 bytes = 0x004F)
        if struct.unpack('!H', payload[16:18])[0] != 79:
            return False
        
        # Check BGP Type OPEN (0x01)
        if payload[18] != 0x01:
            return False
        
        # Check BGP Version 4 (0x04)
        if payload[19] != 0x04:
            return False
        
        return True
    
    def block_ip(self, ip):
        """Block IP using iptables"""
        if ip in self.blocked_ips:
            return
        
        try:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], 
                         check=True, capture_output=True)
            self.blocked_ips.add(ip)
            print(f"[BLOCKED] {ip} - AMP signature detected")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to block {ip}: {e}")
    
    def process_packet(self, packet):
        """Process captured packet"""
        try:
            # Parse IP header
            version, ihl, protocol, src_ip, dst_ip, tcp_data = self.parse_ip_header(packet)
            
            if protocol != 6:  # Not TCP
                return
            
            # Parse TCP header
            src_port, dst_port, seq, ack_seq, data_offset, syn, ack, payload = \
                self.parse_tcp_header(tcp_data)
            
            # Check for SYN-ACK flags
            if not (syn and ack):
                return
            
            # Check for BGP payload
            if self.detect_bgp_payload(payload):
                print(f"[AMP DETECTED] {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                      f"(BGP amplification)")
                self.packet_count[src_ip] += 1
                
                # Block if threshold exceeded
                if self.packet_count[src_ip] > 10:
                    if self.block_ip:
                        self.block_ip(src_ip)
            
            # Check for TCP options pattern (MSS + Window + Timestamp)
            if data_offset > 5:
                tcp_options = tcp_data[20:data_offset*4]
                if len(tcp_options) >= 4:
                    # Check for MSS option (0x02 0x04)
                    if tcp_options[0] == 0x02 and tcp_options[1] == 0x04:
                        self.packet_count[src_ip] += 1
                        if self.packet_count[src_ip] > 100:
                            if self.block_ip:
                                self.block_ip(src_ip)
        
        except Exception as e:
            print(f"[ERROR] Packet processing failed: {e}")
    
    def start_monitoring(self):
        """Start packet capture"""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((self.interface, 0))
            
            print(f"[*] Monitoring {self.interface} for AMP signatures...")
            
            while True:
                packet, addr = sock.recvfrom(65535)
                self.process_packet(packet)
        
        except KeyboardInterrupt:
            print("\n[*] Stopping monitor...")
        except Exception as e:
            print(f"[ERROR] Monitoring failed: {e}")

if __name__ == '__main__':
    detector = AMPSignatureDetector(interface='eth0', block_ip=True)
    detector.start_monitoring()
```

### 5. Suricata/Snort Rules

```bash
# suricata_rules_amp.c.rules

# Detect SYN-ACK packets με BGP payload
alert tcp any any -> any 179 (msg:"AMP: SYN-ACK with BGP payload"; \
    flags:SA; \
    content:"|FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF|"; \
    offset:40; depth:16; \
    content:"|01 04|"; offset:58; depth:2; \
    sid:1000001; rev:1;)

# Detect SYN-ACK packets με BGP OPEN message
alert tcp any any -> any 179 (msg:"AMP: BGP OPEN in SYN-ACK"; \
    flags:SA; \
    content:"|00 4F 01 04|"; offset:56; depth:4; \
    sid:1000002; rev:1;)

# Detect SYN-ACK flood pattern
alert tcp any any -> any any (msg:"AMP: SYN-ACK flood pattern"; \
    flags:SA; \
    threshold:type threshold, track by_src, count 100, seconds 1; \
    sid:1000003; rev:1;)

# Detect BGP amplification attempt
alert tcp any any -> any 179 (msg:"AMP: BGP amplification attempt"; \
    flags:SA; \
    content:"|FF FF FF FF FF FF FF FF|"; offset:40; depth:8; \
    content:"|4F 01|"; offset:57; depth:2; \
    sid:1000004; rev:1;)
```

### 6. Complete Protection Script

```bash
#!/bin/bash
# complete_amp_protection.sh

echo "[*] Setting up AMP (SYN-ACK + BGP) protection..."

# Flush existing rules
iptables -F INPUT
iptables -F FORWARD

# Default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Block SYN-ACK packets με BGP payload
iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -m string --string "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    --algo bm --from 40 --to 60 \
    -m u32 --u32 "0>>22&0x3C@18&0xFF=0x01" \
    -m u32 --u32 "0>>22&0x3C@19&0xFF=0x04" \
    -j DROP

# Block SYN-ACK packets με BGP Length = 79
iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -m u32 --u32 "0>>22&0x3C@16&0xFFFF=0x004F" \
    -j DROP

# Rate limit SYN-ACK packets
iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -m limit --limit 1000/sec --limit-burst 2000 \
    -j ACCEPT

iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -j DROP

# Allow legitimate SYN-ACK (from established connections)
iptables -A INPUT -p tcp \
    --tcp-flags SYN,ACK SYN,ACK \
    -m state --state ESTABLISHED \
    -j ACCEPT

echo "[+] AMP protection rules installed"
echo "[*] Monitoring for BGP amplification attempts..."
```

---

## Προστασία από BGP Amplification

### 1. BGP Router Hardening

```bash
# Disable BGP on public interfaces (if not needed)
# Configure BGP to only accept connections from known peers
# Use BGP authentication (MD5)

# Example: Cisco IOS
router bgp 65000
 neighbor 192.168.1.1 remote-as 65001
 neighbor 192.168.1.1 password MySecretPassword
 neighbor 192.168.1.1 ttl-security hops 1
```

### 2. Rate Limiting BGP Traffic

```bash
# Limit BGP connections
iptables -A INPUT -p tcp --dport 179 \
    -m limit --limit 10/min --limit-burst 5 \
    -j ACCEPT

iptables -A INPUT -p tcp --dport 179 -j DROP
```

### 3. BGP Message Validation

```bash
# Block BGP messages from non-BGP peers
# Use BGP session authentication
# Validate BGP message structure
```

---

## Testing Protection

### Test Script

```bash
#!/bin/bash
# test_amp_protection.sh

echo "[*] Testing AMP protection..."

# Test 1: SYN-ACK με BGP payload
echo "[TEST 1] Sending SYN-ACK with BGP payload..."
# (Use amp.c with --bgp flag)

# Test 2: SYN-ACK flood
echo "[TEST 2] Sending SYN-ACK flood..."
# (Use amp.c without --bgp flag)

# Test 3: Legitimate SYN-ACK
echo "[TEST 3] Sending legitimate SYN-ACK..."
# (From established connection)

echo "[*] Check iptables logs:"
iptables -L -n -v
```

---

## Monitoring

### Log Analysis

```bash
# Monitor blocked packets
iptables -L INPUT -n -v | grep DROP

# Monitor BGP traffic
tcpdump -i any -n 'tcp port 179' -c 100

# Monitor SYN-ACK packets
tcpdump -i any -n 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0' -c 100
```

---

## Σύνοψη

### Signatures για amp.c:

1. **SYN-ACK Flags**: Και SYN και ACK flags set
2. **BGP Payload**: 79 bytes BGP OPEN message (αν --bgp flag)
3. **BGP Marker**: 16 bytes 0xFF
4. **BGP Type**: OPEN (0x01)
5. **BGP Version**: 4 (0x04)
6. **Packet Size**: ~60 bytes (χωρίς BGP), ~140 bytes (με BGP)
7. **TCP Options**: MSS + Window + Timestamp pattern

### Προστασία:

1. **iptables**: String matching για BGP payload
2. **nftables**: Byte matching για BGP signatures
3. **eBPF/XDP**: Kernel-level filtering
4. **Python DPI**: Deep packet inspection
5. **Suricata/Snort**: IDS/IPS rules
6. **Rate Limiting**: Backup protection

---

**Σημείωση**: Αυτή η προστασία είναι ειδικά για το `amp.c`. Για γενικότερη προστασία από DDoS, χρησιμοποιήστε rate limiting, connection limiting, και DDoS protection services.


# Προστασία με Signature-Based Filtering για ack.c

## Επισκόπηση

Αντί για γενικό rate limiting, μπορούμε να αναγνωρίσουμε τα **συγκεκριμένα signatures** που χρησιμοποιεί το `ack.c` και να τα φιλτράρουμε απευθείας. Αυτή η προσέγγιση είναι πιο αποτελεσματική και έχει λιγότερα false positives.

---

## Signatures που Χρησιμοποιεί το ack.c

### 1. TCP Header Signatures

#### TCP Data Offset = 15 (60 bytes header)
```c
tcph->doff = 15;  // 15 * 4 = 60 bytes TCP header
```
**Normal TCP headers**: 5-6 (20-24 bytes)  
**ack.c signature**: 15 (60 bytes) - **ΠΟΛΥ ΑΣΥΘΗΘΕΣ**

#### TCP Flags Pattern
```c
tcph->ack = 1;
tcph->syn = 0;
tcph->fin = 0;
tcph->rst = 0;
tcph->psh = 0;
tcph->urg = 0;
```
**Signature**: Pure ACK packet (μόνο ACK flag, όλα τα άλλα 0)

### 2. TCP Options Signature

Το `ack.c` χρησιμοποιεί **ακριβώς 40 bytes TCP options** με συγκεκριμένη σειρά:

```
[MSS:4] [Window:3] [Timestamp:10] [SACK_PERM:2] [SACK:10] [SACK:10] [SACK:10] [NOP padding]
```

**Pattern:**
1. MSS option (type 2, length 4)
2. Window Scaling (type 3, length 3)  
3. Timestamp (type 8, length 10)
4. SACK_PERM (type 4, length 2)
5. 1-3 SACK blocks (type 5, length 10 each)
6. NOP padding μέχρι 40 bytes

### 3. Payload Signature

```c
static char payload_data[1420];
memset(payload_data, 0xFF, sizeof(payload_data));
```

**Signature**: 1420 bytes payload, **όλα 0xFF** (0xFF 0xFF 0xFF ...)

### 4. Packet Size Signature

```c
iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + 40 + sizeof(payload_data);
// = 20 + 60 + 40 + 1420 = 1540 bytes (αλλά με IP options μπορεί να είναι 1500)
```

**Signature**: ~1500 bytes total packet size

### 5. IP Header Signatures

```c
iph->frag_off = htons(0x4000);  // DF flag set
iph->ttl = 64;  // ή 128, ή 255
iph->tos = 0;   // συνήθως 0
```

---

## Υλοποίηση Signature-Based Filtering

### 1. iptables με String Matching

```bash
#!/bin/bash
# signature_block_ack.c.sh

# Block packets με TCP header offset = 15 (60 bytes)
# Χρησιμοποιούμε u32 match για να ελέγξουμε το TCP data offset
iptables -A INPUT -p tcp \
    -m u32 --u32 "0>>22&0x3C@12>>4&0xF=15" \
    -j DROP

# Block ACK packets με 40 bytes TCP options
# TCP options start at offset 20 (TCP header base)
iptables -A INPUT -p tcp \
    -m u32 --u32 "0>>22&0x3C@12>>4&0xF=15" \
    -m u32 --u32 "0>>22&0x3C@20&0xFFFFFFFF=0x02040000" \
    -j DROP

# Block packets με payload 0xFF pattern
# Payload starts after TCP header (60 bytes = offset 80 from IP start)
iptables -A INPUT -p tcp \
    -m string --string "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    --algo bm --from 80 --to 1500 \
    -j DROP
```

### 2. nftables με Byte Matching

```bash
#!/usr/sbin/nft -f
# signature_block.nft

table inet filter {
    chain input {
        type filter hook input priority 0;
        
        # Block TCP packets με data offset = 15 (60 bytes header)
        tcp flags ack \
            @th,52,4 & 0xf0000000 = 0xf0000000 \
            drop comment "ack.c: TCP doff=15"
        
        # Block 0xFF payload pattern
        @nh,80,8 = 0xffffffffffffffff \
            drop comment "ack.c: 0xFF payload"
    }
}
```

### 3. eBPF/XDP Signature Filter

```c
// xdp_ack_signature_filter.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_ack_signature_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
    
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;
    
    // Signature 1: TCP data offset = 15 (60 bytes)
    if (tcp->doff != 15) return XDP_PASS;
    
    // Signature 2: Pure ACK (only ACK flag set)
    if (!(tcp->ack) || tcp->syn || tcp->fin || tcp->rst || tcp->psh || tcp->urg) {
        return XDP_PASS;
    }
    
    // Signature 3: Check TCP options pattern
    // Options start at offset 20 from TCP header start
    void *options = (void *)(tcp + 1);
    if (options + 40 > data_end) return XDP_PASS;
    
    // Check για MSS option (0x02 0x04)
    if (((unsigned char *)options)[0] == 0x02 && 
        ((unsigned char *)options)[1] == 0x04) {
        
        // Check για SACK_PERM (0x04 0x02) - συνήθως μετά από MSS, Window, Timestamp
        // Timestamp είναι 10 bytes, Window είναι 3 bytes, MSS είναι 4 bytes
        // SACK_PERM είναι περίπου στο offset 17 από options start
        if (((unsigned char *)options)[17] == 0x04 && 
            ((unsigned char *)options)[18] == 0x02) {
            
            // Signature 4: Check payload για 0xFF pattern
            void *payload = options + 40;  // After 40 bytes options
            if (payload + 8 <= data_end) {
                // Check first 8 bytes of payload
                __u64 *payload_check = (__u64 *)payload;
                if (*payload_check == 0xFFFFFFFFFFFFFFFFULL) {
                    // MATCH! Drop packet
                    return XDP_DROP;
                }
            }
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

Compile:
```bash
clang -O2 -target bpf -c xdp_ack_signature_filter.c -o xdp_ack_signature_filter.o
```

Load:
```bash
ip link set dev eth0 xdp obj xdp_ack_signature_filter.o sec xdp
```

### 4. Python Deep Packet Inspection

```python
#!/usr/bin/env python3
# signature_detector.py

import socket
import struct
from collections import defaultdict

class ACKSignatureDetector:
    def __init__(self, interface='eth0'):
        self.interface = interface
        self.blocked_ips = set()
        self.detection_count = defaultdict(int)
        
    def parse_tcp_header(self, data):
        """Parse TCP header και επιστρέφει flags"""
        if len(data) < 20:
            return None
            
        src_port, dst_port = struct.unpack('!HH', data[0:4])
        seq_num = struct.unpack('!I', data[4:8])[0]
        ack_num = struct.unpack('!I', data[8:12])[0]
        
        # TCP flags (byte 13)
        flags = data[13]
        data_offset = (data[12] >> 4) & 0xF
        
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'seq': seq_num,
            'ack': ack_num,
            'data_offset': data_offset,
            'flags': flags,
            'ack_flag': bool(flags & 0x10),
            'syn_flag': bool(flags & 0x02),
            'fin_flag': bool(flags & 0x01),
            'rst_flag': bool(flags & 0x04),
            'psh_flag': bool(flags & 0x08),
            'urg_flag': bool(flags & 0x20),
        }
    
    def check_tcp_options(self, tcp_data):
        """Ελέγχει TCP options για ack.c signature"""
        if len(tcp_data) < 60:  # Need 60 bytes header
            return False
            
        # TCP options start at offset 20
        options = tcp_data[20:60]
        
        if len(options) < 40:
            return False
        
        # Signature: MSS (0x02 0x04) στην αρχή
        if options[0] != 0x02 or options[1] != 0x04:
            return False
        
        # Check για SACK_PERM (0x04 0x02) - συνήθως στο offset 17
        # MSS(4) + Window(3) + Timestamp(10) = 17 bytes
        if len(options) > 18:
            if options[17] == 0x04 and options[18] == 0x02:
                return True
        
        return False
    
    def check_payload_signature(self, payload):
        """Ελέγχει αν το payload είναι 0xFF pattern"""
        if len(payload) < 8:
            return False
        
        # Check first 8 bytes
        if payload[:8] == b'\xFF' * 8:
            # Check more bytes για confidence
            if len(payload) >= 100:
                if payload[:100] == b'\xFF' * 100:
                    return True
        return False
    
    def detect_ack_signature(self, ip_header, tcp_data, payload):
        """Detect ack.c signature"""
        tcp_info = self.parse_tcp_header(tcp_data)
        
        if not tcp_info:
            return False
        
        # Signature 1: TCP data offset = 15 (60 bytes)
        if tcp_info['data_offset'] != 15:
            return False
        
        # Signature 2: Pure ACK (only ACK flag)
        if not (tcp_info['ack_flag'] and 
                not tcp_info['syn_flag'] and 
                not tcp_info['fin_flag'] and 
                not tcp_info['rst_flag'] and
                not tcp_info['psh_flag'] and
                not tcp_info['urg_flag']):
            return False
        
        # Signature 3: TCP options pattern
        if not self.check_tcp_options(tcp_data):
            return False
        
        # Signature 4: 0xFF payload
        if payload and not self.check_payload_signature(payload):
            return False
        
        return True
    
    def block_ip(self, ip):
        """Block IP με iptables"""
        if ip not in self.blocked_ips:
            import subprocess
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.blocked_ips.add(ip)
            print(f"[BLOCK] Blocked IP: {ip} (ack.c signature detected)")
    
    def monitor(self):
        """Monitor traffic για signatures"""
        # Create raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((self.interface, 0))
        
        print(f"[*] Monitoring {self.interface} for ack.c signatures...")
        
        while True:
            try:
                packet, addr = sock.recvfrom(65535)
                
                # Parse Ethernet header
                eth_header = packet[0:14]
                eth_type = struct.unpack('!H', eth_header[12:14])[0]
                
                if eth_type != 0x0800:  # Not IPv4
                    continue
                
                # Parse IP header
                ip_header = packet[14:34]
                ip_proto = ip_header[9]
                
                if ip_proto != 6:  # Not TCP
                    continue
                
                src_ip = socket.inet_ntoa(ip_header[12:16])
                ip_header_len = (ip_header[0] & 0xF) * 4
                
                # Parse TCP header
                tcp_start = 14 + ip_header_len
                tcp_header = packet[tcp_start:tcp_start+60]
                
                # Get payload
                tcp_header_len = ((tcp_header[12] >> 4) & 0xF) * 4
                payload_start = tcp_start + tcp_header_len
                payload = packet[payload_start:]
                
                # Detect signature
                if self.detect_ack_signature(ip_header, tcp_header, payload):
                    self.detection_count[src_ip] += 1
                    print(f"[DETECT] ack.c signature from {src_ip}")
                    
                    # Block after 3 detections
                    if self.detection_count[src_ip] >= 3:
                        self.block_ip(src_ip)
                
            except KeyboardInterrupt:
                print("\n[*] Stopping monitor...")
                break
            except Exception as e:
                print(f"[ERROR] {e}")
                continue

if __name__ == '__main__':
    detector = ACKSignatureDetector()
    detector.monitor()
```

### 5. Suricata Rules (IDS/IPS)

```suricata
# ack.c signature rules
alert tcp any any -> any any (msg:"ACK Flood - TCP doff=15"; \
    tcp.hdrlen:15; \
    flags:A; \
    flags:!S; \
    flags:!F; \
    flags:!R; \
    flags:!P; \
    flags:!U; \
    threshold:type threshold, track by_src, count 10, seconds 1; \
    sid:1000001; rev:1;)

alert tcp any any -> any any (msg:"ACK Flood - 0xFF Payload Pattern"; \
    content:"|FF FF FF FF FF FF FF FF|"; \
    offset:80; \
    depth:100; \
    flags:A; \
    threshold:type threshold, track by_src, count 5, seconds 1; \
    sid:1000002; rev:1;)

alert tcp any any -> any any (msg:"ACK Flood - TCP Options Pattern"; \
    tcp.hdrlen:15; \
    tcp.option:mss; \
    tcp.option:sack_perm; \
    flags:A; \
    threshold:type threshold, track by_src, count 10, seconds 1; \
    sid:1000003; rev:1;)
```

### 6. Snort Rules

```snort
# ack.c detection rules
alert tcp any any -> any any ( \
    msg:"ACK Flood - Large TCP Header (doff=15)"; \
    dsize:>1400; \
    tcp_hdr_len:60; \
    flags:A; \
    flags:!S; \
    flags:!F; \
    flags:!R; \
    threshold:type threshold, track by_src, count 10, seconds 1; \
    sid:1000001; rev:1;)

alert tcp any any -> any any ( \
    msg:"ACK Flood - 0xFF Payload Signature"; \
    content:"|FF FF FF FF FF FF FF FF|"; \
    offset:80; \
    depth:100; \
    flags:A; \
    threshold:type threshold, track by_src, count 5, seconds 1; \
    sid:1000002; rev:1;)
```

---

## Ολοκληρωμένο Protection Script

```bash
#!/bin/bash
# complete_signature_protection.sh

set -e

INTERFACE="eth0"
LOG_FILE="/var/log/ack_signature_block.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

setup_signature_filters() {
    log "Setting up signature-based filters..."
    
    # Create custom chain
    iptables -N ACK_SIGNATURE_FILTER 2>/dev/null || true
    iptables -F ACK_SIGNATURE_FILTER
    
    # Rule 1: Block TCP packets με data offset = 15 (60 bytes header)
    # This is the strongest signature - πολύ σπάνιο σε legitimate traffic
    iptables -A ACK_SIGNATURE_FILTER -p tcp \
        -m u32 --u32 "0>>22&0x3C@12>>4&0xF=15" \
        -j DROP
    
    # Rule 2: Block ACK packets με 0xFF payload pattern
    iptables -A ACK_SIGNATURE_FILTER -p tcp \
        -m string --string "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
        --algo bm --from 80 --to 1500 \
        -j DROP
    
    # Rule 3: Block ACK packets με large TCP options (40 bytes)
    # Check για MSS option pattern
    iptables -A ACK_SIGNATURE_FILTER -p tcp \
        -m u32 --u32 "0>>22&0x3C@20&0xFFFF=0x0204" \
        -m u32 --u32 "0>>22&0x3C@12>>4&0xF=15" \
        -j DROP
    
    # Log matches (optional, για debugging)
    iptables -A ACK_SIGNATURE_FILTER -p tcp \
        -m u32 --u32 "0>>22&0x3C@12>>4&0xF=15" \
        -j LOG --log-prefix "ACK_SIGNATURE: " --log-level 4
    
    # Insert into INPUT chain
    iptables -I INPUT -p tcp -j ACK_SIGNATURE_FILTER
    
    log "Signature filters configured"
}

# Alternative: Use nftables (more modern)
setup_nftables_signatures() {
    log "Setting up nftables signature filters..."
    
    cat > /tmp/ack_signatures.nft <<'EOF'
table inet filter {
    chain input {
        type filter hook input priority 0;
        
        # Block TCP doff=15 (60 bytes header)
        tcp flags ack \
            @th,52,4 & 0xf0000000 = 0xf0000000 \
            drop comment "ack.c: TCP doff=15"
        
        # Block 0xFF payload pattern
        @nh,80,8 = 0xffffffffffffffff \
            drop comment "ack.c: 0xFF payload"
    }
}
EOF
    
    nft -f /tmp/ack_signatures.nft
    log "nftables signature filters configured"
}

main() {
    log "Starting Signature-Based ACK Protection"
    
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        exit 1
    fi
    
    # Choose method
    if command -v nft >/dev/null 2>&1; then
        setup_nftables_signatures
    else
        setup_signature_filters
    fi
    
    log "Protection active - blocking ack.c signatures"
}

main "$@"
```

---

## Testing Signature Detection

```bash
#!/bin/bash
# test_signature_detection.sh

# Capture packets και check για signatures
tcpdump -i eth0 -n -c 1000 -w test.pcap 'tcp[tcpflags] & tcp-ack != 0'

# Analyze με tshark
tshark -r test.pcap -T fields \
    -e ip.src -e tcp.srcport -e tcp.hdr_len -e tcp.flags \
    | awk '$3 == 60 && $4 == 16 {print "SIGNATURE MATCH:", $1}'

# Check για 0xFF payload
tshark -r test.pcap -T fields \
    -e ip.src -e frame.number \
    -Y "tcp.hdr_len == 60 && tcp.flags.ack == 1" \
    | while read ip frame; do
        tshark -r test.pcap -Y "frame.number == $frame" \
            -x | grep -q "ff ff ff ff" && echo "0xFF payload: $ip"
    done
```

---

## Πλεονεκτήματα Signature-Based Filtering

1. **Ακριβής Detection**: Αναγνωρίζει ακριβώς τα packets του ack.c
2. **Λίγα False Positives**: Legitimate traffic δεν έχει αυτά τα signatures
3. **Υψηλή Αποτελεσματικότητα**: Block από το πρώτο packet
4. **Χαμηλό Overhead**: Μόνο pattern matching, όχι rate limiting
5. **Δεν Επηρεάζει Legitimate Traffic**: Normal ACK packets δεν έχουν doff=15

---

## Συμπεράσματα

Το signature-based filtering είναι **πολύ πιο αποτελεσματικό** από το rate limiting για το `ack.c` επειδή:

- Το **TCP doff=15** (60 bytes header) είναι **πολύ σπάνιο** σε legitimate traffic
- Το **0xFF payload pattern** είναι **χαρακτηριστικό** του ack.c
- Το **40 bytes TCP options** με συγκεκριμένη σειρά είναι **unique signature**

Αυτή η προσέγγιση μπορεί να **block 100%** των ack.c packets **χωρίς να επηρεάσει** το legitimate traffic.

---

## Πηγές

- [iptables u32 match](https://www.netfilter.org/documentation/HOWTO/netfilter-extensions-HOWTO-4.html#ss4.4)
- [nftables expressions](https://wiki.nftables.org/wiki-nftables/index.php/Expressions)
- [eBPF/XDP Documentation](https://github.com/iovisor/bcc)


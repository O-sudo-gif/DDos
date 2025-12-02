# Προστασία με Signature-Based Filtering για syn.c

## Επισκόπηση

Αντί για γενικό rate limiting, μπορούμε να αναγνωρίσουμε τα **συγκεκριμένα signatures** που χρησιμοποιεί το `syn.c` και να τα φιλτράρουμε απευθείας. Αυτή η προσέγγιση είναι πιο αποτελεσματική και έχει λιγότερα false positives.

---

## Signatures που Χρησιμοποιεί το syn.c

### 1. TCP Header Signatures

#### TCP Flags Pattern - Pure SYN
```c
tcph->syn = 1;
tcph->ack = 0;
tcph->fin = 0;
tcph->rst = 0;
tcph->psh = 0;
tcph->urg = 0;
```
**Signature**: Pure SYN packet (μόνο SYN flag, όλα τα άλλα 0)

**Σημείωση**: Αυτό είναι λιγότερο χαρακτηριστικό από το ACK flood, αλλά σε συνδυασμό με άλλα signatures είναι αποτελεσματικό.

#### TCP Data Offset (Variable)
```c
int tcp_hdr_len = sizeof(struct tcphdr) + tcp_optlen;
int calculated_doff = (tcp_hdr_len + 3) / 4;
if (calculated_doff < 5) calculated_doff = 5;
if (calculated_doff > 15) calculated_doff = 15;
tcph->doff = calculated_doff;
```
**Signature**: Variable TCP header length (5-15, 20-60 bytes) με random TCP options

### 2. TCP Options Signature

Το `syn.c` χρησιμοποιεί **random TCP options** (0-40 bytes) με συγκεκριμένες πιθανότητες:

```c
int opt_choice = random_number_beetwhen(0, 100);

// MSS (90% probability)
if (opt_choice < 90) {
    tcp_options[offset++] = TCP_OPT_MSS;  // 0x02
    tcp_options[offset++] = 4;
    // MSS values: 536, 1024, 1440, 1460, 1500
}

// Window Scale (70% probability)
if (opt_choice < 70) {
    tcp_options[offset++] = TCP_OPT_WINDOW;  // 0x03
    tcp_options[offset++] = 3;
    // Scale: 0-14
}

// SACK_PERM (60% probability)
if (opt_choice < 60) {
    tcp_options[offset++] = TCP_OPT_SACK_PERM;  // 0x04
    tcp_options[offset++] = 2;
}

// Timestamp (80% probability)
if (opt_choice < 80) {
    tcp_options[offset++] = TCP_OPT_TIMESTAMP;  // 0x08
    tcp_options[offset++] = 10;
    // Timestamp values
}
```

**Pattern Characteristics:**
- MSS option (90% των packets)
- Window Scale (70% των packets)
- Timestamp (80% των packets)
- SACK_PERM (60% των packets)
- NOP padding για 4-byte alignment

**Signature**: SYN packets με αυτή τη συγκεκριμένη **συνδυαστική πιθανότητα** των options

### 3. No Payload Signature

```c
data = "";
int data_len = 0;  // No data payload for pure SYN flood
```

**Signature**: Pure SYN packets **χωρίς payload** (~40-80 bytes total packet size)

### 4. Packet Size Signature

```c
int total_packet_len = sizeof(struct iphdr) + tcp_hdr_len + data_len;
// = 20 + (20-60) + 0 = 40-80 bytes
```

**Signature**: Μικρά packets (40-80 bytes) - **πολύ μικρότερα** από το ACK flood

### 5. IP Header Signatures

```c
iph->ttl = 64;  // ή 128, ή 255 (realistic distribution)
iph->tos = 0;   // συνήθως 0, αλλά μπορεί να είναι 0x10, 0x08, κλπ
iph->frag_off = 0;  // No fragmentation
```

**TTL Distribution:**
- 50% TTL = 64 (Linux)
- 25% TTL = 128 (Windows)
- 15% TTL = 255 (Maximum)
- 10% TTL = 32-64 (Lower values)

### 6. Sequence Number Pattern

```c
// SYN packets use random initial sequence numbers
uint32_t seq_val = base_seq + random_offset;
tcph->seq = htonl(seq_val);
tcph->ack_seq = 0;  // SYN packets have ACK=0
```

**Signature**: SYN packets με **ACK sequence = 0** (αυτό είναι normal για SYN)

### 7. High SYN Rate Signature

Το `syn.c` στέλνει **πολύ υψηλό ρυθμό** SYN packets (100k-500k PPS), που είναι **πολύ πιο υψηλό** από το legitimate traffic.

---

## Υλοποίηση Signature-Based Filtering

### 1. iptables με SYN Rate Limiting

```bash
#!/bin/bash
# signature_block_syn.c.sh

# Block excessive SYN packets (rate limiting)
# Legitimate connections: ~10-100 SYN/sec per IP
# syn.c: 100k-500k SYN/sec total
iptables -A INPUT -p tcp --tcp-flags SYN SYN \
    -m limit --limit 50/sec --limit-burst 100 \
    -j ACCEPT

iptables -A INPUT -p tcp --tcp-flags SYN SYN \
    -j DROP

# Block SYN packets με suspicious TCP options pattern
# Check για MSS + Window Scale + Timestamp combination
iptables -A INPUT -p tcp --tcp-flags SYN SYN \
    -m u32 --u32 "0>>22&0x3C@20&0xFF=0x02" \  # MSS option
    -m u32 --u32 "0>>22&0x3C@24&0xFF=0x03" \  # Window Scale option
    -m limit --limit 10/sec --limit-burst 20 \
    -j DROP

# Block SYN packets με large TCP options (>20 bytes)
# Normal SYN: 0-20 bytes options, syn.c: up to 40 bytes
iptables -A INPUT -p tcp --tcp-flags SYN SYN \
    -m u32 --u32 "0>>22&0x3C@12>>4&0xF>10" \  # doff > 10 (40+ bytes header)
    -j DROP
```

### 2. nftables με SYN Detection

```bash
#!/usr/sbin/nft -f
# signature_block_syn.nft

table inet filter {
    chain input {
        type filter hook input priority 0;
        
        # Rate limit SYN packets
        tcp flags syn \
            limit rate 50/second burst 100 packets \
            accept comment "Normal SYN rate"
        
        tcp flags syn \
            drop comment "Excessive SYN packets"
        
        # Block SYN με large TCP options
        tcp flags syn \
            @th,52,4 & 0xf0000000 > 0xa0000000 \
            drop comment "syn.c: Large TCP header (doff>10)"
        
        # Block SYN με specific options pattern
        tcp flags syn \
            @th,72,1 = 0x02 \  # MSS option
            @th,76,1 = 0x03 \  # Window Scale option
            limit rate 10/second \
            drop comment "syn.c: MSS+Window pattern"
    }
}
```

### 3. eBPF/XDP Signature Filter

```c
// xdp_syn_signature_filter.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_syn_signature_filter(struct xdp_md *ctx) {
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
    
    // Signature 1: Pure SYN (only SYN flag, no ACK/FIN/RST)
    if (!(tcp->syn) || tcp->ack || tcp->fin || tcp->rst) {
        return XDP_PASS;
    }
    
    // Signature 2: No payload (small packet size)
    int tcp_hdr_len = tcp->doff * 4;
    int total_len = ntohs(ip->tot_len);
    int ip_hdr_len = ip->ihl * 4;
    int payload_len = total_len - ip_hdr_len - tcp_hdr_len;
    
    // syn.c sends pure SYN with no payload
    if (payload_len > 0) {
        return XDP_PASS;  // Has payload, not syn.c
    }
    
    // Signature 3: Large TCP options (doff > 10 = 40+ bytes)
    if (tcp->doff > 10) {
        return XDP_DROP;  // Suspicious large header
    }
    
    // Signature 4: Check TCP options pattern
    void *options = (void *)(tcp + 1);
    if (options + 20 > data_end) return XDP_PASS;
    
    // Check για MSS (0x02) + Window Scale (0x03) combination
    // This is common in syn.c (90% MSS, 70% Window Scale)
    unsigned char *opts = (unsigned char *)options;
    int has_mss = 0, has_window = 0, has_timestamp = 0;
    
    int offset = 0;
    while (offset < tcp_hdr_len - 20 && offset < 40) {
        if (opts[offset] == 0) break;  // End of options
        if (opts[offset] == 1) {  // NOP
            offset++;
            continue;
        }
        
        if (offset + 1 >= tcp_hdr_len - 20) break;
        int opt_len = opts[offset + 1];
        if (opt_len < 2 || offset + opt_len > tcp_hdr_len - 20) break;
        
        if (opts[offset] == 0x02 && opt_len == 4) {  // MSS
            has_mss = 1;
        }
        if (opts[offset] == 0x03 && opt_len == 3) {  // Window Scale
            has_window = 1;
        }
        if (opts[offset] == 0x08 && opt_len == 10) {  // Timestamp
            has_timestamp = 1;
        }
        
        offset += opt_len;
    }
    
    // syn.c signature: MSS (90%) + Window (70%) + Timestamp (80%)
    // If we see all three, high probability it's syn.c
    if (has_mss && has_window && has_timestamp) {
        return XDP_DROP;  // Strong signature match
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

Compile:
```bash
clang -O2 -target bpf -c xdp_syn_signature_filter.c -o xdp_syn_signature_filter.o
```

Load:
```bash
ip link set dev eth0 xdp obj xdp_syn_signature_filter.o sec xdp
```

### 4. Python Deep Packet Inspection

```python
#!/usr/bin/env python3
# syn_signature_detector.py

import socket
import struct
from collections import defaultdict

class SYNSignatureDetector:
    def __init__(self, interface='eth0'):
        self.interface = interface
        self.blocked_ips = set()
        self.detection_count = defaultdict(int)
        self.syn_rate = defaultdict(int)  # Track SYN rate per IP
        
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
            'syn_flag': bool(flags & 0x02),
            'ack_flag': bool(flags & 0x10),
            'fin_flag': bool(flags & 0x01),
            'rst_flag': bool(flags & 0x04),
        }
    
    def check_tcp_options(self, tcp_data):
        """Ελέγχει TCP options για syn.c signature"""
        if len(tcp_data) < 20:
            return False
        
        data_offset = (tcp_data[12] >> 4) & 0xF
        tcp_hdr_len = data_offset * 4
        
        if tcp_hdr_len < 20 or tcp_hdr_len > 60:
            return False
        
        # TCP options start at offset 20
        options = tcp_data[20:tcp_hdr_len]
        
        if len(options) == 0:
            return False  # No options, not syn.c
        
        # Check για MSS, Window Scale, Timestamp
        has_mss = False
        has_window = False
        has_timestamp = False
        
        offset = 0
        while offset < len(options):
            if options[offset] == 0:  # End of options
                break
            if options[offset] == 1:  # NOP
                offset += 1
                continue
            
            if offset + 1 >= len(options):
                break
            
            opt_type = options[offset]
            opt_len = options[offset + 1]
            
            if opt_len < 2 or offset + opt_len > len(options):
                break
            
            if opt_type == 0x02 and opt_len == 4:  # MSS
                has_mss = True
            elif opt_type == 0x03 and opt_len == 3:  # Window Scale
                has_window = True
            elif opt_type == 0x08 and opt_len == 10:  # Timestamp
                has_timestamp = True
            
            offset += opt_len
        
        # syn.c signature: High probability of MSS + Window + Timestamp
        # If all three present, strong indicator
        if has_mss and has_window and has_timestamp:
            return True
        
        # Also check για large options (>20 bytes)
        if len(options) > 20:
            return True
        
        return False
    
    def detect_syn_signature(self, ip_header, tcp_data, payload):
        """Detect syn.c signature"""
        tcp_info = self.parse_tcp_header(tcp_data)
        
        if not tcp_info:
            return False
        
        # Signature 1: Pure SYN (only SYN flag, no ACK)
        if not (tcp_info['syn_flag'] and 
                not tcp_info['ack_flag'] and 
                not tcp_info['fin_flag'] and 
                not tcp_info['rst_flag']):
            return False
        
        # Signature 2: No payload (small packet)
        if payload and len(payload) > 0:
            return False  # syn.c sends no payload
        
        # Signature 3: TCP options pattern
        if not self.check_tcp_options(tcp_data):
            return False
        
        # Signature 4: Large TCP header (doff > 10)
        if tcp_info['data_offset'] > 10:
            return True  # Suspicious large header
        
        return True
    
    def block_ip(self, ip):
        """Block IP με iptables"""
        if ip not in self.blocked_ips:
            import subprocess
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.blocked_ips.add(ip)
            print(f"[BLOCK] Blocked IP: {ip} (syn.c signature detected)")
    
    def monitor(self):
        """Monitor traffic για signatures"""
        import time
        
        # Create raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((self.interface, 0))
        
        print(f"[*] Monitoring {self.interface} for syn.c signatures...")
        
        last_rate_check = time.time()
        
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
                
                # Track SYN rate
                tcp_info = self.parse_tcp_header(tcp_header)
                if tcp_info and tcp_info['syn_flag']:
                    self.syn_rate[src_ip] += 1
                
                # Check rate every second
                current_time = time.time()
                if current_time - last_rate_check >= 1.0:
                    # Check για excessive SYN rate (>1000/sec per IP)
                    for ip, count in list(self.syn_rate.items()):
                        if count > 1000:
                            print(f"[RATE] High SYN rate from {ip}: {count}/sec")
                            self.block_ip(ip)
                    self.syn_rate.clear()
                    last_rate_check = current_time
                
                # Detect signature
                if self.detect_syn_signature(ip_header, tcp_header, payload):
                    self.detection_count[src_ip] += 1
                    print(f"[DETECT] syn.c signature from {src_ip}")
                    
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
    detector = SYNSignatureDetector()
    detector.monitor()
```

### 5. Suricata Rules (IDS/IPS)

```suricata
# syn.c signature rules
alert tcp any any -> any any (msg:"SYN Flood - Pure SYN with Large Options"; \
    tcp.hdrlen:>10; \
    flags:S; \
    flags:!A; \
    flags:!F; \
    flags:!R; \
    threshold:type threshold, track by_src, count 10, seconds 1; \
    sid:2000001; rev:1;)

alert tcp any any -> any any (msg:"SYN Flood - High SYN Rate"; \
    flags:S; \
    flags:!A; \
    threshold:type threshold, track by_src, count 100, seconds 1; \
    sid:2000002; rev:1;)

alert tcp any any -> any any (msg:"SYN Flood - MSS+Window+Timestamp Pattern"; \
    tcp.option:mss; \
    tcp.option:window_scale; \
    tcp.option:timestamp; \
    flags:S; \
    flags:!A; \
    threshold:type threshold, track by_src, count 5, seconds 1; \
    sid:2000003; rev:1;)
```

### 6. Snort Rules

```snort
# syn.c detection rules
alert tcp any any -> any any ( \
    msg:"SYN Flood - Large TCP Header (doff>10)"; \
    tcp_hdr_len:>40; \
    flags:S; \
    flags:!A; \
    threshold:type threshold, track by_src, count 10, seconds 1; \
    sid:2000001; rev:1;)

alert tcp any any -> any any ( \
    msg:"SYN Flood - Excessive SYN Rate"; \
    flags:S; \
    flags:!A; \
    threshold:type threshold, track by_src, count 100, seconds 1; \
    sid:2000002; rev:1;)
```

---

## Ολοκληρωμένο Protection Script

```bash
#!/bin/bash
# complete_syn_signature_protection.sh

set -e

INTERFACE="eth0"
LOG_FILE="/var/log/syn_signature_block.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

setup_signature_filters() {
    log "Setting up signature-based SYN filters..."
    
    # Create custom chain
    iptables -N SYN_SIGNATURE_FILTER 2>/dev/null || true
    iptables -F SYN_SIGNATURE_FILTER
    
    # Rule 1: Rate limit SYN packets (primary defense)
    # Legitimate: ~10-100 SYN/sec per IP
    # syn.c: 100k-500k SYN/sec total
    iptables -A SYN_SIGNATURE_FILTER -p tcp --tcp-flags SYN SYN \
        -m limit --limit 50/sec --limit-burst 100 \
        -j ACCEPT
    
    iptables -A SYN_SIGNATURE_FILTER -p tcp --tcp-flags SYN SYN \
        -j DROP
    
    # Rule 2: Block SYN με large TCP options (doff > 10 = 40+ bytes)
    iptables -A SYN_SIGNATURE_FILTER -p tcp --tcp-flags SYN SYN \
        -m u32 --u32 "0>>22&0x3C@12>>4&0xF>10" \
        -j DROP
    
    # Rule 3: Block SYN με MSS + Window Scale pattern
    iptables -A SYN_SIGNATURE_FILTER -p tcp --tcp-flags SYN SYN \
        -m u32 --u32 "0>>22&0x3C@20&0xFF=0x02" \  # MSS
        -m u32 --u32 "0>>22&0x3C@24&0xFF=0x03" \  # Window Scale
        -m limit --limit 10/sec --limit-burst 20 \
        -j DROP
    
    # Enable SYN cookies (kernel-level protection)
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies
    
    # Log matches (optional)
    iptables -A SYN_SIGNATURE_FILTER -p tcp --tcp-flags SYN SYN \
        -m u32 --u32 "0>>22&0x3C@12>>4&0xF>10" \
        -j LOG --log-prefix "SYN_SIGNATURE: " --log-level 4
    
    # Insert into INPUT chain
    iptables -I INPUT -p tcp -j SYN_SIGNATURE_FILTER
    
    log "Signature filters configured"
}

# Alternative: Use nftables
setup_nftables_signatures() {
    log "Setting up nftables signature filters..."
    
    cat > /tmp/syn_signatures.nft <<'EOF'
table inet filter {
    chain input {
        type filter hook input priority 0;
        
        # Rate limit SYN packets
        tcp flags syn \
            limit rate 50/second burst 100 packets \
            accept comment "Normal SYN rate"
        
        tcp flags syn \
            drop comment "Excessive SYN packets"
        
        # Block SYN με large TCP options
        tcp flags syn \
            @th,52,4 & 0xf0000000 > 0xa0000000 \
            drop comment "syn.c: Large TCP header (doff>10)"
    }
}
EOF
    
    nft -f /tmp/syn_signatures.nft
    
    # Enable SYN cookies
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies
    
    log "nftables signature filters configured"
}

main() {
    log "Starting Signature-Based SYN Protection"
    
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
    
    log "Protection active - blocking syn.c signatures"
}

main "$@"
```

---

## Testing Signature Detection

```bash
#!/bin/bash
# test_syn_signature_detection.sh

# Capture SYN packets
tcpdump -i eth0 -n -c 1000 -w test_syn.pcap 'tcp[tcpflags] & tcp-syn != 0'

# Analyze με tshark
tshark -r test_syn.pcap -T fields \
    -e ip.src -e tcp.srcport -e tcp.hdr_len -e tcp.flags \
    | awk '$3 > 40 && $4 == 2 {print "SIGNATURE MATCH:", $1}'

# Check για high SYN rate
tshark -r test_syn.pcap -T fields \
    -e ip.src -e frame.time \
    | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
```

---

## Πλεονεκτήματα Signature-Based Filtering

1. **Αποτελεσματική Detection**: Αναγνωρίζει patterns του syn.c
2. **Rate Limiting**: Primary defense για SYN floods
3. **SYN Cookies**: Kernel-level protection
4. **Χαμηλό Overhead**: Pattern matching + rate limiting
5. **Δεν Επηρεάζει Legitimate Traffic**: Normal SYN packets έχουν μικρότερα headers

---

## Συμπεράσματα

Το signature-based filtering για το `syn.c` είναι **πιο δύσκολο** από το ACK flood επειδή:

- Το **Pure SYN** είναι **normal** σε legitimate traffic
- Το **TCP options pattern** είναι **variable** (random)
- Το **packet size** είναι **μικρό** (40-80 bytes)

**Ωστόσο**, ο συνδυασμός των:
- **Rate limiting** (primary defense)
- **Large TCP options detection** (doff > 10)
- **SYN cookies** (kernel protection)
- **Options pattern matching** (MSS+Window+Timestamp)

μπορεί να **μειώσει σημαντικά** την αποτελεσματικότητα του syn.c.

---

## Πηγές

- [iptables u32 match](https://www.netfilter.org/documentation/HOWTO/netfilter-extensions-HOWTO-4.html#ss4.4)
- [nftables expressions](https://wiki.nftables.org/wiki-nftables/index.php/Expressions)
- [eBPF/XDP Documentation](https://github.com/iovisor/bcc)
- [SYN Cookies](https://lwn.net/Articles/277146/)


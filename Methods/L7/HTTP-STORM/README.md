# 🌪️ TORNADO v2.0 ENHANCED - HTTP/2 Load Testing Tool

> **High-performance HTTP/2 and HTTP/1.1 load testing tool optimized for 100k+ requests per second**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: Node.js](https://img.shields.io/badge/Platform-Node.js-green.svg)](https://nodejs.org/)
[![Language: JavaScript](https://img.shields.io/badge/Language-JavaScript-yellow.svg)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Status: Active](https://img.shields.io/badge/Status-Active-green.svg)]()

---

## ⚠️ **LEGAL DISCLAIMER**

**This tool is for educational and authorized security testing purposes ONLY.**

- **Unauthorized use** of this tool against systems you do not own or have explicit written permission to test is **illegal** and may result in criminal prosecution
- The authors and contributors are **not responsible** for any misuse of this software
- Use this tool **responsibly** and only on systems you own or have explicit authorization to test
- **Load testing** requires written authorization from the system owner

**By using this software, you agree to use it legally and ethically.**

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Options](#options)
- [Examples](#examples)
- [Performance](#performance)
- [Protection Strategies](#protection-strategies)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

**TORNADO** is a high-performance HTTP/2 and HTTP/1.1 load testing tool designed for stress testing web applications, APIs, and CDN infrastructure. It supports both HTTP/2 and HTTP/1.1 protocols with advanced features like proxy rotation, custom headers, and intelligent rate limiting.

### Key Capabilities

- ✅ **HTTP/2 Support** - Full HTTP/2 protocol implementation with HPACK compression
- ✅ **HTTP/1.1 Support** - Traditional HTTP/1.1 with Keep-Alive connections
- ✅ **Mixed Protocol Mode** - Automatically switches between HTTP/2 and HTTP/1.1
- ✅ **Proxy Rotation** - SOCKS5/HTTP proxy support with automatic rotation
- ✅ **High Performance** - Optimized for 100,000+ requests per second
- ✅ **Multi-threaded** - Cluster-based architecture for maximum throughput
- ✅ **Custom Headers** - Full control over HTTP headers and user agents
- ✅ **Rate Limiting** - Intelligent rate limiting with randomization
- ✅ **Debug Mode** - Real-time status code monitoring

---

## ✨ Features

### Protocol Support

```
┌─────────────────────────────────────────────────────────┐
│                    Protocol Stack                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐         ┌──────────────┐              │
│  │   HTTP/2     │         │   HTTP/1.1   │              │
│  │              │         │              │              │
│  │ • HPACK      │         │ • Keep-Alive │              │
│  │ • Multiplex  │         │ • Chunked    │              │
│  │ • Server Push│         │ • Compression│              │
│  │ • Streams    │         │ • Headers    │              │
│  └──────────────┘         └──────────────┘              │
│         │                        │                      │
│         └────────┬───────────────┘                      │
│                  │                                      │
│         ┌────────▼────────┐                             │
│         │   TLS 1.2/1.3   │                             │
│         │                 │                             │
│         │ • ALPN          │                             │
│         │ • SNI           │                             │
│         │ • Cipher Suite  │                             │
│         └────────┬────────┘                             │
│                  │                                      │
│         ┌────────▼────────┐                             │
│         │   TCP Socket    │                             │
│         └─────────────────┘                             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Performance Optimizations

- **Fast PRNG** - Custom random number generator (10x faster than Math.random)
- **Connection Pooling** - Reusable connection pool for reduced overhead
- **Batch Processing** - Batched request sending for maximum throughput
- **Zero-Copy Buffers** - Pre-allocated buffers to minimize memory allocation
- **Worker Clustering** - Multi-process architecture for CPU utilization

### Advanced Features

- **Bot Fight Mode** - Cloudflare challenge bypass with cookie generation
- **Random Query Strings** - Dynamic query parameter generation
- **Custom Referers** - Random or custom referer header generation
- **POST Data Support** - POST request payload support
- **Header Customization** - Multiple custom headers with delimiter support
- **Rate Randomization** - Random rate limiting for bypass testing

---

## 🏗️ Architecture

### System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Master Process                            │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  • Parse Arguments                                     │  │
│  │  • Load Proxy List                                     │  │
│  │  • Spawn Worker Processes                              │  │
│  │  • Monitor Statistics                                  │  │
│  └────────────────────────────────────────────────────────┘  │
└───────────────────────────┬──────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Worker 1   │    │   Worker 2   │    │   Worker N   │
│              │    │              │    │              │
│ • FastPRNG   │    │ • FastPRNG   │    │ • FastPRNG   │
│ • Connections│    │ • Connections│    │ • Connections│
│ • HTTP/2     │    │ • HTTP/2     │    │ • HTTP/2     │
│ • HTTP/1.1   │    │ • HTTP/1.1   │    │ • HTTP/1.1   │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                           ▼
                ┌───────────────────────┐
                │   Proxy Rotation      │
                │   (SOCKS5/HTTP)       │
                └───────────┬───────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │   Target Server       │
                │   (HTTPS)             │
                └───────────────────────┘
```

### Request Flow

```
┌─────────────┐
│   Request   │
│  Generation │
└──────┬──────┘
       │
       ├─► Parse URL
       ├─► Generate Headers
       ├─► Apply Custom Options
       └─► Encode (HPACK/HTTP)
            │
            ▼
┌─────────────┐
│   Proxy     │
│  Selection  │
└──────┬──────┘
       │
       ├─► Random Proxy
       ├─► TCP Connect
       └─► TLS Handshake
            │
            ▼
┌─────────────┐
│  Protocol   │
│ Negotiation │
└──────┬──────┘
       │
       ├─► HTTP/2 (h2)
       └─► HTTP/1.1 (http/1.1)
            │
            ▼
┌─────────────┐
│   Request   │
│   Sending   │
└──────┬──────┘
       │
       ├─► Batch Write
       ├─► Stream Management
       └─► Response Handling
```

---

## 📦 Installation

### Prerequisites

- **Node.js** >= 14.0.0
- **npm** or **yarn** package manager
- **Proxy file** (optional, for proxy rotation)

### Install Dependencies

```bash
# Navigate to the HTTP-STORM directory
cd L7/HTTP-STORM

# Install dependencies
npm install

# Or using yarn
yarn install
```

### Verify Installation

```bash
# Check Node.js version
node --version

# Verify hpack package
npm list hpack
```

---

## 🚀 Usage

### Basic Syntax

```bash
node http-storm.js <METHOD> <TARGET> <TIME> <THREADS> <RATELIMIT> <PROXYFILE> [OPTIONS]
```

### Required Parameters

| Parameter   | Description                            | Example              |
|-------------|----------------------------------------|----------------------|
| `METHOD`    | HTTP method (GET, POST, HEAD, OPTIONS) | `GET`                |
| `TARGET`    | Target URL (must be HTTPS)             | `https://example.com`|
| `TIME`      | Duration in seconds (1-86400)          | `120`                |
| `THREADS`   | Number of worker threads (1-512)       | `32`                 |
| `RATELIMIT` | Requests per second (1-90)             | `90`                 |
| `PROXYFILE` | Path to proxy list file                | `proxy.txt`          |

### Basic Example

```bash
node http-storm.js GET "https://example.com" 120 32 90 proxy.txt
```

---

## ⚙️ Options

### Query String Options

| Option           | Values | Description                                    |
|------------------|--------|------------------------------------------------|
| `--query`        | `1/2/3`| Query string generation mode                   |
|                  | `1`    | Cloudflare challenge token format              |
|                  | `2`    | Random query parameters                        |
|                  | `3`    | Standard query format (`?q=...`)               |

### Request Customization

| Option           | Format                            | Description                          |
|------------------|-----------------------------------|--------------------------------------|
| `--cookie`       | `"key=value"`                     | Custom cookie header                 |
| `--referer`      | `"https://..."` or `rand`         | Custom or random referer             |
| `--postdata`     | `"key=value"`                     | POST request body data               |
| `--header`       | `"name:value"` or `"n1:v1#n2:v2"` | Custom headers (use `#` to separate) |

### Rate Limiting

| Option           | Values  | Description                                    |
|------------------|---------|------------------------------------------------|
| `--delay`        | `0-1000`| Delay between requests (ms)                    |
|                  | `0`     | Maximum speed (recommended for high RPS)       |
| `--randrate`     | -       | Randomize rate between 1-90                    |

### Protocol Control

| Option           | Values    | Description                                    |
|------------------|-----------|------------------------------------------------|
| `--http`         | `1/2/mix` | Force HTTP version                             |
|                  | `1`       | HTTP/1.1 only                                  |
|                  | `2`       | HTTP/2 only                                    |
|                  | `mix`     | Random selection between HTTP/2 and HTTP/1.1   |

### Advanced Options

| Option           | Description                                    |
|------------------|------------------------------------------------|
| `--bfm`          | Bot Fight Mode (Cloudflare challenge bypass)   |
| `--full`         | Optimized mode for large backends (CDN)        |
| `--debug`        | Enable debug mode (shows status codes)         |

---

## 📝 Examples

### Example 1: Basic HTTP/2 Load Test

```bash
node http-storm.js GET "https://example.com" 120 32 90 proxy.txt
```

**Output:**
```
🌪️ TORNADO v2.0 ENHANCED - Optimized for 100k+ req/s
📊 Threads: 32 | Proxies: 1000
```

### Example 2: Advanced Configuration

```bash
node http-storm.js GET "https://example.com?q=%RAND%" 120 32 90 proxy.txt \
  --query 1 \
  --cookie "session=abc123" \
  --delay 0 \
  --bfm true \
  --referer rand \
  --debug \
  --randrate \
  --full
```

**Features:**
- Cloudflare challenge query strings
- Custom session cookie
- Maximum speed (no delay)
- Bot Fight Mode enabled
- Random referer generation
- Debug mode for status monitoring
- Rate randomization
- Full optimization mode

### Example 3: POST Request with Data

```bash
node http-storm.js POST "https://api.example.com/login" 60 16 50 proxy.txt \
  --postdata "username=test&password=%RAND%" \
  --header "Content-Type:application/x-www-form-urlencoded" \
  --debug
```

### Example 4: HTTP/1.1 Only Mode

```bash
node http-storm.js GET "https://example.com" 120 32 90 proxy.txt --http 1
```

### Example 5: Mixed Protocol Mode

```bash
node http-storm.js GET "https://example.com" 120 32 90 proxy.txt --http mix
```

### Example 6: Custom Headers

```bash
node http-storm.js GET "https://api.example.com" 120 32 90 proxy.txt \
  --header "X-API-Key:abc123#Authorization:Bearer token#X-Custom:value"
```

---

## 📊 Performance

### Benchmarks

Typical performance on modern hardware:

| Configuration        | Threads | RPS      | CPU Usage | Memory    | Protocol |
|----------------------|---------|----------|-----------|-----------|----------|
| Standard (HTTP/2)    | 32      | 50k-100k | 40-60%    | 200-400MB | HTTP/2   |
| High Performance     | 64      | 100k-200k| 60-80%    | 400-800MB | HTTP/2   |
| Maximum (--full)     | 128     | 200k+    | 80-100%   | 800MB+    | HTTP/2   |
| HTTP/1.1 Mode        | 32      | 30k-60k  | 30-50%    | 150-300MB | HTTP/1.1 |

*Results vary by hardware, network conditions, and target server capacity*

### Optimization Tips

1. **Use `--delay 0`** for maximum speed
2. **Enable `--full`** for large backend testing
3. **Increase threads** for multi-core systems
4. **Use HTTP/2** for better multiplexing
5. **Disable `--debug`** for production testing

---

## 🛡️ Protection Strategies

For comprehensive protection strategies, see the **[Protection Guide](PROTECTION/PROTECTION_GUIDE.md)**.

### Quick Protection Overview

The tool can be detected by:

1. **High Request Rate** - Unusually high requests per second
2. **HTTP/2 Settings** - Specific HTTP/2 connection settings
3. **Header Patterns** - Consistent header patterns
4. **Proxy IPs** - Known proxy IP addresses
5. **User-Agent Patterns** - Repeated user-agent strings

### Multi-Layer Defense

```
┌─────────────────────────────────────────┐
│  Layer 1: CDN/DDoS Protection Service   │
│  - Cloudflare, AWS Shield               │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│  Layer 2: Web Server Rate Limiting     │
│  - Nginx limit_req                      │
│  - Apache mod_evasive                   │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│  Layer 3: WAF (Web Application Firewall)│
│  - ModSecurity rules                    │
│  - Cloudflare WAF                       │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│  Layer 4: Application-Level Protection  │
│  - Express rate limiting                │
│  - Request validation                   │
└─────────────────────────────────────────┘
```

### Quick Protection Examples

#### Nginx Rate Limiting

```nginx
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=20r/s;
limit_req zone=api_limit burst=30 nodelay;
```

#### Express.js Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
```

**For detailed protection strategies, detection methods, WAF rules, monitoring, and complete protection scripts, see [PROTECTION/PROTECTION_GUIDE.md](PROTECTION/PROTECTION_GUIDE.md).**

---

## 🔧 Troubleshooting

### Common Issues

#### Issue: "ECONNREFUSED" errors

**Solution:**
- Check proxy file format (should be `host:port`)
- Verify proxy connectivity
- Ensure proxies support HTTPS

#### Issue: Low RPS

**Solution:**
- Increase thread count
- Use `--delay 0` for maximum speed
- Enable `--full` mode
- Check network bandwidth

#### Issue: "HPACK" module not found

**Solution:**
```bash
npm install hpack
```

#### Issue: High memory usage

**Solution:**
- Reduce thread count
- Disable debug mode
- Use HTTP/1.1 mode (lower memory)

### Debug Mode

Enable debug mode to see real-time statistics:

```bash
node http-storm.js GET "https://example.com" 120 32 90 proxy.txt --debug
```

**Output:**
```
2024-01-01 12:00:00 { '200': 50000, '429': 100, '503': 50 }
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Contribution Areas

- ✅ Performance optimizations
- ✅ New protocol support
- ✅ Additional bypass techniques
- ✅ Documentation improvements
- ✅ Bug fixes

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

**Important:** The license does not grant permission to use this tool illegally. Users are responsible for compliance with all applicable laws.

---

## 🙏 Acknowledgments

- HTTP/2 protocol implementation
- HPACK compression library
- Node.js cluster module
- Open-source community

---

## 📞 Support

### Getting Help

- **Issues:** Open an issue on GitHub
- **Documentation:** Check this README
- **Examples:** See the Examples section above

### Additional Resources

- [HTTP/2 Specification (RFC 7540)](https://tools.ietf.org/html/rfc7540)
- [HPACK Specification (RFC 7541)](https://tools.ietf.org/html/rfc7541)
- [Node.js Cluster Documentation](https://nodejs.org/api/cluster.html)

---

## ⚠️ Responsible Use

### Best Practices

1. ✅ Always get **written authorization** before testing
2. ✅ Test on **isolated networks** when possible
3. ✅ **Monitor** target systems during testing
4. ✅ **Limit** test intensity to avoid service disruption
5. ✅ **Document** all testing activities

### Legal Compliance

- ⚠️ **Never test** systems without authorization
- ⚠️ **Understand** local laws regarding network testing
- ⚠️ **Respect** rate limits and terms of service
- ⚠️ **Report** vulnerabilities responsibly

---

<div align="center">

**Made with ❤️ for security research and education**

[⬆ Back to Top](#-tornado-v20-enhanced---http2-load-testing-tool)

---

**Remember:** With great power comes great responsibility. Use this tool ethically and legally.

</div>


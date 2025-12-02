# Changelog

All notable changes to TCP-AMP will be documented in this file.

## [1.0.0] - 2024

### Initial Release

#### Added
- **SYN-ACK Flood** - Generates TCP packets with both SYN and ACK flags set
- **BGP Amplification** - Optional BGP OPEN message payload (79 bytes) for amplification attacks
- **IP Spoofing** - Generates spoofed source IPs across multiple network ranges
- **Random TCP Options** - Implements MSS, Window Scale, Timestamp, and SACK_PERM options
- **Multi-threading** - Supports up to 10,000 concurrent threads for maximum throughput
- **Rate Limiting** - Built-in rate limiter for controlled packet generation
- **SOCKS5 Proxy Support** - Optional proxy support for routing traffic through SOCKS5 proxies
- **Connection State Tracking** - Maintains connection state for realistic packet sequences
- **Real-time Statistics** - Live monitoring of packets per second (PPS), bandwidth, and connection stats
- **Thread-Safe Operations** - Atomic counters and thread-local storage for safe concurrent execution
- **Socket Pooling** - Creates up to 5,000 raw sockets per thread for maximum throughput

#### Technical Details
- Raw socket implementation for direct packet crafting
- Proper IP and TCP checksum calculation
- Realistic BGP OPEN message generation
- Thread-local storage for connection states
- Efficient memory management

#### Documentation
- Comprehensive README.md
- Usage examples
- Architecture documentation
- Protection guides
- Security policy

#### Build System
- Makefile for easy compilation
- Installation targets
- Clean targets


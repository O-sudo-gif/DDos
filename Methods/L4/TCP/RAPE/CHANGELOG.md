# Changelog

All notable changes to TCP-RAPE will be documented in this file.

## [2.0.0] - 2024

### Added - Clever Bypass Techniques
- **Variable TCP Options (0-20 bytes)** - Changed from fixed 40-byte options to variable 0-20 bytes to avoid detection patterns
- **Variable TCP Header Size (doff 5-15)** - Dynamic header size instead of fixed size
- **SYN-First Simulation** - Sends SYN packets first (30-40% chance) to establish proper connection state
- **Variable Payload Sizes** - Most ACK packets have no payload (70% chance), variable sizes (0-1420 bytes)
- **Random Payload Regeneration** - Regenerates random payload each time to avoid 0xFF pattern detection
- **IP ID Patterns Per Connection** - Incremental IP IDs per connection hash (like ack.c)
- **SACK Blocks for Established Connections** - Rarely includes SACK blocks (5% chance) with SLE & SRE
- **Enhanced Rate Limiting Bypass** - Micro-delays (10-100μs) every 50-200 packets

### Enhanced
- **Maximum Power Mode** - Increased sockets from 2,000 to 10,000 per thread
- **Send Buffers** - Increased from 128MB to 512MB per socket
- **Packets Per Burst** - Increased from 3-8 to 10-20 packets per iteration
- **Elite Mode Enabled by Default** - Better bypass capabilities out of the box
- **Improved Connection State Tracking** - Better sequence/ACK number progression
- **Better Window Size Handling** - Uses common window sizes (16384, 32768, 65535)

### Fixed
- Removed duplicate `conn_ip_ids` definition
- Removed unused `last_send_time` variable
- Fixed compilation warnings with pragmas

## [1.0.0] - 2024

### Initial Release
- Multi-vector TCP attack capabilities
- Support for SYN, ACK, FIN, RST, PSH, URG, SYN-ACK, FIN-ACK, MIXED, and ALL modes
- IP spoofing with multiple IP ranges
- Multi-threading support (up to 10,000 threads)
- Real-time statistics
- Elite bypass mode
- Stealth mode with HTTP payloads


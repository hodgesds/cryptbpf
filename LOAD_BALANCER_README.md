# Load Balancer with Client Certificate Session Detection

This example demonstrates an advanced eBPF-based load balancer that uses client certificate fingerprints for session detection and affinity.

## Overview

The load balancer implements:

- **Client Certificate Authentication**: Verifies ECDSA signatures using client certificates
- **Session Detection**: Uses SHA-256 certificate hashes to identify unique clients
- **Session Affinity**: Maintains sticky sessions - same client always routes to same backend
- **Multiple Load Balancing Algorithms**:
  - Round-robin (using consistent hashing)
  - Least connections (routes to backend with fewest active connections)
  - Weighted (distributes based on backend weights)
- **TOML Configuration**: Easy-to-edit configuration file
- **Real-time Statistics**: Tracks sessions, authentication, and backend load

## Architecture

```
┌─────────────┐
│   Client    │ (has ECDSA certificate)
└──────┬──────┘
       │ UDP packet with cert_header
       │ [payload][magic|cert_hash|signature|pubkey_id]
       ↓
┌──────────────────────────────────────────────────┐
│  XDP Load Balancer (Kernel Space)                │
│                                                  │
│  1. Verify ECDSA signature                       │
│  2. Look up or create session (cert_hash)        │
│  3. Select backend (algorithm-based)             │
│  4. Track connection counts                      │
│  5. Forward to backend                           │
└──────────────────┬───────────────────────────────┘
                   │
       ┌───────────┼───────────┐
       ↓           ↓           ↓
  ┌────────┐  ┌────────┐  ┌────────┐
  │Backend │  │Backend │  │Backend │
  │   #0   │  │   #1   │  │   #2   │
  └────────┘  └────────┘  └────────┘
```

## Files Created

### 1. BPF Program
- **`src/bpf/load_balancer.bpf.c`** - Kernel-space load balancer
  - Packet parsing and validation
  - ECDSA signature verification
  - Session tracking and affinity
  - Backend selection algorithms
  - Statistics collection

### 2. Userspace Demo
- **`src/demos/load_balancer.rs`** - Rust userspace controller
  - TOML configuration parsing
  - BPF program loading and attachment
  - Certificate management
  - Statistics monitoring

### 3. Configuration
- **`lb_config.toml`** - Example configuration file
  - Load balancer settings
  - Backend server pool
  - Client certificate configuration

### 4. Build Integration
- Updated `build.rs` to compile the new BPF program
- Updated `src/main.rs` with `load-balancer` subcommand
- Updated `src/demos/mod.rs` to export the module

## Configuration (TOML)

Example `lb_config.toml`:

```toml
[load_balancer]
session_timeout_sec = 300       # Session timeout (5 minutes)
algorithm = "round-robin"       # or "least-connections", "weighted"
require_cert_auth = true        # Require certificate authentication
enabled = true

# Backend servers
[[backends]]
id = 0
ip = "192.168.1.10"
port = 8080
enabled = true
weight = 100
max_connections = 1000

[[backends]]
id = 1
ip = "192.168.1.11"
port = 8080
enabled = true
weight = 100
max_connections = 1000

# Client certificates
[[certificates]]
id = 0
name = "client-cert-1"
generate_on_startup = true      # Generate new keypair for testing
valid_until_days = 365
```

## Usage

### Build

```bash
cargo build --release
```

### Run Load Balancer

```bash
# With default configuration
sudo ./target/release/cryptbpf load-balancer --device eth0

# With custom configuration
sudo ./target/release/cryptbpf load-balancer --device eth0 --config lb_config.toml
```

### Monitor Statistics

The load balancer prints statistics every 5 seconds:

```
=== Load Balancer Statistics ===
Total packets: 1523
Sessions created: 45
Sessions reused: 1478
Auth success: 1523
Auth failed: 0
Cert invalid: 0
Cert expired: 0
No backend available: 0
Load balanced: 1523

=== Backend Statistics ===
Backend #0: 192.168.1.10:8080
  Status: UP
  Current connections: 15/1000
  Total requests: 523
  Total bytes: 1048576

Backend #1: 192.168.1.11:8080
  Status: UP
  Current connections: 15/1000
  Total requests: 500
  Total bytes: 1024000

Backend #2: 192.168.1.12:8080
  Status: UP
  Current connections: 15/1000
  Total requests: 500
  Total bytes: 1024000
```

## Packet Format

Clients must send UDP packets to port 8080 with the following format:

```
[payload_data][cert_header]

cert_header (101 bytes):
  - magic (4 bytes): 0x4C425346 ("LBSF")
  - cert_hash (32 bytes): SHA-256 of client certificate
  - signature (64 bytes): ECDSA signature of payload
  - pubkey_id (1 byte): Certificate ID
  - reserved (3 bytes): Padding
```

## How It Works

### 1. Certificate Verification

When a packet arrives:
1. Extract the `cert_header` from the end of the UDP payload
2. Look up the client certificate using `pubkey_id`
3. Check certificate expiration
4. Hash the payload using `bpf_sha256_hash()`
5. Verify signature using `bpf_ecdsa_verify_secp256r1()`
6. Drop packet if verification fails

### 2. Session Management

After successful authentication:
1. Look up session using `cert_hash` as key
2. If session exists and not expired:
   - Reuse existing backend assignment
   - Update last activity timestamp
3. If session doesn't exist or expired:
   - Select backend using configured algorithm
   - Create new session entry
   - Increment backend connection count

### 3. Load Balancing Algorithms

**Round-Robin (Consistent Hashing)**:
```c
hash = hash_cert_to_backend(cert_hash, num_backends)
backend_id = hash % num_backends
```

**Least Connections**:
```c
Find backend with:
  - Lowest current_connections count
  - Below max_connections limit
  - Enabled and healthy
```

**Weighted**:
```c
Similar to round-robin but considers backend weights
```

### 4. Statistics Tracking

The load balancer tracks:
- Total packets processed
- Sessions created vs reused
- Authentication success/failure
- Certificate validity issues
- Backend availability
- Per-backend request counts and bytes

## BPF Maps

### Configuration Maps
- `certificates_map`: Trusted client certificates (up to 256)
- `backends_map`: Backend server pool (up to 16)
- `lb_config_map`: Load balancer settings

### Runtime Maps
- `sessions_map`: Active sessions (up to 4096)
- `lb_stats_map`: Statistics counters

## Security Considerations

1. **Certificate Validation**: All packets must have valid ECDSA signatures
2. **Expiration Checking**: Expired certificates are rejected
3. **Connection Limits**: Backends enforce max_connections limits
4. **Session Timeout**: Inactive sessions expire after configured timeout
5. **Trusted Certificates Only**: Only pre-configured certificates are accepted

## Performance

- **XDP Attachment**: Processes packets at the earliest point in RX path
- **Kernel-Space Processing**: No context switches to userspace
- **Efficient Hashing**: Fast SHA-256 and consistent hashing
- **ECDSA in BPF**: Hardware-accelerated signature verification
- **Session Affinity**: Minimal overhead for established sessions

## Testing

To test the load balancer, you'll need:

1. **Backend servers** listening on configured IPs/ports
2. **Test clients** that:
   - Generate ECDSA keypairs (secp256r1)
   - Sign packets with private key
   - Include certificate header in packets
   - Send UDP to port 8080

See the `ecdsa_verification` demo for examples of ECDSA signing:

```bash
sudo ./target/release/cryptbpf ecdsa-verification
```

## Kernel Requirements

- Linux kernel 6.5+ with BPF crypto kfunc support
- `CONFIG_BPF=y`
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_CRYPTO_ECDSA=y`
- `CONFIG_DEBUG_INFO_BTF=y`

Check kernel support:

```bash
sudo ./target/release/cryptbpf kernel-check
```

## Future Enhancements

Potential improvements:
- Health check probes for backend servers
- Dynamic backend addition/removal
- Metrics export (Prometheus)
- TLS handshake parsing for real TLS sessions
- IPv6 support
- Connection draining for backend updates
- Rate limiting per client
- Geographic load balancing

## Troubleshooting

**Build fails with "libelf.h not found"**:
```bash
# Ubuntu/Debian
sudo apt-get install libelf-dev

# RHEL/CentOS
sudo yum install elfutils-libelf-devel
```

**XDP attach fails**:
- Ensure running as root
- Check network interface exists
- Verify kernel supports XDP

**No traffic being processed**:
- Verify packets are UDP destined to port 8080
- Check packet format includes cert_header
- Ensure certificates are configured correctly
- Monitor statistics to see counter updates

## References

- eBPF crypto kfuncs: https://docs.kernel.org/bpf/kfuncs.html
- ECDSA secp256r1: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
- XDP programming: https://www.kernel.org/doc/html/latest/networking/af_xdp.html

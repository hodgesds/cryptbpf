// SPDX-License-Identifier: GPL-2.0
/* Load Balancer with Client Certificate Session Detection
 *
 * Implements intelligent load balancing that:
 * - Detects client sessions using certificate fingerprints
 * - Maintains session affinity (sticky sessions)
 * - Distributes load across backend servers
 * - Tracks per-backend connection counts and health
 *
 * Protocol: UDP packets with embedded certificate info
 * Format: [payload][cert_header]
 *   cert_header = {
 *     magic: 0x4C425346 ("LBSF")
 *     cert_hash: SHA-256 of client certificate
 *     signature: ECDSA signature of payload
 *     pubkey_id: Certificate ID
 *   }
 *
 * Use case: TLS-aware load balancing, session persistence,
 *           client authentication at the load balancer level
 */

#include "common.h"

#define MAX_BACKENDS 16
#define MAX_SESSIONS 4096
#define MAX_CERTIFICATES 256
#define LB_PORT 8080

// Magic number for load balancer session frame
#define LB_MAGIC 0x4C425346  // "LBSF"

// Client certificate header (appended to packet)
struct cert_header {
    __u32 magic;                    // LB_MAGIC
    __u8 cert_hash[32];             // SHA-256 of certificate
    __u8 signature[64];             // ECDSA signature of payload
    __u8 pubkey_id;                 // Certificate ID
    __u8 reserved[3];
} __attribute__((packed));

// Client certificate entry (trusted certificates)
struct client_certificate {
    __u8 pubkey[65];                // Uncompressed ECDSA public key
    __u8 cert_hash[32];             // SHA-256 of certificate
    __u64 issued_at;                // Certificate issue time
    __u64 expires_at;               // Certificate expiration
    __u32 sessions_created;         // Number of sessions
    __u8 valid;                     // Certificate is valid
    __u8 reserved[7];
};

// Map of trusted client certificates
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CERTIFICATES);
    __type(key, __u8);              // Certificate ID
    __type(value, struct client_certificate);
} certificates_map SEC(".maps");

// Backend server configuration
struct backend_server {
    __u32 ip_addr;                  // Backend IP address
    __u16 port;                     // Backend port
    __u8 enabled;                   // Server is active
    __u8 health_status;             // 0=down, 1=up
    __u32 weight;                   // Load balancing weight (1-100)
    __u32 max_connections;          // Connection limit
    __u32 current_connections;      // Active connections
    __u64 total_requests;           // Total requests served
    __u64 total_bytes;              // Total bytes transferred
};

// Backend servers configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);             // Backend ID
    __type(value, struct backend_server);
} backends_map SEC(".maps");

// Session tracking
struct session_info {
    __u8 cert_hash[32];             // Client certificate hash
    __u32 client_ip;                // Client IP
    __u32 backend_id;               // Assigned backend ID
    __u64 created_at;               // Session creation time
    __u64 last_activity;            // Last packet time
    __u32 packets_sent;             // Packets in this session
    __u32 bytes_sent;               // Bytes in this session
    __u8 active;                    // Session is active
    __u8 reserved[7];
};

// Active sessions (key: cert_hash)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key, __u8[32]);          // Certificate hash
    __type(value, struct session_info);
} sessions_map SEC(".maps");

// Load balancer configuration
struct lb_config {
    __u32 num_backends;             // Number of configured backends
    __u32 session_timeout_sec;      // Session timeout (seconds)
    __u32 lb_algorithm;             // 0=round-robin, 1=least-conn, 2=weighted
    __u32 require_cert_auth;        // Require certificate authentication
    __u32 enabled;                  // Load balancer enabled
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lb_config);
} lb_config_map SEC(".maps");

// Statistics
struct lb_stats {
    __u64 total_packets;
    __u64 sessions_created;
    __u64 sessions_reused;
    __u64 auth_success;
    __u64 auth_failed;
    __u64 cert_invalid;
    __u64 cert_expired;
    __u64 no_backend_available;
    __u64 load_balanced;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lb_stats);
} lb_stats_map SEC(".maps");

// External kfunc declarations
extern int bpf_sha256_hash(const __u8 *data, __u32 len, __u8 *out) __ksym;
extern int bpf_ecdsa_verify_secp256r1(const __u8 *message, __u32 msg_len,
                                      const __u8 *signature,
                                      const __u8 *public_key) __ksym;

static __always_inline void update_stat(__u64 *counter)
{
    __sync_fetch_and_add(counter, 1);
}

// Simple hash function for consistent hashing
static __always_inline __u32 hash_cert_to_backend(__u8 *cert_hash, __u32 num_backends)
{
    __u32 hash = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        hash = hash * 31 + cert_hash[i];
    }
    return hash % num_backends;
}

// Find least loaded backend
static __always_inline __u32 find_least_loaded_backend(__u32 num_backends)
{
    __u32 best_backend = 0;
    __u32 min_connections = 0xFFFFFFFF;

    #pragma unroll
    for (__u32 i = 0; i < MAX_BACKENDS; i++) {
        if (i >= num_backends)
            break;

        struct backend_server *backend = bpf_map_lookup_elem(&backends_map, &i);
        if (!backend || !backend->enabled || !backend->health_status)
            continue;

        if (backend->current_connections < backend->max_connections &&
            backend->current_connections < min_connections) {
            min_connections = backend->current_connections;
            best_backend = i;
        }
    }

    return best_backend;
}

// Select backend based on load balancing algorithm
static __always_inline __u32 select_backend(struct lb_config *config,
                                            __u8 *cert_hash)
{
    if (config->lb_algorithm == 0) {
        // Round-robin using consistent hashing
        return hash_cert_to_backend(cert_hash, config->num_backends);
    } else if (config->lb_algorithm == 1) {
        // Least connections
        return find_least_loaded_backend(config->num_backends);
    } else {
        // Weighted (simplified: use consistent hash with weights)
        return hash_cert_to_backend(cert_hash, config->num_backends);
    }
}

// Verify client certificate and signature
static __always_inline int verify_client_cert(struct cert_header *hdr,
                                               __u8 *payload,
                                               __u32 payload_len,
                                               struct lb_stats *stats)
{
    // Look up certificate
    struct client_certificate *cert = bpf_map_lookup_elem(&certificates_map,
                                                          &hdr->pubkey_id);
    if (!cert || !cert->valid) {
        if (stats)
            update_stat(&stats->cert_invalid);
        return -1;
    }

    // Check expiration
    __u64 now = bpf_ktime_get_ns() / 1000000000; // Convert to seconds
    if (now > cert->expires_at) {
        if (stats)
            update_stat(&stats->cert_expired);
        return -1;
    }

    // Hash the payload
    __u8 payload_hash[32];
    int ret = bpf_sha256_hash(payload, payload_len, payload_hash);
    if (ret != 0) {
        if (stats)
            update_stat(&stats->auth_failed);
        return -1;
    }

    // Verify signature
    ret = bpf_ecdsa_verify_secp256r1(payload_hash, 32,
                                     hdr->signature, cert->pubkey);
    if (ret != 0) {
        if (stats)
            update_stat(&stats->auth_failed);
        return -1;
    }

    if (stats)
        update_stat(&stats->auth_success);

    return 0;
}

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = parse_ethhdr(data, data_end);
    if (!eth)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *iph = parse_iphdr(eth, data_end);
    if (!iph)
        return XDP_PASS;

    // Only handle UDP packets
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udph = bpf_ptr_add(iph, sizeof(*iph));
    if (bpf_ptr_add(udph, sizeof(*udph)) > data_end)
        return XDP_PASS;

    // Check if destined for load balancer port
    if (udph->dest != bpf_htons(LB_PORT))
        return XDP_PASS;

    // Get configuration and stats
    __u32 key = 0;
    struct lb_config *config = bpf_map_lookup_elem(&lb_config_map, &key);
    if (!config || !config->enabled)
        return XDP_PASS;

    struct lb_stats *stats = bpf_map_lookup_elem(&lb_stats_map, &key);
    if (stats)
        update_stat(&stats->total_packets);

    // Get payload start and calculate payload length
    __u8 *payload_start = bpf_ptr_add(udph, sizeof(*udph));
    __u32 udp_len = bpf_ntohs(udph->len);
    if (udp_len < sizeof(*udph) + sizeof(struct cert_header))
        return XDP_PASS;

    __u32 payload_len = udp_len - sizeof(*udph) - sizeof(struct cert_header);

    // Get certificate header (at end of payload)
    struct cert_header *cert_hdr = bpf_ptr_add(payload_start, payload_len);
    if (bpf_ptr_add(cert_hdr, sizeof(*cert_hdr)) > data_end)
        return XDP_PASS;

    // Verify magic number
    if (cert_hdr->magic != LB_MAGIC)
        return XDP_PASS;

    // Verify client certificate if required
    if (config->require_cert_auth) {
        if (verify_client_cert(cert_hdr, payload_start, payload_len, stats) != 0)
            return XDP_DROP;
    }

    // Look up existing session
    struct session_info *session = bpf_map_lookup_elem(&sessions_map,
                                                       cert_hdr->cert_hash);

    __u64 now = bpf_ktime_get_ns();
    __u32 backend_id;

    if (session && session->active) {
        // Check session timeout
        __u64 age_ns = now - session->last_activity;
        __u64 timeout_ns = (__u64)config->session_timeout_sec * 1000000000ULL;

        if (age_ns < timeout_ns) {
            // Reuse existing session
            backend_id = session->backend_id;
            session->last_activity = now;
            session->packets_sent++;

            if (stats)
                update_stat(&stats->sessions_reused);
        } else {
            // Session expired, create new one
            session->active = 0;
            session = NULL;
        }
    }

    if (!session) {
        // Create new session
        backend_id = select_backend(config, cert_hdr->cert_hash);

        // Check if backend is available
        struct backend_server *backend = bpf_map_lookup_elem(&backends_map,
                                                             &backend_id);
        if (!backend || !backend->enabled || !backend->health_status) {
            if (stats)
                update_stat(&stats->no_backend_available);
            return XDP_DROP;
        }

        // Check connection limit
        if (backend->current_connections >= backend->max_connections) {
            if (stats)
                update_stat(&stats->no_backend_available);
            return XDP_DROP;
        }

        // Create session
        struct session_info new_session = {0};
        __builtin_memcpy(new_session.cert_hash, cert_hdr->cert_hash, 32);
        new_session.client_ip = iph->saddr;
        new_session.backend_id = backend_id;
        new_session.created_at = now;
        new_session.last_activity = now;
        new_session.packets_sent = 1;
        new_session.active = 1;

        bpf_map_update_elem(&sessions_map, cert_hdr->cert_hash,
                           &new_session, BPF_ANY);

        // Update backend connection count
        __sync_fetch_and_add(&backend->current_connections, 1);

        if (stats)
            update_stat(&stats->sessions_created);
    }

    // Update backend statistics
    struct backend_server *backend = bpf_map_lookup_elem(&backends_map, &backend_id);
    if (backend) {
        __sync_fetch_and_add(&backend->total_requests, 1);
        __sync_fetch_and_add(&backend->total_bytes, payload_len);
    }

    if (stats)
        update_stat(&stats->load_balanced);

    // In a real implementation, we would rewrite the packet destination
    // to the selected backend IP and forward it. For this demo, we just
    // track the decision in our maps.

    // TODO: Rewrite destination IP/port to backend
    // TODO: Update checksums
    // TODO: Forward packet

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
/* Cryptographic Rate Limiting with Proof-of-Work
 *
 * Requires clients to provide SHA-256 hash with specific prefix (difficulty)
 * before allowing connections. Computational proof prevents DDoS attacks.
 *
 * Use case: DDoS mitigation, API rate limiting, resource protection
 */

#include "common.h"

#define MAX_CLIENTS 4096
#define POW_PREFIX_BYTES 2      // Require 2 bytes (16 bits) of zeros
#define CHALLENGE_TIMEOUT_NS (60ULL * 1000000000ULL)  // 60 seconds

// Proof-of-Work header structure
struct pow_header {
    __u32 magic;               // 0x504F5721 ("POW!")
    __u8 challenge[32];        // SHA-256 challenge from server
    __u64 nonce;               // Client's nonce solution
    __u8 solution[32];         // SHA-256(challenge || nonce)
} __attribute__((packed));

// Client challenge state
struct client_challenge {
    __u8 challenge[32];        // Issued challenge
    __u64 timestamp;           // When challenge was issued
    __u32 difficulty;          // Number of leading zero bits required
    __u8 active;               // Is challenge active?
    __u8 solved;               // Has client solved it?
};

// Per-client rate limit state
struct client_state {
    __u64 last_packet_time;
    __u32 packet_count;
    __u32 tokens;              // Token bucket for rate limiting
    __u64 last_token_refill;
};

// Map of active challenges per client IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CLIENTS);
    __type(key, __u32);        // Client IP
    __type(value, struct client_challenge);
} challenges_map SEC(".maps");

// Map of client rate limit states
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CLIENTS);
    __type(key, __u32);        // Client IP
    __type(value, struct client_state);
} ratelimit_map SEC(".maps");

// Rate limit configuration
struct ratelimit_config {
    __u32 tokens_per_second;
    __u32 bucket_size;
    __u32 pow_difficulty;      // Number of leading zero bits
    __u32 enabled;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ratelimit_config);
} config_map SEC(".maps");

// Statistics
struct pow_stats {
    __u64 challenges_issued;
    __u64 solutions_verified;
    __u64 solutions_rejected;
    __u64 packets_allowed;
    __u64 packets_ratelimited;
    __u64 invalid_pow;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pow_stats);
} pow_stats_map SEC(".maps");

// External kfunc declarations
extern int bpf_sha256_hash(const __u8 *data, __u32 len, __u8 *out) __ksym;

static __always_inline void update_stat(__u64 *counter)
{
    __sync_fetch_and_add(counter, 1);
}

// Check if hash has required number of leading zero bits
static __always_inline int verify_difficulty(__u8 *hash, __u32 difficulty)
{
    __u32 zero_bytes = difficulty / 8;
    __u32 zero_bits = difficulty % 8;

    // Check full zero bytes
    #pragma unroll
    for (__u32 i = 0; i < POW_PREFIX_BYTES && i < zero_bytes; i++) {
        if (hash[i] != 0)
            return 0;
    }

    // Check partial zero bits in next byte
    if (zero_bits > 0 && zero_bytes < 32) {
        __u8 mask = (1 << (8 - zero_bits)) - 1;
        if ((hash[zero_bytes] & ~mask) != 0)
            return 0;
    }

    return 1;
}

SEC("xdp")
int xdp_crypto_ratelimit(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = parse_ethhdr(data, data_end);
    if (!eth)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = parse_iphdr(eth, data_end);
    if (!iph)
        return XDP_PASS;

    __u32 client_ip = iph->saddr;
    __u32 cfg_key = 0;
    struct ratelimit_config *config = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!config || !config->enabled)
        return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();
    struct pow_stats *stats = bpf_map_lookup_elem(&pow_stats_map, &cfg_key);

    // Look up or create client state
    struct client_state *state = bpf_map_lookup_elem(&ratelimit_map, &client_ip);
    if (!state) {
        // New client - issue challenge
        struct client_challenge challenge = {
            .timestamp = now,
            .difficulty = config->pow_difficulty,
            .active = 1,
            .solved = 0,
        };

        // Generate challenge (use client IP + timestamp as seed)
        __u8 challenge_input[12];
        __builtin_memcpy(challenge_input, &client_ip, 4);
        __builtin_memcpy(challenge_input + 4, &now, 8);

        bpf_sha256_hash(challenge_input, 12, challenge.challenge);
        bpf_map_update_elem(&challenges_map, &client_ip, &challenge, BPF_ANY);

        if (stats)
            update_stat(&stats->challenges_issued);

        // Drop packet - client needs to solve PoW first
        return XDP_DROP;
    }

    // Check if client has active challenge
    struct client_challenge *challenge = bpf_map_lookup_elem(&challenges_map, &client_ip);
    if (challenge && challenge->active && !challenge->solved) {
        // Look for PoW solution in packet
        // For demo, check if TCP payload contains pow_header
        if (iph->protocol != IPPROTO_TCP)
            return XDP_DROP;

        struct tcphdr *tcph = bpf_ptr_add(iph, sizeof(*iph));
        if (bpf_ptr_add(tcph, sizeof(*tcph)) > data_end)
            return XDP_DROP;

        __u8 *payload = bpf_ptr_add(tcph, sizeof(*tcph));
        if (bpf_ptr_add(payload, sizeof(struct pow_header)) > data_end)
            return XDP_DROP;

        struct pow_header *pow = (struct pow_header *)payload;
        if (pow->magic != bpf_htonl(0x504F5721)) {
            if (stats)
                update_stat(&stats->packets_ratelimited);
            return XDP_DROP;
        }

        // Verify the solution hash
        if (!verify_difficulty(pow->solution, challenge->difficulty)) {
            if (stats)
                update_stat(&stats->invalid_pow);
            return XDP_DROP;
        }

        // Verify solution is hash of (challenge || nonce)
        __u8 verify_input[40];  // 32 bytes challenge + 8 bytes nonce
        __builtin_memcpy(verify_input, pow->challenge, 32);
        __builtin_memcpy(verify_input + 32, &pow->nonce, 8);

        __u8 computed_hash[32];
        int ret = bpf_sha256_hash(verify_input, 40, computed_hash);
        if (ret != 0)
            return XDP_DROP;

        // Compare computed hash with provided solution
        int hash_match = 1;
        #pragma unroll
        for (int i = 0; i < 32; i++) {
            if (computed_hash[i] != pow->solution[i]) {
                hash_match = 0;
                break;
            }
        }

        if (!hash_match) {
            if (stats)
                update_stat(&stats->solutions_rejected);
            return XDP_DROP;
        }

        // Valid solution! Mark challenge as solved
        challenge->solved = 1;
        if (stats)
            update_stat(&stats->solutions_verified);

        // Initialize rate limit state
        state->tokens = config->bucket_size;
        state->last_token_refill = now;
        state->last_packet_time = now;
        state->packet_count = 1;
    }

    // Apply token bucket rate limiting
    __u64 time_delta = now - state->last_token_refill;
    __u64 seconds = time_delta / 1000000000ULL;
    if (seconds > 0) {
        __u32 new_tokens = seconds * config->tokens_per_second;
        state->tokens += new_tokens;
        if (state->tokens > config->bucket_size)
            state->tokens = config->bucket_size;
        state->last_token_refill = now;
    }

    // Check if client has tokens available
    if (state->tokens == 0) {
        if (stats)
            update_stat(&stats->packets_ratelimited);
        return XDP_DROP;
    }

    // Consume token and allow packet
    state->tokens--;
    state->last_packet_time = now;
    state->packet_count++;

    if (stats)
        update_stat(&stats->packets_allowed);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

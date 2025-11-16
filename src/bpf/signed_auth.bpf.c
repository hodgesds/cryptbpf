// SPDX-License-Identifier: GPL-2.0
/* Signed Packet Authentication System
 *
 * Implements kernel-level packet signing and verification using ECDSA.
 * Maintains an allow-list of trusted public keys in BPF maps.
 *
 * Use case: Trusted network segments, anti-spoofing, secure IoT communication
 */

#include "common.h"

#define MAX_TRUSTED_KEYS 256
#define SIGNATURE_PORT 9999

// Packet signature header (appended to packet)
struct sig_header {
    __u32 magic;               // 0x5147BEEF
    __u8 signature[64];        // ECDSA signature (r || s)
    __u8 pubkey_id;            // Index into trusted keys map
    __u8 reserved[3];
} __attribute__((packed));

// Trusted public key entry
struct trusted_key {
    __u8 pubkey[65];           // Uncompressed ECDSA public key (0x04 || x || y)
    __u32 packets_verified;
    __u64 last_seen;
    __u8 valid;
};

// Map of trusted public keys
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRUSTED_KEYS);
    __type(key, __u8);         // Key ID
    __type(value, struct trusted_key);
} trusted_keys_map SEC(".maps");

// Statistics
struct sig_stats {
    __u64 packets_verified;
    __u64 packets_rejected;
    __u64 invalid_signature;
    __u64 unknown_key;
    __u64 packets_signed;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sig_stats);
} sig_stats_map SEC(".maps");

// External kfunc declarations (updated for dynptr API)
extern int bpf_sha256_hash(const struct bpf_dynptr *data, const struct bpf_dynptr *out) __ksym;
extern struct bpf_ecdsa_ctx *bpf_ecdsa_ctx_create(const struct bpf_dynptr *algo_name, const struct bpf_dynptr *public_key, int *err) __ksym;
extern void bpf_ecdsa_ctx_release(struct bpf_ecdsa_ctx *ctx) __ksym;
extern int bpf_ecdsa_verify(struct bpf_ecdsa_ctx *ctx, const struct bpf_dynptr *message, const struct bpf_dynptr *signature) __ksym;

// Algorithm name for ECDSA
static const char ecdsa_algo[] = "p1363(ecdsa-nist-p256)";

static __always_inline void update_stat(__u64 *counter)
{
    __sync_fetch_and_add(counter, 1);
}

SEC("xdp")
int xdp_signed_auth(struct xdp_md *ctx)
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

    // Only verify UDP packets on our signature port
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udph = bpf_ptr_add(iph, sizeof(*iph));
    if (bpf_ptr_add(udph, sizeof(*udph)) > data_end)
        return XDP_PASS;

    // Check if this packet is meant to be verified
    if (udph->dest != bpf_htons(SIGNATURE_PORT))
        return XDP_PASS;

    __u32 key = 0;
    struct sig_stats *stats = bpf_map_lookup_elem(&sig_stats_map, &key);

    // Payload should contain: [data][sig_header]
    __u8 *payload_start = bpf_ptr_add(udph, sizeof(*udph));

    // Calculate payload size
    __u16 udp_len = bpf_ntohs(udph->len);
    if (udp_len < sizeof(*udph) + sizeof(struct sig_header))
        return XDP_DROP;

    __u32 payload_len = udp_len - sizeof(*udph);
    __u32 data_len = payload_len - sizeof(struct sig_header);

    // Bounds check
    if (bpf_ptr_add(payload_start, payload_len) > data_end)
        return XDP_DROP;

    // Extract signature header (at end of payload)
    struct sig_header *sighdr = bpf_ptr_add(payload_start, data_len);
    if (bpf_ptr_add(sighdr, sizeof(*sighdr)) > data_end)
        return XDP_DROP;

    // Verify magic
    if (sighdr->magic != bpf_htonl(0x5147BEEF)) {
        if (stats)
            update_stat(&stats->packets_rejected);
        return XDP_DROP;
    }

    // Look up trusted key
    struct trusted_key *tkey = bpf_map_lookup_elem(&trusted_keys_map, &sighdr->pubkey_id);
    if (!tkey || !tkey->valid) {
        if (stats)
            update_stat(&stats->unknown_key);
        return XDP_DROP;
    }

    // Compute SHA-256 hash of the data portion (excluding signature header)
    __u8 hash[32];

    // We need to hash the data, but BPF verifier requires bounded loops
    // For demo, we'll hash a fixed small portion
    // In production, use bpf_sha256_hash with proper bounds
    if (data_len > 1024)
        data_len = 1024;  // Limit for demo

    struct bpf_dynptr data_ptr, out_ptr;
    long ret_init;

    ret_init = bpf_dynptr_from_mem(payload_start, data_len, 0, &data_ptr);
    if (ret_init < 0) {
        if (stats)
            update_stat(&stats->packets_rejected);
        return XDP_DROP;
    }

    ret_init = bpf_dynptr_from_mem(hash, 32, 0, &out_ptr);
    if (ret_init < 0) {
        if (stats)
            update_stat(&stats->packets_rejected);
        return XDP_DROP;
    }

    int ret = bpf_sha256_hash(&data_ptr, &out_ptr);
    if (ret != 0) {
        if (stats)
            update_stat(&stats->packets_rejected);
        return XDP_DROP;
    }

    // Create ECDSA context with trusted key's public key
    char algo_buf[24];
    __builtin_memcpy(algo_buf, ecdsa_algo, 22);
    algo_buf[22] = '\0';

    int err = 0;
    struct bpf_dynptr algo_ptr, pubkey_ptr;

    ret_init = bpf_dynptr_from_mem(algo_buf, 22, 0, &algo_ptr);
    if (ret_init < 0) {
        if (stats)
            update_stat(&stats->packets_rejected);
        return XDP_DROP;
    }

    ret_init = bpf_dynptr_from_mem((__u8 *)tkey->pubkey, 65, 0, &pubkey_ptr);
    if (ret_init < 0) {
        if (stats)
            update_stat(&stats->packets_rejected);
        return XDP_DROP;
    }

    struct bpf_ecdsa_ctx *ecdsa_ctx = bpf_ecdsa_ctx_create(&algo_ptr, &pubkey_ptr, &err);
    if (!ecdsa_ctx) {
        if (stats)
            update_stat(&stats->invalid_signature);
        return XDP_DROP;
    }

    // Prepare message and signature dynptrs
    struct bpf_dynptr msg_ptr, sig_ptr;

    ret_init = bpf_dynptr_from_mem(hash, 32, 0, &msg_ptr);
    if (ret_init < 0) {
        bpf_ecdsa_ctx_release(ecdsa_ctx);
        if (stats)
            update_stat(&stats->invalid_signature);
        return XDP_DROP;
    }

    ret_init = bpf_dynptr_from_mem((__u8 *)sighdr->signature, 64, 0, &sig_ptr);
    if (ret_init < 0) {
        bpf_ecdsa_ctx_release(ecdsa_ctx);
        if (stats)
            update_stat(&stats->invalid_signature);
        return XDP_DROP;
    }

    // Verify ECDSA signature
    ret = bpf_ecdsa_verify(ecdsa_ctx, &msg_ptr, &sig_ptr);

    // Release the context
    bpf_ecdsa_ctx_release(ecdsa_ctx);

    if (ret != 0) {
        if (stats)
            update_stat(&stats->invalid_signature);
        return XDP_DROP;
    }

    // Signature valid! Allow packet
    if (stats)
        update_stat(&stats->packets_verified);

    // Update trusted key stats
    __sync_fetch_and_add(&tkey->packets_verified, 1);
    tkey->last_seen = bpf_ktime_get_ns();

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

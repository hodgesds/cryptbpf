// SPDX-License-Identifier: GPL-2.0
/* Zero-Knowledge Packet Filter
 *
 * This program implements privacy-preserving access control using hash-based
 * zero-knowledge proofs. Clients prove they know a secret without revealing it.
 *
 * Use case: Anonymous authentication, privacy networks, selective disclosure
 */

#include "common.h"

#define MAX_CHALLENGES 1024

// Challenge-response structure for ZKP
struct zkp_challenge {
    __u8 challenge[32];        // Random challenge (SHA-256)
    __u64 timestamp;           // When challenge was issued
    __u32 client_ip;           // Client IP address
    __u8 valid;                // Is this challenge slot valid?
};

// ZKP proof structure (in packet custom header)
struct zkp_proof {
    __u8 response[32];         // H(secret || challenge)
    __u8 challenge[32];        // Original challenge
} __attribute__((packed));

// Map of active challenges
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CHALLENGES);
    __type(key, __u32);        // Client IP
    __type(value, struct zkp_challenge);
} challenge_map SEC(".maps");

// Map of valid secret hashes (H(secret))
// Userspace pre-populates this with allowed users
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u8[32]);     // SHA-256 hash of secret
    __type(value, __u8);       // Just a marker (1 = valid)
} valid_secrets_map SEC(".maps");

// Statistics
struct zkp_stats {
    __u64 challenges_issued;
    __u64 proofs_verified;
    __u64 proofs_rejected;
    __u64 packets_allowed;
    __u64 packets_dropped;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct zkp_stats);
} zkp_stats_map SEC(".maps");

// External kfunc declarations (updated for dynptr API)
extern int bpf_sha256_hash(const struct bpf_dynptr *data, const struct bpf_dynptr *out) __ksym;

static __always_inline void update_stat(__u64 *counter)
{
    __sync_fetch_and_add(counter, 1);
}

SEC("tc")
int tc_zkp_filter(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = parse_ethhdr(data, data_end);
    if (!eth)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = parse_iphdr(eth, data_end);
    if (!iph)
        return TC_ACT_OK;

    // Only process TCP packets for demo
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcph = bpf_ptr_add(iph, sizeof(*iph));
    if (bpf_ptr_add(tcph, sizeof(*tcph)) > data_end)
        return TC_ACT_OK;

    __u32 client_ip = iph->saddr;
    __u32 key = 0;
    struct zkp_stats *stats = bpf_map_lookup_elem(&zkp_stats_map, &key);

    // Check if client has a valid challenge
    struct zkp_challenge *challenge = bpf_map_lookup_elem(&challenge_map, &client_ip);
    if (!challenge || !challenge->valid) {
        // No challenge yet - this would trigger userspace to issue one
        // For demo, we pass packet to userspace
        if (stats)
            update_stat(&stats->challenges_issued);
        return TC_ACT_OK;
    }

    // Look for ZKP proof in TCP payload (simplified - would use TCP options in production)
    __u8 *payload = bpf_ptr_add(tcph, sizeof(*tcph));
    if (bpf_ptr_add(payload, sizeof(struct zkp_proof)) > data_end)
        return TC_ACT_OK;

    struct zkp_proof *proof = (struct zkp_proof *)payload;

    // Verify the challenge matches
    __u8 challenge_match = 1;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (proof->challenge[i] != challenge->challenge[i]) {
            challenge_match = 0;
            break;
        }
    }

    if (!challenge_match) {
        if (stats)
            update_stat(&stats->proofs_rejected);
        return TC_ACT_SHOT;
    }

    // Now verify the ZKP: Check if H(response) exists in valid_secrets_map
    // In a real ZKP system, the response would be: H(secret || challenge)
    // We verify by checking all known secrets to see if any match
    // Note: This is a simplified demonstration. Production ZKP would use
    // more sophisticated cryptographic protocols (e.g., Schnorr, zk-SNARKs)

    __u8 response_hash[32];

    // Initialize dynptr for proof response and output hash
    struct bpf_dynptr data_ptr, out_ptr;
    long ret_init;

    ret_init = bpf_dynptr_from_mem(proof->response, 32, 0, &data_ptr);
    if (ret_init < 0) {
        if (stats)
            update_stat(&stats->proofs_rejected);
        return TC_ACT_SHOT;
    }

    ret_init = bpf_dynptr_from_mem(response_hash, 32, 0, &out_ptr);
    if (ret_init < 0) {
        if (stats)
            update_stat(&stats->proofs_rejected);
        return TC_ACT_SHOT;
    }

    int ret = bpf_sha256_hash(&data_ptr, &out_ptr);
    if (ret != 0) {
        if (stats)
            update_stat(&stats->proofs_rejected);
        return TC_ACT_SHOT;
    }

    // Check if this response hash is in our valid set
    __u8 *valid = bpf_map_lookup_elem(&valid_secrets_map, response_hash);
    if (!valid) {
        if (stats)
            update_stat(&stats->proofs_rejected);
        // Invalid proof - drop packet
        return TC_ACT_SHOT;
    }

    // Valid proof! Allow the packet
    if (stats) {
        update_stat(&stats->proofs_verified);
        update_stat(&stats->packets_allowed);
    }

    // Mark challenge as used (one-time use)
    challenge->valid = 0;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

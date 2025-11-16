// SPDX-License-Identifier: GPL-2.0
/* Content-Addressed Storage Verifier
 *
 * Verifies content-addressed data inline by computing SHA-256 hash of payload
 * and comparing with content identifier in packet header. Drops mismatches.
 *
 * Use case: IPFS-like systems, CDN integrity verification, distributed storage
 */

#include "common.h"

#define MAX_CONTENT_SIZE 4096
#define CID_SIZE 32  // SHA-256 based content ID

// Content-addressed header structure
struct cas_header {
    __u32 magic;               // 0xCA5CA5CA
    __u8 content_id[CID_SIZE]; // SHA-256 hash of content
    __u32 content_len;         // Length of content following this header
    __u16 flags;
    __u16 reserved;
} __attribute__((packed));

// Cached content ID verification results (to avoid re-hashing)
struct cid_cache_entry {
    __u64 last_verified;
    __u32 verify_count;
    __u8 valid;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u8[CID_SIZE]);  // Content ID
    __type(value, struct cid_cache_entry);
} cid_cache_map SEC(".maps");

// Allowlist of known good content IDs (optional - for restricted content systems)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u8[CID_SIZE]);  // Content ID
    __type(value, __u8);          // 1 = allowed
} allowlist_map SEC(".maps");

// Statistics
struct cas_stats {
    __u64 packets_verified;
    __u64 packets_invalid;
    __u64 hash_mismatches;
    __u64 cache_hits;
    __u64 cache_misses;
    __u64 content_too_large;
    __u64 allowlist_hits;
    __u64 allowlist_misses;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cas_stats);
} cas_stats_map SEC(".maps");

// Configuration
struct cas_config {
    __u32 enforce_allowlist;   // If 1, only allow content in allowlist
    __u32 max_content_size;    // Maximum content size to verify
    __u32 use_cache;           // Enable CID caching
    __u32 enabled;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cas_config);
} cas_config_map SEC(".maps");

// External kfunc declarations
extern int bpf_sha256_hash(const __u8 *data, __u32 len, __u8 *out) __ksym;

static __always_inline void update_stat(__u64 *counter)
{
    __sync_fetch_and_add(counter, 1);
}

static __always_inline int compare_hash(__u8 *h1, __u8 *h2)
{
    #pragma unroll
    for (int i = 0; i < CID_SIZE; i++) {
        if (h1[i] != h2[i])
            return 0;
    }
    return 1;
}

SEC("xdp")
int xdp_content_verifier(struct xdp_md *ctx)
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

    // Only verify UDP packets (typical for content distribution)
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udph = bpf_ptr_add(iph, sizeof(*iph));
    if (bpf_ptr_add(udph, sizeof(*udph)) > data_end)
        return XDP_PASS;

    __u32 cfg_key = 0;
    struct cas_config *config = bpf_map_lookup_elem(&cas_config_map, &cfg_key);
    if (!config || !config->enabled)
        return XDP_PASS;

    struct cas_stats *stats = bpf_map_lookup_elem(&cas_stats_map, &cfg_key);

    // Parse CAS header
    __u8 *payload = bpf_ptr_add(udph, sizeof(*udph));
    if (bpf_ptr_add(payload, sizeof(struct cas_header)) > data_end)
        return XDP_PASS;

    struct cas_header *cas = (struct cas_header *)payload;

    // Verify magic
    if (cas->magic != bpf_htonl(0xCA5CA5CA))
        return XDP_PASS;

    // Check content size
    __u32 content_len = bpf_ntohl(cas->content_len);
    if (content_len > config->max_content_size || content_len > MAX_CONTENT_SIZE) {
        if (stats)
            update_stat(&stats->content_too_large);
        bpf_printk("CAS: Content too large (%u bytes) from %pI4, DROP", content_len, &iph->saddr);
        return XDP_DROP;
    }

    bpf_printk("CAS: Verifying content from %pI4 len=%u", &iph->saddr, content_len);

    // Get pointer to actual content
    __u8 *content = bpf_ptr_add(payload, sizeof(struct cas_header));
    if (bpf_ptr_add(content, content_len) > data_end)
        return XDP_DROP;

    // Check cache if enabled
    if (config->use_cache) {
        struct cid_cache_entry *cache_entry = bpf_map_lookup_elem(&cid_cache_map, cas->content_id);
        if (cache_entry && cache_entry->valid) {
            // Cache hit - content was previously verified
            cache_entry->verify_count++;
            cache_entry->last_verified = bpf_ktime_get_ns();
            if (stats) {
                update_stat(&stats->cache_hits);
                update_stat(&stats->packets_verified);
            }
            bpf_printk("CAS: Cache HIT, PASS (count=%u)", cache_entry->verify_count);
            return XDP_PASS;
        }
        if (stats)
            update_stat(&stats->cache_misses);
        bpf_printk("CAS: Cache MISS, computing hash");
    }

    // Compute SHA-256 hash of content
    __u8 computed_hash[32];
    int ret = bpf_sha256_hash(content, content_len, computed_hash);
    if (ret != 0) {
        if (stats)
            update_stat(&stats->packets_invalid);
        return XDP_DROP;
    }

    // Compare computed hash with claimed content ID
    if (!compare_hash(computed_hash, cas->content_id)) {
        if (stats) {
            update_stat(&stats->hash_mismatches);
            update_stat(&stats->packets_invalid);
        }
        bpf_printk("CAS: Hash MISMATCH! Content tampered, DROP");
        // Hash mismatch - content has been tampered with!
        return XDP_DROP;
    }

    bpf_printk("CAS: Hash verified successfully");

    // Check allowlist if enforced
    if (config->enforce_allowlist) {
        __u8 *allowed = bpf_map_lookup_elem(&allowlist_map, cas->content_id);
        if (!allowed) {
            if (stats)
                update_stat(&stats->allowlist_misses);
            bpf_printk("CAS: Content not in allowlist, DROP");
            return XDP_DROP;
        }
        if (stats)
            update_stat(&stats->allowlist_hits);
        bpf_printk("CAS: Allowlist check passed");
    }

    // Content verified! Update cache
    if (config->use_cache) {
        struct cid_cache_entry new_entry = {
            .last_verified = bpf_ktime_get_ns(),
            .verify_count = 1,
            .valid = 1,
        };
        bpf_map_update_elem(&cid_cache_map, cas->content_id, &new_entry, BPF_ANY);
    }

    if (stats)
        update_stat(&stats->packets_verified);

    bpf_printk("CAS: Content verified, PASS");

    return XDP_PASS;
}

// TC egress version for validating outgoing content
SEC("tc")
int tc_content_verifier_egress(struct __sk_buff *skb)
{
    // Similar logic as XDP version, but for outgoing packets
    // Could be used to verify content before sending to ensure integrity
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
/* Hardware-Accelerated Crypto Offload Manager
 *
 * Intelligently routes crypto operations between BPF (software), hardware
 * accelerators, or userspace based on operation size, type, and system load.
 *
 * Use case: Performance optimization on servers with crypto accelerators,
 *           adaptive crypto processing, load balancing
 */

#include "common.h"

#define OFFLOAD_THRESHOLD_SMALL 512    // Bytes - do in BPF
#define OFFLOAD_THRESHOLD_LARGE 4096   // Bytes - offload to hardware

// Crypto operation types
enum crypto_op_type {
    CRYPTO_OP_HASH = 1,
    CRYPTO_OP_ENCRYPT = 2,
    CRYPTO_OP_DECRYPT = 3,
    CRYPTO_OP_SIGN = 4,
    CRYPTO_OP_VERIFY = 5,
};

// Offload decision destinations
enum offload_dest {
    OFFLOAD_BPF = 0,           // Process in BPF
    OFFLOAD_HARDWARE = 1,      // Redirect to hardware
    OFFLOAD_USERSPACE = 2,     // Pass to userspace
};

// Performance counters for adaptive decision making
struct perf_counters {
    __u64 bpf_ops_completed;
    __u64 bpf_ops_failed;
    __u64 bpf_total_latency_ns;
    __u64 hw_ops_completed;
    __u64 hw_ops_failed;
    __u64 hw_total_latency_ns;
    __u64 userspace_ops_completed;
    __u64 userspace_total_latency_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct perf_counters);
} perf_map SEC(".maps");

// Crypto operation request (from packet or program)
struct crypto_request {
    enum crypto_op_type op_type;
    __u32 data_len;
    __u64 timestamp;
    __u32 src_ip;
    __u16 src_port;
} __attribute__((packed));

// Offload decision tracking
struct offload_decision {
    enum offload_dest destination;
    __u64 decision_time;
    __u32 reason;              // Bitmap of decision reasons
};

#define REASON_SIZE_SMALL      (1 << 0)
#define REASON_SIZE_LARGE      (1 << 1)
#define REASON_BPF_FAST        (1 << 2)
#define REASON_HW_AVAILABLE    (1 << 3)
#define REASON_LOAD_BALANCED   (1 << 4)
#define REASON_OP_TYPE         (1 << 5)

// Map storing recent offload decisions (for ML/adaptive learning)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} decisions_log SEC(".maps");

// Configuration
struct offload_config {
    __u32 small_threshold;
    __u32 large_threshold;
    __u32 prefer_bpf_for_hash;    // Hash operations fast in BPF
    __u32 hw_available;            // Hardware accelerator present
    __u32 adaptive_mode;           // Use performance stats for decisions
    __u32 enabled;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct offload_config);
} offload_config_map SEC(".maps");

// Statistics
struct offload_stats {
    __u64 decisions_made;
    __u64 routed_to_bpf;
    __u64 routed_to_hw;
    __u64 routed_to_userspace;
    __u64 small_ops;
    __u64 large_ops;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct offload_stats);
} offload_stats_map SEC(".maps");

// External kfunc declarations (updated for dynptr API)
extern int bpf_sha256_hash(const struct bpf_dynptr *data, const struct bpf_dynptr *out) __ksym;

static __always_inline void update_stat(__u64 *counter)
{
    __sync_fetch_and_add(counter, 1);
}

// Adaptive decision engine based on performance history
static __always_inline enum offload_dest make_decision(struct crypto_request *req,
                                                        struct offload_config *config,
                                                        struct perf_counters *perf,
                                                        __u32 *reason)
{
    *reason = 0;

    // Rule 1: Hash operations < 512 bytes -> BPF (very fast)
    if (req->op_type == CRYPTO_OP_HASH && req->data_len < config->small_threshold) {
        *reason |= REASON_SIZE_SMALL | REASON_OP_TYPE | REASON_BPF_FAST;
        return OFFLOAD_BPF;
    }

    // Rule 2: Very large operations -> hardware if available
    if (req->data_len > config->large_threshold) {
        *reason |= REASON_SIZE_LARGE;
        if (config->hw_available) {
            *reason |= REASON_HW_AVAILABLE;
            return OFFLOAD_HARDWARE;
        }
        // No hardware, send to userspace
        return OFFLOAD_USERSPACE;
    }

    // Rule 3: Medium size operations - adaptive decision
    if (config->adaptive_mode && perf) {
        // Calculate average latency per operation
        __u64 bpf_avg_latency = perf->bpf_ops_completed > 0 ?
            perf->bpf_total_latency_ns / perf->bpf_ops_completed : 0;
        __u64 hw_avg_latency = perf->hw_ops_completed > 0 ?
            perf->hw_total_latency_ns / perf->hw_ops_completed : 0;

        // Prefer hardware if it's faster and available
        if (config->hw_available && hw_avg_latency > 0 &&
            hw_avg_latency < bpf_avg_latency) {
            *reason |= REASON_LOAD_BALANCED | REASON_HW_AVAILABLE;
            return OFFLOAD_HARDWARE;
        }
    }

    // Rule 4: Default to BPF for small-medium operations
    if (req->data_len < OFFLOAD_THRESHOLD_LARGE) {
        *reason |= REASON_SIZE_SMALL | REASON_BPF_FAST;
        return OFFLOAD_BPF;
    }

    // Rule 5: Fallback to userspace
    return OFFLOAD_USERSPACE;
}

SEC("xdp")
int xdp_crypto_offload(struct xdp_md *ctx)
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

    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udph = bpf_ptr_add(iph, sizeof(*iph));
    if (bpf_ptr_add(udph, sizeof(*udph)) > data_end)
        return XDP_PASS;

    __u32 cfg_key = 0;
    struct offload_config *config = bpf_map_lookup_elem(&offload_config_map, &cfg_key);
    if (!config || !config->enabled)
        return XDP_PASS;

    // Parse crypto request from payload
    __u8 *payload = bpf_ptr_add(udph, sizeof(*udph));
    if (bpf_ptr_add(payload, sizeof(struct crypto_request)) > data_end)
        return XDP_PASS;

    struct crypto_request *req = (struct crypto_request *)payload;
    struct perf_counters *perf = bpf_map_lookup_elem(&perf_map, &cfg_key);
    struct offload_stats *stats = bpf_map_lookup_elem(&offload_stats_map, &cfg_key);

    __u32 reason = 0;
    enum offload_dest dest = make_decision(req, config, perf, &reason);

    // Log decision for analysis
    struct offload_decision *decision = bpf_ringbuf_reserve(&decisions_log,
                                                             sizeof(*decision), 0);
    if (decision) {
        decision->destination = dest;
        decision->decision_time = bpf_ktime_get_ns();
        decision->reason = reason;
        bpf_ringbuf_submit(decision, 0);
    }

    if (stats) {
        update_stat(&stats->decisions_made);
        if (req->data_len < config->small_threshold)
            update_stat(&stats->small_ops);
        if (req->data_len > config->large_threshold)
            update_stat(&stats->large_ops);
    }

    // Execute based on decision
    switch (dest) {
    case OFFLOAD_BPF:
        // Process crypto operation in BPF
        if (req->op_type == CRYPTO_OP_HASH) {
            __u64 start = bpf_ktime_get_ns();

            __u8 *hash_data = bpf_ptr_add(payload, sizeof(*req));
            __u32 hash_len = req->data_len;
            if (hash_len > 1024)
                hash_len = 1024;  // Safety limit

            if (bpf_ptr_add(hash_data, hash_len) <= data_end) {
                __u8 hash_out[32];
                struct bpf_dynptr data_ptr, out_ptr;
                long ret_init;

                ret_init = bpf_dynptr_from_mem(hash_data, hash_len, 0, &data_ptr);
                if (ret_init >= 0) {
                    ret_init = bpf_dynptr_from_mem(hash_out, 32, 0, &out_ptr);
                    if (ret_init >= 0) {
                        int ret = bpf_sha256_hash(&data_ptr, &out_ptr);

                        __u64 latency = bpf_ktime_get_ns() - start;
                        if (perf) {
                            __sync_fetch_and_add(&perf->bpf_ops_completed, 1);
                            __sync_fetch_and_add(&perf->bpf_total_latency_ns, latency);
                            if (ret != 0)
                                __sync_fetch_and_add(&perf->bpf_ops_failed, 1);
                        }
                    }
                }
            }
        }

        if (stats)
            update_stat(&stats->routed_to_bpf);
        return XDP_PASS;

    case OFFLOAD_HARDWARE:
        // Redirect to hardware accelerator queue (via XDP_REDIRECT)
        // In production, this would redirect to a specific NIC queue
        // connected to crypto hardware
        if (stats)
            update_stat(&stats->routed_to_hw);
        // For demo, pass to userspace which would handle HW
        return XDP_PASS;

    case OFFLOAD_USERSPACE:
        // Pass to userspace for processing
        if (stats)
            update_stat(&stats->routed_to_userspace);
        return XDP_PASS;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

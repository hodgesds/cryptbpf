// SPDX-License-Identifier: GPL-2.0
/* Simple BPF program for testing hash computation
 *
 * This program demonstrates:
 * 1. Using bpf_sha256_hash() kfunc in BPF
 * 2. Testing with bpf_prog_test_run
 * 3. Comparing BPF hash output with Rust sha2 crate
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SHA256_DIGEST_SIZE 32

// Map to store input data for hashing
// Can be much larger when using maps vs packet data!
#define MAX_INPUT_SIZE 4096
struct input_data {
    __u32 len;
    __u8 data[MAX_INPUT_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct input_data);
} input_data_map SEC(".maps");

// Map to store the computed hash (for verification)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[SHA256_DIGEST_SIZE]);
} hash_output_map SEC(".maps");

// Map to store input data statistics
struct hash_stats {
    __u64 total_hashes;
    __u64 last_input_len;
    __u32 last_hash_first_4_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct hash_stats);
} hash_stats_map SEC(".maps");

// External kfunc declaration
extern int bpf_sha256_hash(const __u8 *data, __u32 len, __u8 *out) __ksym;

// Hash data from a BPF map - much simpler than packet data!
// Use SEC("syscall") for test_run compatibility (like kernel selftests)
SEC("syscall")
int hash_from_map(void *ctx)
{
    __u32 key = 0;

    // Lookup input data from map
    struct input_data *input = bpf_map_lookup_elem(&input_data_map, &key);
    if (!input) {
        bpf_printk("HashTest: ERROR - no input data in map");
        return 1;
    }

    // Validate length
    if (input->len > MAX_INPUT_SIZE) {
        bpf_printk("HashTest: ERROR - input data too large: %u", input->len);
        return 1;
    }

    bpf_printk("HashTest: Hashing %u bytes from map (much simpler!)", input->len);

    // Hash directly from map - no packet bounds checking needed!
    // The verifier knows map memory is safe
    __u8 hash[SHA256_DIGEST_SIZE];
    int ret = bpf_sha256_hash(input->data, input->len, hash);

    if (ret != 0) {
        bpf_printk("HashTest: ERROR - Hash computation failed with code %d", ret);
        return 1;
    }

    // Log first 4 bytes of hash
    __u32 hash_preview = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];
    bpf_printk("HashTest: Hash computed successfully, first 4 bytes: 0x%08x", hash_preview);

    // Store the hash
    bpf_map_update_elem(&hash_output_map, &key, hash, 0);

    // Update statistics
    struct hash_stats *stats = bpf_map_lookup_elem(&hash_stats_map, &key);
    if (stats) {
        stats->total_hashes++;
        stats->last_input_len = input->len;
        stats->last_hash_first_4_bytes = hash_preview;
    }

    bpf_printk("HashTest: Hash stored in map, total hashes: %llu",
               stats ? stats->total_hashes : 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

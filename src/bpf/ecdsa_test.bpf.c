// SPDX-License-Identifier: GPL-2.0
/* ECDSA signature verification test using BPF crypto kfuncs
 *
 * This program demonstrates:
 * 1. Using bpf_ecdsa_verify_secp256r1() kfunc in BPF
 * 2. Testing with bpf_prog_test_run
 * 3. Comparing BPF ECDSA verification with Rust p256 crate
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define SHA256_DIGEST_SIZE 32
#define ECDSA_SIG_SIZE 64
#define ECDSA_PUBKEY_SIZE 65

// Test data structure
struct ecdsa_test_data {
    __u8 message_hash[SHA256_DIGEST_SIZE];
    __u8 signature[ECDSA_SIG_SIZE];
    __u8 public_key[ECDSA_PUBKEY_SIZE];
};

// Map to store test data
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ecdsa_test_data);
} ecdsa_test_map SEC(".maps");

// Map to store verification result
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __s32);  // verification result
} ecdsa_result_map SEC(".maps");

// Statistics
struct ecdsa_stats {
    __u64 total_verifications;
    __u64 successful_verifications;
    __u64 failed_verifications;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ecdsa_stats);
} ecdsa_stats_map SEC(".maps");

// Algorithm name (P1363 format wrapper for standard r||s signatures)
const volatile char algo_name[24] = "p1363(ecdsa-nist-p256)";

// Map to store algorithm name for dynptr creation
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[24]);
} algo_name_map SEC(".maps");

// ECDSA verification using syscall program type (for test_run)
// Kfuncs are declared in vmlinux.h from kernel BTF
// Syscall programs can use sleepable kfuncs with test_run
SEC("syscall")
int ecdsa_verify_from_map(void *ctx)
{
    __u32 key = 0;
    __s32 result;
    int err = 0;

    bpf_printk("ECDSA Test: Starting verification from map");

    // Lookup test data from map
    struct ecdsa_test_data *test_data = bpf_map_lookup_elem(&ecdsa_test_map, &key);
    if (!test_data) {
        bpf_printk("ECDSA Test: ERROR - no test data in map");
        return 1;
    }

    // Verify the public key format (must start with 0x04)
    if (test_data->public_key[0] != 0x04) {
        bpf_printk("ECDSA Test: ERROR - invalid public key format (not uncompressed)");
        result = -22; // -EINVAL
        bpf_map_update_elem(&ecdsa_result_map, &key, &result, 0);
        return 1;
    }

    bpf_printk("ECDSA Test: Verifying signature with secp256r1 (context-based API)");
    bpf_printk("ECDSA Test: Message hash first 4 bytes: 0x%02x%02x%02x%02x",
               test_data->message_hash[0], test_data->message_hash[1],
               test_data->message_hash[2], test_data->message_hash[3]);
    bpf_printk("ECDSA Test: Signature first 4 bytes: 0x%02x%02x%02x%02x",
               test_data->signature[0], test_data->signature[1],
               test_data->signature[2], test_data->signature[3]);
    bpf_printk("ECDSA Test: Public key first 4 bytes: 0x%02x%02x%02x%02x",
               test_data->public_key[0], test_data->public_key[1],
               test_data->public_key[2], test_data->public_key[3]);

    // Get algorithm name from map (needed for dynptr creation from map memory)
    char *algo_buf = bpf_map_lookup_elem(&algo_name_map, &key);
    if (!algo_buf) {
        bpf_printk("ECDSA Test: ERROR - algo name map not initialized");
        result = -1;
        bpf_map_update_elem(&ecdsa_result_map, &key, &result, 0);
        return 1;
    }

    // Create dynptrs from map memory (not stack)
    struct bpf_dynptr algo_ptr, pubkey_ptr;
    long ret_init;

    ret_init = bpf_dynptr_from_mem(algo_buf, 22, 0, &algo_ptr);
    if (ret_init < 0) {
        bpf_printk("ECDSA Test: ERROR - Failed to create algo dynptr: %ld", ret_init);
        result = ret_init;
        bpf_map_update_elem(&ecdsa_result_map, &key, &result, 0);
        return 1;
    }

    ret_init = bpf_dynptr_from_mem((__u8 *)test_data->public_key, ECDSA_PUBKEY_SIZE, 0, &pubkey_ptr);
    if (ret_init < 0) {
        bpf_printk("ECDSA Test: ERROR - Failed to create pubkey dynptr: %ld", ret_init);
        result = ret_init;
        bpf_map_update_elem(&ecdsa_result_map, &key, &result, 0);
        return 1;
    }

    // Create ECDSA context with public key
    // Using p1363() wrapper to handle standard r||s signature format
    struct bpf_ecdsa_ctx *ecdsa_ctx = bpf_ecdsa_ctx_create(&algo_ptr, &pubkey_ptr, &err);

    if (!ecdsa_ctx) {
        bpf_printk("ECDSA Test: ERROR - Failed to create context, err=%d", err);
        result = err;
        bpf_map_update_elem(&ecdsa_result_map, &key, &result, 0);
        return 1;
    }

    bpf_printk("ECDSA Test: Context created successfully");

    // Create dynptrs for message hash and signature (from map memory)
    struct bpf_dynptr msg_ptr, sig_ptr;

    ret_init = bpf_dynptr_from_mem((__u8 *)test_data->message_hash, SHA256_DIGEST_SIZE, 0, &msg_ptr);
    if (ret_init < 0) {
        bpf_printk("ECDSA Test: ERROR - Failed to create msg dynptr: %ld", ret_init);
        bpf_ecdsa_ctx_release(ecdsa_ctx);
        result = ret_init;
        bpf_map_update_elem(&ecdsa_result_map, &key, &result, 0);
        return 1;
    }

    ret_init = bpf_dynptr_from_mem((__u8 *)test_data->signature, ECDSA_SIG_SIZE, 0, &sig_ptr);
    if (ret_init < 0) {
        bpf_printk("ECDSA Test: ERROR - Failed to create sig dynptr: %ld", ret_init);
        bpf_ecdsa_ctx_release(ecdsa_ctx);
        result = ret_init;
        bpf_map_update_elem(&ecdsa_result_map, &key, &result, 0);
        return 1;
    }

    // Verify signature using context
    result = bpf_ecdsa_verify(ecdsa_ctx, &msg_ptr, &sig_ptr);

    // Release the context
    bpf_ecdsa_ctx_release(ecdsa_ctx);

    if (result == 0) {
        bpf_printk("ECDSA Test: ✓ Signature verification PASSED");
    } else if (result == -129) { // -EKEYREJECTED
        bpf_printk("ECDSA Test: ✗ Signature verification FAILED (invalid signature)");
    } else {
        bpf_printk("ECDSA Test: ERROR - Verification returned error code %d", result);
    }

    // Store result
    bpf_map_update_elem(&ecdsa_result_map, &key, &result, 0);

    // Update statistics
    struct ecdsa_stats *stats = bpf_map_lookup_elem(&ecdsa_stats_map, &key);
    if (stats) {
        stats->total_verifications++;
        if (result == 0) {
            stats->successful_verifications++;
        } else {
            stats->failed_verifications++;
        }
    }

    return (result == 0) ? 0 : 1;
}

char LICENSE[] SEC("license") = "GPL";

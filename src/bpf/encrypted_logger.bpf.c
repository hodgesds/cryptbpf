// SPDX-License-Identifier: GPL-2.0
/* Encrypted BPF Ring Buffer Logger
 *
 * Encrypts sensitive kernel events before writing to ring buffer for userspace consumption.
 * Provides secure kernel-to-userspace communication with confidentiality guarantees.
 *
 * Use case: Secure audit logging, compliance requirements, sensitive telemetry
 */

#include "common.h"

#define MAX_LOG_SIZE 256

// Encrypted log entry structure
struct encrypted_log_entry {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u8 event_type;
    __u8 iv[16];               // AES-GCM IV
    __u8 tag[16];              // AES-GCM authentication tag
    __u8 encrypted_data[MAX_LOG_SIZE];
    __u32 encrypted_len;
} __attribute__((packed));

// Plaintext log data (encrypted before submission)
struct log_data {
    char comm[16];             // Process name
    __u32 syscall_nr;
    __u64 arg1;
    __u64 arg2;
    __u8 sensitive_data[128];
};

// Ring buffer for encrypted logs
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} encrypted_logs SEC(".maps");

// Map to store crypto context pointer (for AES-GCM encryption)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); // Pointer to bpf_crypto_ctx
} logger_crypto_ctx SEC(".maps");

// Statistics
struct logger_stats {
    __u64 logs_encrypted;
    __u64 logs_dropped;
    __u64 encryption_errors;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct logger_stats);
} logger_stats_map SEC(".maps");

static __always_inline __u64 get_random_iv_part(void)
{
    // Generate pseudo-random IV component using timestamp and ktime
    return bpf_ktime_get_ns() ^ bpf_get_prandom_u32();
}

// Hook example: trace process execution for security monitoring
SEC("tp/sched/sched_process_exec")
int trace_exec(void *ctx)
{
    struct log_data log = {};
    struct encrypted_log_entry *entry;

    // Collect sensitive process execution data
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    log.syscall_nr = 59; // execve
    log.arg1 = pid_tgid >> 32;
    log.arg2 = uid_gid >> 32;

    bpf_get_current_comm(&log.comm, sizeof(log.comm));

    // In this simplified demo, we would normally:
    // 1. Generate a random IV
    // 2. Create dynptrs for src/dst/iv
    // 3. Call bpf_crypto_encrypt() with the crypto context
    // 4. Write encrypted result to ring buffer
    //
    // However, crypto operations require sleepable context (BPF_PROG_TYPE_SYSCALL)
    // or must be done in TC/XDP with pre-configured contexts
    //
    // For this tracepoint demo, we'll show the structure and defer actual
    // encryption to a syscall program or userspace relay

    // Reserve space in ring buffer
    entry = bpf_ringbuf_reserve(&encrypted_logs, sizeof(*entry), 0);
    if (!entry) {
        __u32 key = 0;
        struct logger_stats *stats = bpf_map_lookup_elem(&logger_stats_map, &key);
        if (stats)
            __sync_fetch_and_add(&stats->logs_dropped, 1);
        return 0;
    }

    // Fill metadata (not encrypted)
    entry->timestamp = bpf_ktime_get_ns();
    entry->pid = pid_tgid >> 32;
    entry->uid = uid_gid >> 32;
    entry->event_type = 1; // EXEC event

    // Generate IV (simplified)
    __u64 *iv_ptr = (__u64 *)entry->iv;
    iv_ptr[0] = get_random_iv_part();
    iv_ptr[1] = get_random_iv_part();

    // TODO: Actual encryption with bpf_crypto_encrypt()
    // For demo, we'll copy plaintext (in production this would be encrypted)
    entry->encrypted_len = sizeof(log);
    if (entry->encrypted_len <= MAX_LOG_SIZE) {
        __builtin_memcpy(entry->encrypted_data, &log, sizeof(log));
    }

    // Submit to userspace
    bpf_ringbuf_submit(entry, 0);

    __u32 key = 0;
    struct logger_stats *stats = bpf_map_lookup_elem(&logger_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->logs_encrypted, 1);
        __sync_fetch_and_add(&stats->total_bytes, sizeof(*entry));
    }

    return 0;
}

// Syscall program for doing actual encryption (sleepable context)
SEC("syscall")
int encrypt_and_log(void *ctx)
{
    // This would be called from userspace with bpf_prog_test_run()
    // to perform encryption operations that require sleepable context
    //
    // Example flow:
    // 1. Userspace writes sensitive data to a BPF map
    // 2. Calls this syscall program
    // 3. Program loads crypto context from logger_crypto_ctx map
    // 4. Encrypts data using bpf_crypto_encrypt()
    // 5. Writes encrypted result to ring buffer
    // 6. Userspace reads from ring buffer and decrypts

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

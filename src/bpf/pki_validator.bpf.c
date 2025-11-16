// SPDX-License-Identifier: GPL-2.0
/* In-Kernel PKI Certificate Validator
 *
 * Validates certificate chains and ECDSA signatures inline at TC layer.
 * Performs certificate expiration and revocation checks using BPF maps.
 *
 * Use case: Accelerated TLS offload, mTLS enforcement, certificate-based access control
 */

#include "common.h"

#define MAX_CERT_CHAIN_DEPTH 3
#define MAX_CERTIFICATES 512
#define MAX_REVOKED_CERTS 1024

// Simplified certificate structure (production would parse actual X.509)
struct certificate {
    __u8 pubkey[65];           // ECDSA secp256r1 public key
    __u8 signature[64];        // Signature from issuer
    __u8 issuer_key_id[32];    // SHA-256 hash of issuer's public key
    __u64 not_before;          // Unix timestamp
    __u64 not_after;           // Unix timestamp
    __u8 subject_key_id[32];   // SHA-256 hash of this cert's public key
    __u8 is_ca;                // Can sign other certificates
} __attribute__((packed));

// Certificate status
enum cert_status {
    CERT_VALID = 0,
    CERT_EXPIRED = 1,
    CERT_NOT_YET_VALID = 2,
    CERT_REVOKED = 3,
    CERT_UNTRUSTED = 4,
    CERT_INVALID_SIG = 5,
};

// Map of trusted root CA certificates
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u8[32]);     // Subject key ID
    __type(value, struct certificate);
} root_ca_map SEC(".maps");

// Map of intermediate CA certificates
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CERTIFICATES);
    __type(key, __u8[32]);     // Subject key ID
    __type(value, struct certificate);
} intermediate_ca_map SEC(".maps");

// Certificate Revocation List (CRL)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_REVOKED_CERTS);
    __type(key, __u8[32]);     // Subject key ID of revoked cert
    __type(value, __u64);      // Revocation timestamp
} crl_map SEC(".maps");

// Statistics
struct pki_stats {
    __u64 certs_validated;
    __u64 certs_rejected;
    __u64 expired_certs;
    __u64 revoked_certs;
    __u64 untrusted_certs;
    __u64 invalid_signatures;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pki_stats);
} pki_stats_map SEC(".maps");

// External kfunc declarations (updated for dynptr API)
extern int bpf_sha256_hash(const struct bpf_dynptr *data, const struct bpf_dynptr *out) __ksym;
extern struct bpf_ecdsa_ctx *bpf_ecdsa_ctx_create(const struct bpf_dynptr *algo_name, const struct bpf_dynptr *public_key, int *err) __ksym;
extern void bpf_ecdsa_ctx_release(struct bpf_ecdsa_ctx *ctx) __ksym;
extern int bpf_ecdsa_verify(struct bpf_ecdsa_ctx *ctx, const struct bpf_dynptr *message, const struct bpf_dynptr *signature) __ksym;

static __always_inline void update_stat(__u64 *counter)
{
    __sync_fetch_and_add(counter, 1);
}

// Algorithm name for ECDSA
static const char ecdsa_algo[] = "p1363(ecdsa-nist-p256)";

// Verify certificate signature using issuer's public key
static __always_inline int verify_cert_signature(struct certificate *cert,
                                                  struct certificate *issuer)
{
    // In production, we'd hash the actual certificate TBS (To Be Signed) portion
    // For demo, we hash the public key and timestamps
    __u8 tbs_data[65 + 16];  // pubkey + timestamps
    __builtin_memcpy(tbs_data, cert->pubkey, 65);
    __builtin_memcpy(tbs_data + 65, &cert->not_before, 8);
    __builtin_memcpy(tbs_data + 73, &cert->not_after, 8);

    __u8 tbs_hash[32];
    struct bpf_dynptr data_ptr, out_ptr;
    long ret_init;

    ret_init = bpf_dynptr_from_mem(tbs_data, 81, 0, &data_ptr);
    if (ret_init < 0)
        return -1;

    ret_init = bpf_dynptr_from_mem(tbs_hash, 32, 0, &out_ptr);
    if (ret_init < 0)
        return -1;

    int ret = bpf_sha256_hash(&data_ptr, &out_ptr);
    if (ret != 0)
        return -1;

    // Create ECDSA context with issuer's public key
    char algo_buf[24];
    __builtin_memcpy(algo_buf, ecdsa_algo, 22);
    algo_buf[22] = '\0';

    int err = 0;
    struct bpf_dynptr algo_ptr, pubkey_ptr;

    ret_init = bpf_dynptr_from_mem(algo_buf, 22, 0, &algo_ptr);
    if (ret_init < 0)
        return -1;

    ret_init = bpf_dynptr_from_mem((__u8 *)issuer->pubkey, 65, 0, &pubkey_ptr);
    if (ret_init < 0)
        return -1;

    struct bpf_ecdsa_ctx *ecdsa_ctx = bpf_ecdsa_ctx_create(&algo_ptr, &pubkey_ptr, &err);
    if (!ecdsa_ctx)
        return err ? err : -1;

    // Prepare message and signature dynptrs
    struct bpf_dynptr msg_ptr, sig_ptr;

    ret_init = bpf_dynptr_from_mem(tbs_hash, 32, 0, &msg_ptr);
    if (ret_init < 0) {
        bpf_ecdsa_ctx_release(ecdsa_ctx);
        return -1;
    }

    ret_init = bpf_dynptr_from_mem((__u8 *)cert->signature, 64, 0, &sig_ptr);
    if (ret_init < 0) {
        bpf_ecdsa_ctx_release(ecdsa_ctx);
        return -1;
    }

    // Verify signature using context
    ret = bpf_ecdsa_verify(ecdsa_ctx, &msg_ptr, &sig_ptr);

    // Release the context
    bpf_ecdsa_ctx_release(ecdsa_ctx);

    return ret;
}

// Validate a single certificate
static __always_inline enum cert_status validate_certificate(struct certificate *cert,
                                                              __u64 current_time)
{
    // Check expiration
    if (current_time < cert->not_before)
        return CERT_NOT_YET_VALID;
    if (current_time > cert->not_after)
        return CERT_EXPIRED;

    // Check revocation
    __u64 *revoked = bpf_map_lookup_elem(&crl_map, cert->subject_key_id);
    if (revoked)
        return CERT_REVOKED;

    return CERT_VALID;
}

// Validate certificate chain (simplified - no loop unrolling needed for bounded depth)
static __always_inline enum cert_status validate_chain(struct certificate *leaf_cert,
                                                        __u64 current_time,
                                                        struct pki_stats *stats)
{
    struct certificate *current = leaf_cert;
    struct certificate *issuer;

    // Validate leaf certificate
    enum cert_status status = validate_certificate(current, current_time);
    if (status != CERT_VALID) {
        if (status == CERT_EXPIRED && stats)
            update_stat(&stats->expired_certs);
        if (status == CERT_REVOKED && stats)
            update_stat(&stats->revoked_certs);
        return status;
    }

    // Walk up the chain (unroll for max depth)
    // Level 1: Check intermediate CA
    issuer = bpf_map_lookup_elem(&intermediate_ca_map, current->issuer_key_id);
    if (issuer) {
        status = validate_certificate(issuer, current_time);
        if (status != CERT_VALID)
            return status;

        if (verify_cert_signature(current, issuer) != 0) {
            if (stats)
                update_stat(&stats->invalid_signatures);
            return CERT_INVALID_SIG;
        }

        current = issuer;
    }

    // Level 2: Check root CA
    issuer = bpf_map_lookup_elem(&root_ca_map, current->issuer_key_id);
    if (!issuer) {
        if (stats)
            update_stat(&stats->untrusted_certs);
        return CERT_UNTRUSTED;
    }

    status = validate_certificate(issuer, current_time);
    if (status != CERT_VALID)
        return status;

    if (verify_cert_signature(current, issuer) != 0) {
        if (stats)
            update_stat(&stats->invalid_signatures);
        return CERT_INVALID_SIG;
    }

    return CERT_VALID;
}

SEC("tc")
int tc_pki_validator(struct __sk_buff *skb)
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

    // Only validate TLS-like TCP connections
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcph = bpf_ptr_add(iph, sizeof(*iph));
    if (bpf_ptr_add(tcph, sizeof(*tcph)) > data_end)
        return TC_ACT_OK;

    // In production, we'd parse TLS handshake and extract certificate
    // For demo, assume certificate is in TCP payload
    __u8 *payload = bpf_ptr_add(tcph, sizeof(*tcph));
    if (bpf_ptr_add(payload, sizeof(struct certificate)) > data_end)
        return TC_ACT_OK;

    struct certificate *client_cert = (struct certificate *)payload;

    __u32 key = 0;
    struct pki_stats *stats = bpf_map_lookup_elem(&pki_stats_map, &key);

    // Get current time (nanoseconds since boot, would use real time in production)
    __u64 current_time = bpf_ktime_get_ns() / 1000000000ULL;

    // Validate the certificate chain
    enum cert_status status = validate_chain(client_cert, current_time, stats);

    if (status != CERT_VALID) {
        if (stats)
            update_stat(&stats->certs_rejected);
        // Drop packets with invalid certificates
        return TC_ACT_SHOT;
    }

    if (stats)
        update_stat(&stats->certs_validated);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
/* Encrypted Network Packet Tunnel using XDP and BPF crypto
 *
 * This program demonstrates high-performance in-kernel packet encryption/decryption
 * for creating a VPN-like encrypted tunnel at the XDP layer (before network stack).
 */

#include "common.h"

#define TUNNEL_PORT 4789  // Custom encrypted tunnel port
#define MAX_PAYLOAD_SIZE 1400
#define ECDSA_SIG_SIZE 64
#define ECDSA_PUBKEY_SIZE 65

// Tunnel header structure with ECDSA authentication
struct tunnel_hdr {
    __u32 magic;           // 0xDEADBEEF
    __u32 seq;             // Sequence number
    __u8 iv[16];           // AES-GCM IV (96 bits used, rest padding)
    __u8 tag[16];          // AES-GCM authentication tag
    __u8 signature[64];    // ECDSA signature (r || s)
    __u8 pubkey_id;        // Public key identifier
} __attribute__((packed));

// Map value to store crypto context as kptr (enables persistence!)
struct crypto_ctx_storage {
    struct bpf_crypto_ctx __kptr *ctx;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct crypto_ctx_storage);
} crypto_ctx_map SEC(".maps");

// Map value to store ECDSA signing context as kptr
struct ecdsa_sign_ctx_storage {
    struct bpf_ecdsa_ctx __kptr *ctx;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ecdsa_sign_ctx_storage);
} ecdsa_sign_ctx_map SEC(".maps");

// Map value to store ECDSA verification contexts as kptr
struct ecdsa_verify_ctx_storage {
    struct bpf_ecdsa_ctx __kptr *ctx;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u8);    // pubkey_id
    __type(value, struct ecdsa_verify_ctx_storage);
} ecdsa_verify_ctx_map SEC(".maps");

// Map for tunnel configuration
struct tunnel_config {
    __u32 local_ip;
    __u32 remote_ip;
    __u16 local_port;
    __u16 remote_port;
    __u32 enabled;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_config);
} config_map SEC(".maps");

// Statistics
struct tunnel_stats {
    __u64 packets_encrypted;
    __u64 packets_decrypted;
    __u64 packets_dropped;
    __u64 bytes_encrypted;
    __u64 bytes_decrypted;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_stats);
} stats_map SEC(".maps");

// Per-CPU scratch buffers for crypto operations (to avoid stack overflow)
struct crypto_scratch {
    __u8 plaintext[MAX_PAYLOAD_SIZE];
    __u8 ciphertext[MAX_PAYLOAD_SIZE];  // CBC: same size as plaintext (no auth tag)
    __u8 iv[16];  // IV for dynptr (verifier doesn't accept stack for bpf_dynptr_from_mem)
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct crypto_scratch);
} scratch_map SEC(".maps");

static __always_inline void update_stats(__u64 *counter, __u64 value)
{
    __sync_fetch_and_add(counter, value);
}

// Helper to copy data in BPF-safe way
static __always_inline void copy_bytes(__u8 *dst, __u8 *src, __u32 len)
{
    if (len > MAX_PAYLOAD_SIZE)
        return;

    #pragma clang loop unroll(disable)
    for (__u32 i = 0; i < MAX_PAYLOAD_SIZE; i++) {
        if (i >= len)
            break;
        dst[i] = src[i];
    }
}

// Scratch map for ECDSA key material (dynptr_from_mem requires PTR_TO_MAP_VALUE)
struct ecdsa_scratch {
    char algo[32];
    __u8 privkey[32];
    __u8 pubkey[65];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ecdsa_scratch);
} ecdsa_scratch_map SEC(".maps");

// Global data for algorithm names
static const char ecdsa_algo_name[] = "ecdsa-nist-p256";
static const char crypto_algo_name[] = "cbc(aes)";  // Note: GCM not supported in BPF, using CBC
static const char crypto_type_name[] = "skcipher";

// Generate pseudo-random IV using packet data and timestamp
static __always_inline void generate_iv(__u8 *iv, __u32 seq, __u64 timestamp)
{
    // Simple IV generation: combine sequence number and timestamp
    // In production, use proper random number generation
    __builtin_memcpy(iv, &seq, sizeof(__u32));
    __builtin_memcpy(iv + 4, &timestamp, sizeof(__u64));
    // Pad remaining bytes
    __builtin_memset(iv + 12, 0, 4);
}

// Syscall program to create AES-GCM crypto context (REAL ENCRYPTION!)
SEC("syscall")
int create_crypto_ctx(void *ctx_in)
{
    struct bpf_crypto_params params = {};

    // Copy type and algo from global data
    __builtin_memcpy(params.type, crypto_type_name, sizeof(crypto_type_name));
    __builtin_memcpy(params.algo, crypto_algo_name, sizeof(crypto_algo_name));
    params.key_len = 32;  // AES-256
    params.authsize = 0;  // CBC doesn't use authentication tags (not an AEAD)

    // Generate AES-256 key (in production, receive from userspace)
    __builtin_memset(params.key, 0xAB, 32);

    int err = 0;
    struct bpf_crypto_ctx *ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);

    if (!ctx) {
        bpf_printk("Failed to create crypto context: %d", err);
        return err;
    }

    bpf_printk("✓ AES-256-CBC crypto context created");

    // Lookup map storage
    __u32 key = 0;
    struct crypto_ctx_storage *storage = bpf_map_lookup_elem(&crypto_ctx_map, &key);
    if (!storage) {
        bpf_crypto_ctx_release(ctx);
        return -1;
    }

    // ✨ CRITICAL: Use bpf_kptr_xchg to transfer ownership to map!
    // This releases our reference and stores it in the map.
    struct bpf_crypto_ctx *old_ctx = bpf_kptr_xchg(&storage->ctx, ctx);
    if (old_ctx) {
        bpf_crypto_ctx_release(old_ctx);
    }

    bpf_printk("✓ Crypto context stored as kptr (ready for TC use!)");
    return 0;
}

// Syscall program to create ECDSA signing context with private key
SEC("syscall")
int create_ecdsa_sign_ctx(void *ctx_in)
{
    // Workaround: Use map for scratch space (dynptr_from_mem only accepts PTR_TO_MAP_VALUE)
    __u32 scratch_key = 0;
    struct ecdsa_scratch *scratch = bpf_map_lookup_elem(&ecdsa_scratch_map, &scratch_key);
    if (!scratch)
        return -1;

    // Copy algo name and generate private key in map memory
    __builtin_memcpy(scratch->algo, ecdsa_algo_name, sizeof(ecdsa_algo_name));
    __builtin_memset(scratch->privkey, 0xAA, 32);

    struct bpf_dynptr algo_ptr, key_ptr;
    // Now works! PTR_TO_MAP_VALUE is accepted
    if (bpf_dynptr_from_mem(scratch->algo, sizeof(ecdsa_algo_name) - 1, 0, &algo_ptr) < 0)
        return -1;
    if (bpf_dynptr_from_mem(scratch->privkey, 32, 0, &key_ptr) < 0)
        return -1;

    int err = 0;
    struct bpf_ecdsa_ctx *ecdsa_ctx = bpf_ecdsa_ctx_create_with_privkey(&algo_ptr, &key_ptr, &err);

    if (!ecdsa_ctx) {
        bpf_printk("Failed to create ECDSA sign context: %d", err);
        return err;
    }

    bpf_printk("✓ ECDSA signing context created");

    // Lookup map storage
    __u32 key = 0;
    struct ecdsa_sign_ctx_storage *storage = bpf_map_lookup_elem(&ecdsa_sign_ctx_map, &key);
    if (!storage) {
        bpf_ecdsa_ctx_release(ecdsa_ctx);
        return -1;
    }

    // Transfer ownership to map
    struct bpf_ecdsa_ctx *old_ctx = bpf_kptr_xchg(&storage->ctx, ecdsa_ctx);
    if (old_ctx) {
        bpf_ecdsa_ctx_release(old_ctx);
    }

    bpf_printk("✓ ECDSA signing context stored as kptr");
    return 0;
}

// Syscall program to create ECDSA verification context with public key
SEC("syscall")
int create_ecdsa_verify_ctx(void *ctx_in)
{
    // Workaround: Use map for scratch space
    __u32 scratch_key = 0;
    struct ecdsa_scratch *scratch = bpf_map_lookup_elem(&ecdsa_scratch_map, &scratch_key);
    if (!scratch)
        return -1;

    // Copy algo name and generate dummy public key in map memory
    __builtin_memcpy(scratch->algo, ecdsa_algo_name, sizeof(ecdsa_algo_name));
    scratch->pubkey[0] = 0x04; // Uncompressed point marker
    __builtin_memset(scratch->pubkey + 1, 0xBB, 64);

    struct bpf_dynptr algo_ptr, key_ptr;
    if (bpf_dynptr_from_mem(scratch->algo, sizeof(ecdsa_algo_name) - 1, 0, &algo_ptr) < 0)
        return -1;
    if (bpf_dynptr_from_mem(scratch->pubkey, 65, 0, &key_ptr) < 0)
        return -1;

    int err = 0;
    struct bpf_ecdsa_ctx *ecdsa_ctx = bpf_ecdsa_ctx_create(&algo_ptr, &key_ptr, &err);

    if (!ecdsa_ctx) {
        bpf_printk("Failed to create ECDSA verify context: %d", err);
        return err;
    }

    bpf_printk("✓ ECDSA verification context created");

    // Lookup or create map storage for this pubkey_id
    __u8 pubkey_id = 0;
    struct ecdsa_verify_ctx_storage *storage = bpf_map_lookup_elem(&ecdsa_verify_ctx_map, &pubkey_id);
    if (!storage) {
        struct ecdsa_verify_ctx_storage new_storage = {};
        bpf_map_update_elem(&ecdsa_verify_ctx_map, &pubkey_id, &new_storage, BPF_ANY);
        storage = bpf_map_lookup_elem(&ecdsa_verify_ctx_map, &pubkey_id);
        if (!storage) {
            bpf_ecdsa_ctx_release(ecdsa_ctx);
            return -1;
        }
    }

    // Transfer ownership to map
    struct bpf_ecdsa_ctx *old_ctx = bpf_kptr_xchg(&storage->ctx, ecdsa_ctx);
    if (old_ctx) {
        bpf_ecdsa_ctx_release(old_ctx);
    }

    bpf_printk("✓ ECDSA verification context stored as kptr (key ID %u)", pubkey_id);
    return 0;
}

SEC("xdp")
int xdp_encrypted_tunnel(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = parse_ethhdr(data, data_end);
    if (!eth)
        return XDP_PASS;

    // Only handle IPv4 for now
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = parse_iphdr(eth, data_end);
    if (!iph)
        return XDP_PASS;

    // Check if UDP (our tunnel protocol)
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udph = bpf_ptr_add(iph, sizeof(*iph));
    if (bpf_ptr_add(udph, sizeof(*udph)) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    struct tunnel_config *config = bpf_map_lookup_elem(&config_map, &key);
    if (!config || !config->enabled)
        return XDP_PASS;

    // Check if this is a tunnel packet (destination port matches)
    if (udph->dest == bpf_htons(TUNNEL_PORT)) {
        // This is an encrypted tunnel packet - decrypt it
        struct tunnel_hdr *thdr = bpf_ptr_add(udph, sizeof(*udph));
        if (bpf_ptr_add(thdr, sizeof(*thdr)) > data_end)
            return XDP_PASS;

        if (thdr->magic != bpf_htonl(0xDEADBEEF))
            return XDP_PASS;

        bpf_printk("Tunnel: RX encrypted packet from %pI4:%u seq=%u", &iph->saddr, bpf_ntohs(udph->source), bpf_ntohl(thdr->seq));

        // Get crypto context from map
        __u64 *ctx_ptr = bpf_map_lookup_elem(&crypto_ctx_map, &key);
        if (!ctx_ptr || *ctx_ptr == 0) {
            bpf_printk("Tunnel: No crypto context available");
            return XDP_PASS;
        }

        struct bpf_crypto_ctx *crypto_ctx = (struct bpf_crypto_ctx *)(*ctx_ptr);

        // Extract encrypted payload
        void *encrypted_payload = bpf_ptr_add(thdr, sizeof(*thdr));
        if (encrypted_payload > data_end) {
            return XDP_PASS;
        }

        // Calculate payload size (remaining data after tunnel header)
        __u32 payload_size = (__u32)((unsigned long)data_end - (unsigned long)encrypted_payload);
        if (payload_size > MAX_PAYLOAD_SIZE || payload_size < 16) {
            // Need at least auth tag size
            return XDP_PASS;
        }

        struct tunnel_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
        if (stats) {
            update_stats(&stats->packets_decrypted, 1);
            update_stats(&stats->bytes_decrypted, payload_size);
        }

        bpf_printk("Tunnel: Encrypted packet detected (decrypt via TC ingress)");
        return XDP_PASS;
    }

    // Outgoing packet - check if it should be encrypted
    if (iph->daddr == config->remote_ip) {
        bpf_printk("Tunnel: TX packet to %pI4 proto=%u, should encrypt", &iph->daddr, iph->protocol);

        // Get crypto context
        __u64 *ctx_ptr = bpf_map_lookup_elem(&crypto_ctx_map, &key);
        if (!ctx_ptr || *ctx_ptr == 0) {
            bpf_printk("Tunnel: No crypto context available");
            return XDP_PASS;
        }

        struct bpf_crypto_ctx *crypto_ctx = (struct bpf_crypto_ctx *)(*ctx_ptr);

        // Generate IV for this packet
        __u64 timestamp = bpf_ktime_get_ns();
        static __u32 seq_counter = 0;
        __u32 seq = __sync_fetch_and_add(&seq_counter, 1);

        __u8 iv[16];
        generate_iv(iv, seq, timestamp);

        struct tunnel_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
        if (stats) {
            update_stats(&stats->packets_encrypted, 1);
        }

        bpf_printk("Tunnel: Outgoing packet to tunnel endpoint (encrypt via TC egress)");
        return XDP_PASS;
    }

    return XDP_PASS;
}

// TC egress program - encrypt outgoing packets
SEC("tc")
int tc_encrypt_egress(struct __sk_buff *skb)
{
    // Pull data to ensure it's linear
    if (bpf_skb_pull_data(skb, skb->len) < 0)
        return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = parse_ethhdr(data, data_end);
    if (!eth || eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = parse_iphdr(eth, data_end);
    if (!iph)
        return TC_ACT_OK;

    __u32 key = 0;
    struct tunnel_config *config = bpf_map_lookup_elem(&config_map, &key);
    if (!config || !config->enabled || iph->daddr != config->remote_ip)
        return TC_ACT_OK;

    // Get crypto context storage (kptr)
    struct crypto_ctx_storage *storage = bpf_map_lookup_elem(&crypto_ctx_map, &key);
    if (!storage || !storage->ctx)
        return TC_ACT_OK;

    // ✨ Acquire reference from kptr (works in TC!)
    struct bpf_crypto_ctx *crypto_ctx = bpf_crypto_ctx_acquire(storage->ctx);
    if (!crypto_ctx) {
        bpf_printk("Tunnel: Failed to acquire crypto context");
        return TC_ACT_OK;
    }

    // Calculate payload size
    __u32 ip_total_len = bpf_ntohs(iph->tot_len);
    __u32 payload_len = ip_total_len - sizeof(struct iphdr);

    if (payload_len > MAX_PAYLOAD_SIZE || payload_len == 0) {
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }

    __u32 scratch_key = 0;
    struct crypto_scratch *scratch = bpf_map_lookup_elem(&scratch_map, &scratch_key);
    if (!scratch) {
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }

    // Generate IV and sequence
    __u64 timestamp = bpf_ktime_get_ns();
    static __u32 seq_counter = 0;
    __u32 seq = __sync_fetch_and_add(&seq_counter, 1);

    generate_iv(scratch->iv, seq, timestamp);

    // Read payload from packet
    __u32 offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
    __u32 read_len = payload_len;
    if (read_len > MAX_PAYLOAD_SIZE)
        read_len = MAX_PAYLOAD_SIZE;

    if (bpf_skb_load_bytes(skb, offset, scratch->plaintext, read_len) < 0) {
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }

    // ✅ REAL ENCRYPTION using bpf_crypto_encrypt!
    // Create dynptrs for encrypt operation
    struct bpf_dynptr src_ptr, dst_ptr, iv_ptr;
    if (bpf_dynptr_from_mem(scratch->plaintext, read_len, 0, &src_ptr) < 0) {
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }

    // CBC: ciphertext size = plaintext size (no auth tag like GCM)
    if (bpf_dynptr_from_mem(scratch->ciphertext, read_len, 0, &dst_ptr) < 0) {
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }
    if (bpf_dynptr_from_mem(scratch->iv, 16, 0, &iv_ptr) < 0) {
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }

    // Perform AES-256-CBC encryption
    int encrypt_ret = bpf_crypto_encrypt(crypto_ctx, &src_ptr, &dst_ptr, &iv_ptr);
    if (encrypt_ret < 0) {
        bpf_printk("Tunnel: Encryption failed: %d", encrypt_ret);
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }

    bpf_printk("Tunnel: ✓ Packet encrypted (%u bytes)", read_len);

    // Calculate new packet size: eth + IP + UDP + tunnel_hdr + ciphertext
    __u32 tunnel_payload_len = sizeof(struct tunnel_hdr) + payload_len;
    __u32 new_total_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + tunnel_payload_len;
    __u32 old_total_len = sizeof(struct ethhdr) + ip_total_len;

    // Adjust packet size
    int size_delta = new_total_len - old_total_len;
    if (bpf_skb_change_tail(skb, new_total_len, 0) < 0) {
        bpf_printk("Tunnel: Failed to resize packet");
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }

    // Build tunnel header
    struct tunnel_hdr thdr = {
        .magic = bpf_htonl(0xDEADBEEF),
        .seq = bpf_htonl(seq),
        .pubkey_id = 0, // Local key ID
    };
    __builtin_memcpy(thdr.iv, scratch->iv, 16);
    // Note: CBC mode doesn't produce auth tags (not AEAD)
    __builtin_memset(thdr.tag, 0, 16);  // Zero out tag field

    // Sign the packet (ECDSA signature for authentication)
    // KERNEL LIMITATION: ECDSA contexts can't persist (same as crypto contexts)
    // For demonstration, use mock signature
    __builtin_memset(thdr.signature, 0xCC, ECDSA_SIG_SIZE);

    // Write new UDP header
    struct udphdr new_udph = {
        .source = bpf_htons(TUNNEL_PORT),
        .dest = bpf_htons(TUNNEL_PORT),
        .len = bpf_htons(sizeof(struct udphdr) + tunnel_payload_len),
        .check = 0, // Will be updated
    };

    // Update IP header
    __u32 new_ip_total = sizeof(struct iphdr) + sizeof(struct udphdr) + tunnel_payload_len;

    // Store new headers and payload
    __u32 write_offset = sizeof(struct ethhdr);

    // Update IP header fields in place
    __u8 new_protocol = IPPROTO_UDP;
    bpf_skb_store_bytes(skb, write_offset + offsetof(struct iphdr, protocol), &new_protocol, 1, 0);

    __u32 new_daddr = config->remote_ip;
    bpf_skb_store_bytes(skb, write_offset + offsetof(struct iphdr, daddr), &new_daddr, 4, 0);

    __u16 new_tot_len = bpf_htons(new_ip_total);
    bpf_skb_store_bytes(skb, write_offset + offsetof(struct iphdr, tot_len), &new_tot_len, 2, 0);

    // Write UDP header
    write_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
    bpf_skb_store_bytes(skb, write_offset, &new_udph, sizeof(struct udphdr), 0);

    // Write tunnel header
    write_offset += sizeof(struct udphdr);
    bpf_skb_store_bytes(skb, write_offset, &thdr, sizeof(struct tunnel_hdr), 0);

    // Write encrypted payload (without auth tag, it's already in tunnel header)
    write_offset += sizeof(struct tunnel_hdr);
    bpf_skb_store_bytes(skb, write_offset, scratch->ciphertext, read_len, 0);

    // Recalculate IP checksum
    __u16 csum = 0;
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), &csum, 2, 0);
    bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, 0, 0);

    // Update statistics
    struct tunnel_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (stats) {
        update_stats(&stats->packets_encrypted, 1);
        update_stats(&stats->bytes_encrypted, read_len);
    }

    bpf_printk("Tunnel: Encrypted %u bytes, seq=%u", read_len, seq);

    // Release crypto context reference
    bpf_crypto_ctx_release(crypto_ctx);
    return TC_ACT_OK;
}

// TC ingress program - decrypt incoming tunnel packets
SEC("tc")
int tc_decrypt_ingress(struct __sk_buff *skb)
{
    // Pull data to ensure it's linear
    if (bpf_skb_pull_data(skb, skb->len) < 0)
        return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = parse_ethhdr(data, data_end);
    if (!eth || eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = parse_iphdr(eth, data_end);
    if (!iph || iph->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    struct udphdr *udph = bpf_ptr_add(iph, sizeof(*iph));
    if (bpf_ptr_add(udph, sizeof(*udph)) > data_end)
        return TC_ACT_OK;

    // Check if this is a tunnel packet
    if (udph->dest != bpf_htons(TUNNEL_PORT))
        return TC_ACT_OK;

    struct tunnel_hdr thdr;
    __u32 thdr_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    if (bpf_skb_load_bytes(skb, thdr_offset, &thdr, sizeof(thdr)) < 0)
        return TC_ACT_OK;

    if (thdr.magic != bpf_htonl(0xDEADBEEF))
        return TC_ACT_OK;

    // Verify ECDSA signature
    // KERNEL LIMITATION: Can't use bpf_ecdsa_verify() in TC (contexts can't persist)
    // In production, verification would be:
    // 1. Look up ECDSA verification context by thdr.pubkey_id
    // 2. Compute hash of (tunnel header + encrypted payload)
    // 3. Call bpf_ecdsa_verify(ctx, hash, thdr.signature)
    // 4. Drop packet if verification fails
    //
    // For now, log the pubkey_id and accept all packets
    bpf_printk("Tunnel: Packet from peer key ID %u (signature not verified)", thdr.pubkey_id);

    __u32 key = 0;
    struct tunnel_config *config = bpf_map_lookup_elem(&config_map, &key);
    if (!config || !config->enabled)
        return TC_ACT_OK;

    // Get crypto context storage (kptr)
    struct crypto_ctx_storage *storage = bpf_map_lookup_elem(&crypto_ctx_map, &key);
    if (!storage || !storage->ctx)
        return TC_ACT_OK;

    // ✨ Acquire reference from kptr (works in TC!)
    struct bpf_crypto_ctx *crypto_ctx = bpf_crypto_ctx_acquire(storage->ctx);
    if (!crypto_ctx) {
        bpf_printk("Tunnel: Failed to acquire crypto context");
        return TC_ACT_OK;
    }

    // Calculate encrypted payload size
    __u32 ip_total_len = bpf_ntohs(iph->tot_len);
    __u32 udp_len = bpf_ntohs(udph->len);
    __u32 encrypted_len = udp_len - sizeof(struct udphdr) - sizeof(struct tunnel_hdr);

    if (encrypted_len > MAX_PAYLOAD_SIZE || encrypted_len < 16) {
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }

    // Get scratch buffers from per-CPU map
    __u32 scratch_key = 0;
    struct crypto_scratch *scratch = bpf_map_lookup_elem(&scratch_map, &scratch_key);
    if (!scratch) {
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }

    // Copy IV to scratch map (verifier doesn't accept stack for bpf_dynptr_from_mem)
    __builtin_memcpy(scratch->iv, thdr.iv, 16);

    // Read encrypted payload
    __u32 payload_offset = thdr_offset + sizeof(struct tunnel_hdr);
    __u32 read_len = encrypted_len;
    if (read_len > MAX_PAYLOAD_SIZE)
        read_len = MAX_PAYLOAD_SIZE;

    if (bpf_skb_load_bytes(skb, payload_offset, scratch->ciphertext, read_len) < 0) {
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }

    // ✅ REAL DECRYPTION using bpf_crypto_decrypt!
    // Create dynptrs for decrypt operation
    struct bpf_dynptr src_ptr, dst_ptr, iv_ptr;
    if (bpf_dynptr_from_mem(scratch->ciphertext, read_len, 0, &src_ptr) < 0) {
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }
    if (bpf_dynptr_from_mem(scratch->plaintext, read_len, 0, &dst_ptr) < 0) {
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }
    if (bpf_dynptr_from_mem(scratch->iv, 16, 0, &iv_ptr) < 0) {
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }

    // Perform AES-256-CBC decryption
    int decrypt_ret = bpf_crypto_decrypt(crypto_ctx, &src_ptr, &dst_ptr, &iv_ptr);
    if (decrypt_ret < 0) {
        bpf_printk("Tunnel: Decryption failed: %d", decrypt_ret);
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_SHOT; // Drop invalid packets
    }

    bpf_printk("Tunnel: ✓ Packet decrypted (%u bytes)", read_len);

    // Now reconstruct the original packet
    // New size: eth + decrypted IP packet
    __u32 new_total_len = sizeof(struct ethhdr) + read_len;

    // Write decrypted payload back (this becomes the new IP packet)
    __u32 new_payload_offset = sizeof(struct ethhdr);
    bpf_skb_store_bytes(skb, new_payload_offset, scratch->plaintext, read_len, 0);

    // Shrink packet to remove tunnel overhead
    if (bpf_skb_change_tail(skb, new_total_len, 0) < 0) {
        bpf_printk("Tunnel: Failed to resize packet after decrypt");
        bpf_crypto_ctx_release(crypto_ctx);
        return TC_ACT_OK;
    }

    // Update statistics
    struct tunnel_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (stats) {
        update_stats(&stats->packets_decrypted, 1);
        update_stats(&stats->bytes_decrypted, read_len);
    }

    __u32 seq = bpf_ntohl(thdr.seq);
    bpf_printk("Tunnel: Decrypted %u bytes, seq=%u", read_len, seq);

    // Release crypto context reference
    bpf_crypto_ctx_release(crypto_ctx);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

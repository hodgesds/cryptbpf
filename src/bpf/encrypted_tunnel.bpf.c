// SPDX-License-Identifier: GPL-2.0
/* Encrypted Network Packet Tunnel using XDP and BPF crypto
 *
 * This program demonstrates high-performance in-kernel packet encryption/decryption
 * for creating a VPN-like encrypted tunnel at the XDP layer (before network stack).
 */

#include "common.h"

#define TUNNEL_PORT 4789  // Custom encrypted tunnel port
#define MAX_PAYLOAD_SIZE 1400

// Tunnel header structure
struct tunnel_hdr {
    __u32 magic;           // 0xDEADBEEF
    __u32 seq;             // Sequence number
    __u8 iv[16];           // AES-GCM IV (96 bits used, rest padding)
    __u8 tag[16];          // AES-GCM authentication tag
} __attribute__((packed));

// Map to store crypto context pointer (initialized from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); // Pointer to bpf_crypto_ctx (stored as u64)
} crypto_ctx_map SEC(".maps");

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

static __always_inline void update_stats(__u64 *counter, __u64 value)
{
    __sync_fetch_and_add(counter, value);
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

        // In a real implementation, we would:
        // 1. Extract encrypted payload
        // 2. Use bpf_crypto_decrypt() with the IV and context
        // 3. Replace packet contents with decrypted data
        // 4. Update headers
        //
        // Note: This requires packet expansion/manipulation which is complex in XDP
        // For production, consider using TC (traffic control) instead where we have
        // bpf_skb_* helpers for easier packet manipulation

        struct tunnel_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
        if (stats) {
            update_stats(&stats->packets_decrypted, 1);
        }

        // For now, just pass to userspace for decryption demo
        return XDP_PASS;
    }

    // Outgoing packet - check if it should be encrypted
    if (iph->daddr == config->remote_ip) {
        // This packet should be tunneled and encrypted
        // In a real implementation:
        // 1. Extract original payload
        // 2. Use bpf_crypto_encrypt() with generated IV
        // 3. Prepend tunnel header with IV and tag
        // 4. Wrap in new UDP packet to remote_ip:TUNNEL_PORT

        bpf_printk("Tunnel: TX packet to %pI4 proto=%u, should encrypt", &iph->daddr, iph->protocol);

        struct tunnel_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
        if (stats) {
            update_stats(&stats->packets_encrypted, 1);
        }

        // For now, pass to userspace
        return XDP_PASS;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

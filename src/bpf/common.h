// SPDX-License-Identifier: GPL-2.0
#ifndef __CRYPTBPF_COMMON_H
#define __CRYPTBPF_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Network protocol constants
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// XDP action codes
#define XDP_ABORTED 0
#define XDP_DROP    1
#define XDP_PASS    2
#define XDP_TX      3
#define XDP_REDIRECT 4

// TC action codes
#define TC_ACT_OK         0
#define TC_ACT_SHOT       2

// Crypto constants
#define SHA256_DIGEST_SIZE 32
#define AES_KEY_SIZE 32
#define ECDSA_SIG_SIZE 64
#define ECDSA_PUBKEY_SIZE 65

// Helpers to access data in packets
static __always_inline void *bpf_ptr_add(void *ptr, __u64 off)
{
    return (void *)((unsigned long)ptr + off);
}

// Ethernet header parsing
static __always_inline struct ethhdr *parse_ethhdr(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if (bpf_ptr_add(eth, sizeof(*eth)) > data_end)
        return NULL;
    return eth;
}

// IPv4 header parsing
static __always_inline struct iphdr *parse_iphdr(struct ethhdr *eth, void *data_end)
{
    struct iphdr *iph = bpf_ptr_add(eth, sizeof(*eth));
    if (bpf_ptr_add(iph, sizeof(*iph)) > data_end)
        return NULL;
    return iph;
}

#endif /* __CRYPTBPF_COMMON_H */

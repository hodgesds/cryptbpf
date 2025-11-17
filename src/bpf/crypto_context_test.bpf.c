// SPDX-License-Identifier: GPL-2.0
/* Test: Can we persist crypto contexts using kptr? */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ENOENT 2

char LICENSE[] SEC("license") = "GPL";

/* Map to store crypto context as kptr */
struct crypto_ctx_map_value {
	struct bpf_crypto_ctx __kptr *ctx;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct crypto_ctx_map_value);
} crypto_ctx_kptr_map SEC(".maps");

/* Extern kfunc declarations */
extern struct bpf_crypto_ctx *bpf_crypto_ctx_create(
	const struct bpf_crypto_params *params, u32 params__sz, int *err
) __weak __ksym;

extern void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx) __weak __ksym;
extern struct bpf_crypto_ctx *bpf_crypto_ctx_acquire(struct bpf_crypto_ctx *ctx) __weak __ksym;

extern int bpf_crypto_encrypt(
	struct bpf_crypto_ctx *ctx,
	const struct bpf_dynptr *src,
	const struct bpf_dynptr *dst,
	const struct bpf_dynptr *siv
) __weak __ksym;

/* bpf_kptr_xchg and bpf_dynptr_from_mem are already defined in bpf_helpers.h */

/* Syscall program to create and store crypto context */
SEC("syscall")
int create_persistent_crypto_ctx(void *ctx_in)
{
	struct bpf_crypto_params params = {
		.type = "skcipher",
		.algo = "ctr(aes)",
		.key_len = 32,
	};
	struct bpf_crypto_ctx *ctx;
	struct crypto_ctx_map_value *map_val;
	struct bpf_crypto_ctx *old_ctx;
	__u32 key = 0;
	int err = 0;

	/* Generate AES-256 key */
	__builtin_memset(params.key, 0xAB, 32);

	/* Create crypto context */
	ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!ctx) {
		bpf_printk("Failed to create crypto context: %d", err);
		return err;
	}

	bpf_printk("✓ Crypto context created successfully");

	/* Lookup map entry */
	map_val = bpf_map_lookup_elem(&crypto_ctx_kptr_map, &key);
	if (!map_val) {
		bpf_crypto_ctx_release(ctx);
		return -ENOENT;
	}

	/*
	 * CRITICAL: Use bpf_kptr_xchg to transfer ownership to map!
	 * This releases our reference and stores it in the map.
	 * We do NOT need to call bpf_crypto_ctx_release() anymore!
	 */
	old_ctx = bpf_kptr_xchg(&map_val->ctx, ctx);
	if (old_ctx) {
		/* Release old context if there was one */
		bpf_crypto_ctx_release(old_ctx);
	}

	bpf_printk("✓ Crypto context stored in map as kptr");
	return 0;
}

/* TC program to use the persisted crypto context */
SEC("tc")
int tc_use_crypto_ctx(struct __sk_buff *skb)
{
	struct crypto_ctx_map_value *map_val;
	struct bpf_crypto_ctx *ctx;
	__u32 key = 0;
	int ret;

	/* Lookup map entry with stored kptr */
	map_val = bpf_map_lookup_elem(&crypto_ctx_kptr_map, &key);
	if (!map_val)
		return TC_ACT_OK;

	/*
	 * CRITICAL: Acquire a reference to the kptr!
	 * This increments the refcount so we can use it safely.
	 */
	ctx = bpf_crypto_ctx_acquire(map_val->ctx);
	if (!ctx) {
		bpf_printk("⚠ Failed to acquire crypto context from kptr");
		return TC_ACT_OK;
	}

	bpf_printk("✓ TC: Successfully acquired crypto context from kptr!");
	bpf_printk("✓ TC: Ready to perform crypto operations!");

	/*
	 * TODO: Here we could actually call bpf_crypto_encrypt/decrypt!
	 * For now, just demonstrate that we can acquire the context.
	 */

	/* Must release the acquired reference */
	bpf_crypto_ctx_release(ctx);
	return TC_ACT_OK;
}

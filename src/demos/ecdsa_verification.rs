// ECDSA Verification Demo: BPF vs Rust
// Demonstrates using bpf_prog_test_run to execute BPF ECDSA signature verification
// and comparing it with the same verification in Rust using p256 crate
//
// Usage: cryptbpf ecdsa-verification

use anyhow::Result;
use libbpf_rs::MapCore;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use p256::ecdsa::{Signature, SigningKey, signature::Signer, signature::Verifier};
use sha2::{Digest, Sha256};
use rand_core::OsRng;

// Include the generated skeleton
mod ecdsa_test_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf/ecdsa_test.skel.rs"));
}
use ecdsa_test_skel::*;

const SHA256_DIGEST_SIZE: usize = 32;
const ECDSA_SIG_SIZE: usize = 64;
const ECDSA_PUBKEY_SIZE: usize = 65;

#[repr(C)]
struct EcdsaTestData {
    message_hash: [u8; SHA256_DIGEST_SIZE],
    signature: [u8; ECDSA_SIG_SIZE],
    public_key: [u8; ECDSA_PUBKEY_SIZE],
}

fn test_ecdsa_verification(
    skel: &EcdsaTestSkel,
    message: &[u8],
    signing_key: &SigningKey,
) -> Result<(bool, bool)> {
    // Hash the message
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    // Sign with Rust p256
    let signature: Signature = signing_key.sign(message);
    let signature_bytes = signature.to_bytes();

    // Get public key in uncompressed format (0x04 || x || y)
    let verifying_key = *signing_key.verifying_key();
    let public_key_point = verifying_key.to_encoded_point(false); // false = uncompressed
    let public_key_bytes = public_key_point.as_bytes();

    println!("  Message: {:?}", String::from_utf8_lossy(message));
    println!("  Message hash (SHA-256): {}", hex::encode(&message_hash[..8]));
    println!("  Signature (first 8 bytes): {}", hex::encode(&signature_bytes[..8]));
    println!("  Public key (first 8 bytes): {}", hex::encode(&public_key_bytes[..8]));

    // Verify in Rust
    let rust_result = verifying_key.verify(message, &signature).is_ok();
    println!("  Rust verification: {}", if rust_result { "✅ VALID" } else { "❌ INVALID" });

    // Prepare test data for BPF
    let mut test_data = EcdsaTestData {
        message_hash: [0u8; SHA256_DIGEST_SIZE],
        signature: [0u8; ECDSA_SIG_SIZE],
        public_key: [0u8; ECDSA_PUBKEY_SIZE],
    };

    test_data.message_hash.copy_from_slice(&message_hash);
    test_data.signature.copy_from_slice(&signature_bytes);
    test_data.public_key.copy_from_slice(public_key_bytes);

    // Write to BPF map
    let key = 0u32.to_ne_bytes();
    let test_data_bytes = unsafe {
        std::slice::from_raw_parts(
            &test_data as *const EcdsaTestData as *const u8,
            std::mem::size_of::<EcdsaTestData>(),
        )
    };
    skel.maps.ecdsa_test_map.update(&key, test_data_bytes, libbpf_rs::MapFlags::ANY)?;

    // Run BPF verification
    let input = libbpf_rs::ProgramInput::default();
    let _output = skel.progs.ecdsa_verify_from_map.test_run(input)?;

    // Get result from map
    let result_bytes = skel.maps.ecdsa_result_map
        .lookup(&key, libbpf_rs::MapFlags::ANY)?
        .expect("Result not found in map");

    let bpf_result_code = i32::from_ne_bytes(result_bytes[0..4].try_into().unwrap());
    let bpf_result = bpf_result_code == 0;

    print!("  BPF verification: ");
    if bpf_result_code == 0 {
        println!("✅ VALID (code: 0)");
    } else if bpf_result_code == -129 { // -EKEYREJECTED
        println!("❌ INVALID (code: -129 EKEYREJECTED)");
    } else {
        println!("❌ ERROR (code: {})", bpf_result_code);
    }

    Ok((rust_result, bpf_result))
}

pub fn run() -> Result<()> {
    println!("\n=== ECDSA Verification Demo: BPF vs Rust ===\n");
    println!("This demo shows ECDSA signature verification using secp256r1 (NIST P-256)");
    println!("We sign messages in Rust and verify them both in Rust and BPF.");
    println!("BPF uses the new context-based API for efficient verification.\n");

    // Show kernel requirements
    let kernel_version = std::fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "unknown".to_string());
    println!("Current kernel: {}", kernel_version.lines().next().unwrap_or("unknown"));
    println!("\n⚠️  Requirements:");
    println!("  • Linux kernel with CONFIG_CRYPTO_ECDSA");
    println!("  • bpf_ecdsa_ctx_create() and bpf_ecdsa_verify() kfunc support");
    println!("  If this fails, your kernel doesn't support BPF ECDSA kfuncs.\n");

    // Load BPF program
    println!("--- Loading BPF Program ---");
    let skel_builder = EcdsaTestSkelBuilder::default();
    let mut open_object = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let skel = open_skel.load()?;
    println!("✓ BPF object loaded using skeleton\n");

    // Generate a keypair for testing
    println!("--- Generating Test Keypair ---");
    let signing_key = SigningKey::random(&mut OsRng);
    println!("✓ Generated secp256r1 keypair\n");

    // Test cases
    let test_cases: Vec<(&str, &[u8], bool)> = vec![
        ("Valid signature #1", b"Hello, BPF ECDSA world!" as &[u8], true),
        ("Valid signature #2", b"Testing ECDSA verification in BPF" as &[u8], true),
        ("Valid signature #3", b"The quick brown fox jumps over the lazy dog" as &[u8], true),
    ];

    let mut all_passed = true;

    for (name, message, _expected_valid) in test_cases {
        println!("--- Test: {} ---", name);

        let (rust_result, bpf_result) = test_ecdsa_verification(&skel, message, &signing_key)?;

        // Compare results
        if rust_result == bpf_result {
            println!("  ✅ MATCH (both agree: {})", if rust_result { "VALID" } else { "INVALID" });
        } else {
            println!("  ❌ MISMATCH (Rust: {}, BPF: {})",
                     if rust_result { "VALID" } else { "INVALID" },
                     if bpf_result { "VALID" } else { "INVALID" });
            all_passed = false;
        }
        println!();
    }

    // Test with invalid signature
    println!("--- Test: Invalid signature (should fail) ---");
    {
        let signing_key2 = SigningKey::random(&mut OsRng); // Different key!
        let message = b"Signed with different key";

        // Hash the message
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize();

        // Sign with key2
        let signature: Signature = signing_key2.sign(message);
        let signature_bytes = signature.to_bytes();

        // But verify with key1's public key (should fail)
        let verifying_key = signing_key.verifying_key(); // Wrong key!
        let public_key_point = verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key_point.as_bytes();

        println!("  Message: {:?}", String::from_utf8_lossy(message));
        println!("  Signed with key2, verifying with key1's public key");

        // Verify in Rust (should fail)
        let rust_result = verifying_key.verify(message, &signature).is_ok();
        println!("  Rust verification: {}", if rust_result { "✅ VALID" } else { "❌ INVALID" });

        // Prepare for BPF
        let mut test_data = EcdsaTestData {
            message_hash: [0u8; SHA256_DIGEST_SIZE],
            signature: [0u8; ECDSA_SIG_SIZE],
            public_key: [0u8; ECDSA_PUBKEY_SIZE],
        };

        test_data.message_hash.copy_from_slice(&message_hash);
        test_data.signature.copy_from_slice(&signature_bytes);
        test_data.public_key.copy_from_slice(public_key_bytes);

        let key = 0u32.to_ne_bytes();
        let test_data_bytes = unsafe {
            std::slice::from_raw_parts(
                &test_data as *const EcdsaTestData as *const u8,
                std::mem::size_of::<EcdsaTestData>(),
            )
        };
        skel.maps.ecdsa_test_map.update(&key, test_data_bytes, libbpf_rs::MapFlags::ANY)?;

        // Run BPF verification
        let input = libbpf_rs::ProgramInput::default();
        let _output = skel.progs.ecdsa_verify_from_map.test_run(input)?;

        let result_bytes = skel.maps.ecdsa_result_map
            .lookup(&key, libbpf_rs::MapFlags::ANY)?
            .expect("Result not found");
        let bpf_result_code = i32::from_ne_bytes(result_bytes[0..4].try_into().unwrap());
        let bpf_result = bpf_result_code == 0;

        print!("  BPF verification: ");
        if bpf_result_code == 0 {
            println!("✅ VALID (code: 0)");
        } else if bpf_result_code == -129 {
            println!("❌ INVALID (code: -129 EKEYREJECTED)");
        } else {
            println!("❌ ERROR (code: {})", bpf_result_code);
        }

        if rust_result == bpf_result && !rust_result {
            println!("  ✅ MATCH (both correctly rejected invalid signature)");
        } else {
            println!("  ❌ MISMATCH or unexpected result");
            all_passed = false;
        }
        println!();
    }

    // Check statistics
    println!("--- BPF Statistics ---");
    let key = 0u32.to_ne_bytes();
    let stats_bytes = skel.maps.ecdsa_stats_map
        .lookup(&key, libbpf_rs::MapFlags::ANY)?
        .expect("Stats not found");

    if stats_bytes.len() >= 24 {
        let total = u64::from_ne_bytes(stats_bytes[0..8].try_into().unwrap());
        let successful = u64::from_ne_bytes(stats_bytes[8..16].try_into().unwrap());
        let failed = u64::from_ne_bytes(stats_bytes[16..24].try_into().unwrap());

        println!("BPF Statistics:");
        println!("  Total verifications: {}", total);
        println!("  Successful: {}", successful);
        println!("  Failed: {}", failed);
    }

    if !all_passed {
        println!("\n❌ Some tests failed!");
        std::process::exit(1);
    }

    println!("\n=== Demo Complete ===");
    println!("✅ All tests passed! BPF ECDSA verification matches Rust p256 crate");
    println!("✅ Successfully verified ECDSA signatures using secp256r1 (NIST P-256)");
    println!();
    println!("💡 Key Points:");
    println!("  • BPF uses new context-based API: bpf_ecdsa_ctx_create() + bpf_ecdsa_verify()");
    println!("  • Context is created once and reused for efficient verification");
    println!("  • ECDSA verification in BPF matches Rust implementation");
    println!("  • Supports secp256r1 (NIST P-256) elliptic curve");
    println!("  • Can detect invalid signatures correctly");
    println!("  • Public key must be in uncompressed format (0x04 || x || y)");
    println!("  • Signature format is r || s (64 bytes total)");
    println!();
    println!("💡 To see BPF trace output, run in another terminal:");
    println!("   sudo cat /sys/kernel/debug/tracing/trace_pipe\n");

    Ok(())
}

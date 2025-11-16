// Hash Comparison Demo: BPF vs Rust
// Demonstrates using bpf_prog_test_run to execute BPF hash computation
// and comparing it with the same hash computed in Rust
//
// Usage: cryptbpf hash-comparison

use anyhow::Result;
use libbpf_rs::MapCore;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use sha2::{Digest, Sha256};
use std::thread;
use std::time::Duration;

// Include the generated skeleton
mod hash_test_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf/hash_test.skel.rs"));
}
use hash_test_skel::*;

fn test_hash(skel: &HashTestSkel, test_data: &[u8]) -> Result<Vec<u8>> {
    // Prepare input data structure for the map
    // Must match struct input_data size: u32 (4) + data[4096] = 4100 bytes
    const MAX_INPUT_SIZE: usize = 4096;
    let mut input_buf = vec![0u8; 4 + MAX_INPUT_SIZE];
    input_buf[0..4].copy_from_slice(&(test_data.len() as u32).to_ne_bytes());
    input_buf[4..4 + test_data.len()].copy_from_slice(test_data);

    // Write test data to the input_data_map
    let key = 0u32.to_ne_bytes();
    skel.maps.input_data_map.update(&key, &input_buf, libbpf_rs::MapFlags::ANY)?;

    // Run the map-based hash program (syscall type, not XDP)
    // IMPORTANT: syscall programs must NOT have data_in/data_out set
    // (even empty) or test_run returns -EINVAL
    let input = libbpf_rs::ProgramInput::default();

    let result = skel.progs.hash_from_map.test_run(input);

    match result {
        Ok(output) => {
            eprintln!("[DEBUG] test_run succeeded, return_value={}", output.return_value);
            if output.return_value != 0 {
                return Err(anyhow::anyhow!(
                    "BPF program returned error code: {}\n\
                    This means the program ran but the hash function failed.\n\
                    \nPossible reasons:\n\
                    - bpf_sha256_hash() kfunc not available at runtime\n\
                    - Crypto subsystem not initialized\n\
                    - Invalid data format\n\
                    \nCheck dmesg for kernel messages:\n\
                    sudo dmesg | grep -i bpf | tail -20",
                    output.return_value
                ));
            }
        },
        Err(e) => {
            return Err(anyhow::anyhow!(
                "test_run() syscall failed: {}\n\
                \nThe BPF program loaded successfully but test_run() failed.\n\
                \n🔍 LIKELY CAUSE: Crypto kfuncs may not work with bpf_prog_test_run()\n\
                \nCrypto kfuncs might require the program to be attached to a real hook point.\n\
                This is a kernel limitation, not a bug in the code.\n\
                \nPossible workarounds:\n\
                1. Attach to loopback: cryptbpf hash-comparison-attached --device lo\n\
                2. Use userspace crypto for testing\n\
                3. Check if kernel allows crypto kfuncs in test_run:\n\
                   sudo dmesg | tail -20\n\
                \nThe map-based approach is still correct - this demonstrates\n\
                the limitation of test_run with certain kfuncs.",
                e
            ));
        }
    }

    // Retrieve hash from map
    let bpf_hash_bytes = skel.maps.hash_output_map
        .lookup(&key, libbpf_rs::MapFlags::ANY)?
        .expect("Hash not found in map");

    Ok(bpf_hash_bytes)
}

pub fn run() -> Result<()> {
    println!("\n=== Hash Comparison Demo: BPF vs Rust ===\n");
    println!("This demo shows hashing data from a BPF map (much simpler than packet data!)");
    println!("We can hash much larger data when using maps vs packet bounds.\n");

    // Show kernel requirements
    let kernel_version = std::fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "unknown".to_string());
    println!("Current kernel: {}", kernel_version.lines().next().unwrap_or("unknown"));
    println!("\n⚠️  Requirements:");
    println!("  • Linux 6.0+ with CONFIG_BPF_KFUNC_CRYPTO");
    println!("  • bpf_sha256_hash() kfunc support");
    println!("  If this fails, your kernel doesn't support BPF crypto kfuncs.\n");

    // Load BPF program
    println!("--- Loading BPF Program ---");
    let skel_builder = HashTestSkelBuilder::default();
    let mut open_object = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    println!("[DEBUG] Opening BPF object...");
    println!("[DEBUG] About to load program (verifier will check if kfuncs are allowed)...");

    let skel = open_skel.load()?;
    println!("✓ BPF object loaded using skeleton");
    println!("[DEBUG] Program loaded successfully - verifier approved kfunc usage");
    println!("[DEBUG] Now testing if kfunc works in test_run() context...\n");

    // Test multiple sizes to show the advantage of using maps
    let test_cases = vec![
        ("Small data", b"Hello, BPF world!".to_vec()),
        ("Medium data (256 bytes)", vec![0x42u8; 256]),
        ("Large data (1KB)", vec![0x42u8; 1024]),
        ("Very large data (4KB)", vec![0x42u8; 4096]),
    ];

    let mut all_passed = true;

    for (name, test_data) in test_cases {
        println!("--- Test: {} ({} bytes) ---", name, test_data.len());

        // Compute hash in Rust
        let mut hasher = Sha256::new();
        hasher.update(&test_data);
        let rust_hash = hasher.finalize();

        println!("Rust SHA-256: {}", hex::encode(&rust_hash[..8]));

        // Compute hash in BPF from map
        let bpf_hash_bytes = test_hash(&skel, &test_data)?;

        println!("BPF  SHA-256: {}", hex::encode(&bpf_hash_bytes[..8]));

        // Compare
        if rust_hash.as_slice() == bpf_hash_bytes.as_slice() {
            println!("✅ MATCH\n");
        } else {
            println!("❌ MISMATCH");
            println!("   Rust: {}", hex::encode(&rust_hash));
            println!("   BPF:  {}", hex::encode(&bpf_hash_bytes));
            all_passed = false;
        }

        thread::sleep(Duration::from_millis(100));
    }

    if !all_passed {
        std::process::exit(1);
    }

    // Check statistics
    println!("--- BPF Statistics ---");

    let key = 0u32.to_ne_bytes();
    let stats_bytes = skel.maps.hash_stats_map
        .lookup(&key, libbpf_rs::MapFlags::ANY)?
        .expect("Stats not found");

    // Parse stats (total_hashes: u64, last_input_len: u64, last_hash_first_4_bytes: u32)
    if stats_bytes.len() >= 20 {
        let total_hashes = u64::from_ne_bytes(stats_bytes[0..8].try_into().unwrap());
        let last_input_len = u64::from_ne_bytes(stats_bytes[8..16].try_into().unwrap());
        let hash_preview = u32::from_ne_bytes(stats_bytes[16..20].try_into().unwrap());

        println!("BPF Statistics:");
        println!("  Total hashes computed: {}", total_hashes);
        println!("  Last input length: {} bytes", last_input_len);
        println!("  Last hash preview: 0x{:08x}", hash_preview);
    }

    println!("\n=== Demo Complete ===");
    println!("✅ All tests passed! BPF bpf_sha256_hash() produces identical output to Rust sha2 crate");
    println!("✅ Successfully hashed data from BPF maps (up to 4KB)");
    println!();
    println!("💡 Key Advantages of Using BPF Maps:");
    println!("  • No packet bounds checking complexity");
    println!("  • Can hash much larger data (4KB+ vs 64 bytes with packet data)");
    println!("  • Simpler code that the verifier accepts easily");
    println!("  • Direct memory access without copying loops");
    println!();
    println!("💡 To see BPF trace output, run in another terminal:");
    println!("   sudo cat /sys/kernel/debug/tracing/trace_pipe\n");

    Ok(())
}

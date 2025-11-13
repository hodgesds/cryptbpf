// Proof-of-Work Rate Limiting Demo Module

use anyhow::Result;
use sha2::{Sha256, Digest};

fn solve_challenge(challenge: &[u8; 32], difficulty: u32) -> (u64, [u8; 32]) {
    println!("Solving PoW challenge (difficulty: {} bits)...", difficulty);

    let start = std::time::Instant::now();
    let mut nonce: u64 = 0;

    loop {
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        hasher.update(&nonce.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        if check_difficulty(&hash, difficulty) {
            let elapsed = start.elapsed();
            println!("✓ Solution found in {:?}", elapsed);
            println!("  Nonce: {}", nonce);
            return (nonce, hash);
        }

        nonce += 1;
    }
}

fn check_difficulty(hash: &[u8; 32], difficulty: u32) -> bool {
    let zero_bytes = (difficulty / 8) as usize;
    for i in 0..zero_bytes.min(32) {
        if hash[i] != 0 {
            return false;
        }
    }
    true
}

pub fn run(device: &str, pow_difficulty: u32) -> Result<()> {
    println!("=== Proof-of-Work Rate Limiting Demo ===\n");
    println!("Device: {}\n", device);
    println!("PoW Difficulty: {} bits\n", pow_difficulty);

    let challenge: [u8; 32] = [0x1a; 32];
    let (_nonce, _solution) = solve_challenge(&challenge, 12);

    println!("\nThis protects against DDoS by requiring computational work");
    println!("before granting access to resources.\n");

    Ok(())
}

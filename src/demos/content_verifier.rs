// Content-Addressed Storage Verifier Demo Module

use anyhow::Result;
use sha2::{Sha256, Digest};

pub fn run(device: &str, _enforce_allowlist: bool) -> Result<()> {
    println!("=== Content-Addressed Storage Verifier Demo ===\n");
    println!("Device: {}\n", device);

    let content = b"Hello, IPFS-like world!";
    let mut hasher = Sha256::new();
    hasher.update(content);
    let cid = hasher.finalize();

    println!("Content: {:?}", String::from_utf8_lossy(content));
    println!("CID: {}\n", hex::encode(&cid));

    println!("This verifies content integrity at line-rate:");
    println!("- Compute SHA-256 of payload");
    println!("- Compare with claimed Content ID");
    println!("- Drop if mismatch (tampering detected)");

    Ok(())
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

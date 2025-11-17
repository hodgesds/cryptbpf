use anyhow::{Result, Context};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, TcHook, ProgramInput};
use std::net::Ipv4Addr;
use std::os::fd::AsFd;
use std::time::Duration;
use std::thread;

mod encrypted_tunnel {
    include!(concat!(env!("OUT_DIR"), "/bpf/encrypted_tunnel.skel.rs"));
}

use encrypted_tunnel::*;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct TunnelConfig {
    local_ip: u32,
    remote_ip: u32,
    local_port: u16,
    remote_port: u16,
    enabled: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
struct TunnelStats {
    packets_encrypted: u64,
    packets_decrypted: u64,
    packets_dropped: u64,
    bytes_encrypted: u64,
    bytes_decrypted: u64,
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

pub fn run(device: &str) -> Result<()> {
    println!("=== Encrypted Tunnel Full Implementation ===\n");
    println!("Device: {}\n", device);

    let if_index = nix::net::if_::if_nametoindex(device)
        .context("Failed to get interface index")?;

    println!("Loading BPF programs...");

    let skel_builder = EncryptedTunnelSkelBuilder::default();
    let mut open_object = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)
        .context("Failed to open BPF skeleton")?;

    let skel = open_skel.load().context("Failed to load BPF skeleton")?;

    println!("✓ BPF programs loaded");

    println!("\nConfiguring tunnel...");
    let local_ip = Ipv4Addr::new(10, 0, 0, 1);
    let remote_ip = Ipv4Addr::new(10, 0, 0, 2);

    let config = TunnelConfig {
        local_ip: ipv4_to_u32(local_ip),
        remote_ip: ipv4_to_u32(remote_ip),
        local_port: 4789,
        remote_port: 4789,
        enabled: 1,
    };

    let key: u32 = 0;
    let config_bytes = unsafe {
        std::slice::from_raw_parts(
            &config as *const TunnelConfig as *const u8,
            std::mem::size_of::<TunnelConfig>(),
        )
    };

    skel.maps.config_map
        .update(&key.to_ne_bytes(), config_bytes, MapFlags::ANY)
        .context("Failed to update config map")?;

    println!("  Local IP: {}", local_ip);
    println!("  Remote IP: {}", remote_ip);
    println!("  Tunnel Port: 4789");
    println!("✓ Tunnel configured");

    println!("\nInitializing AES-256-CBC encryption...");
    println!("  Note: BPF crypto only supports CBC mode (not GCM AEAD)");

    // Initialize crypto context (AES-256-CBC)
    match skel.progs.create_crypto_ctx.test_run(ProgramInput::default()) {
        Ok(output) => {
            if output.return_value == 0 {
                println!("✓ AES-256-CBC crypto context created");
                println!("✓ Crypto context stored as kptr (REAL ENCRYPTION ENABLED!)");
            } else {
                println!("⚠ Crypto context creation returned: {}", output.return_value);
            }
        }
        Err(e) => {
            println!("⚠ Failed to create crypto context: {}", e);
        }
    }

    println!("\nInitializing ECDSA authentication (P-256)...");

    // Initialize ECDSA signing context (private key)
    let input = ProgramInput::default();
    match skel.progs.create_ecdsa_sign_ctx.test_run(input) {
        Ok(output) => {
            if output.return_value == 0 {
                println!("✓ ECDSA signing context created");
                println!("✓ ECDSA signing context stored as kptr");
            } else {
                println!("⚠ ECDSA signing context returned: {}", output.return_value);
            }
        }
        Err(e) => {
            println!("⚠ Failed to create ECDSA signing context: {}", e);
        }
    }

    // Initialize ECDSA verification context (public key)
    match skel.progs.create_ecdsa_verify_ctx.test_run(ProgramInput::default()) {
        Ok(output) => {
            if output.return_value == 0 {
                println!("✓ ECDSA verification context created");
                println!("✓ ECDSA verification context stored as kptr");
            } else {
                println!("⚠ ECDSA verification context returned: {}", output.return_value);
            }
        }
        Err(e) => {
            println!("⚠ Failed to create ECDSA verification context: {}", e);
        }
    }

    println!("  Using secp256r1 (NIST P-256) curve");
    println!("  Signatures: 64 bytes (r || s)");

    println!("\nAttaching programs...");
    let _xdp_link = skel.progs.xdp_encrypted_tunnel
        .attach_xdp(if_index as i32)
        .context("Failed to attach XDP program")?;

    println!("✓ XDP program attached");

    let mut tc_egress = TcHook::new(skel.progs.tc_encrypt_egress.as_fd());
    tc_egress.ifindex(if_index as i32)
        .replace(true)
        .handle(1)
        .priority(1);

    match tc_egress.create() {
        Ok(_hook) => {
            tc_egress.attach().context("Failed to attach TC egress")?;
            println!("✓ TC egress program attached (encryption)");
        }
        Err(e) => {
            println!("⚠ Failed to create TC egress hook: {}", e);
        }
    }

    let mut tc_ingress = TcHook::new(skel.progs.tc_decrypt_ingress.as_fd());
    tc_ingress.ifindex(if_index as i32)
        .replace(true)
        .handle(1)
        .priority(1);

    match tc_ingress.create() {
        Ok(_hook) => {
            tc_ingress.attach().context("Failed to attach TC ingress")?;
            println!("✓ TC ingress program attached (decryption)");
        }
        Err(e) => {
            println!("⚠ Failed to create TC ingress hook: {}", e);
        }
    }

    println!("\n=== Encrypted Tunnel Active ===");
    println!("Monitoring traffic...\n");
    println!("The tunnel will:");
    println!("  • Tunnel outgoing packets to {}", remote_ip);
    println!("  • Receive tunnel packets on port 4789");
    println!("  • Encrypt with AES-256-CBC (real kernel crypto!)");
    println!("  • Add tunnel header (magic, seq, IV, ECDSA signature)");
    println!("  • Note: CBC mode provides confidentiality only (no built-in integrity)\n");

    println!("Check kernel logs: sudo dmesg -w | grep Tunnel\n");
    println!("Statistics:");
    println!("{:>20} {:>15} {:>15} {:>15}", "Time", "Encrypted", "Decrypted", "Dropped");
    println!("{:-<65}", "");

    let stats_key: u32 = 0;
    let mut last_stats = TunnelStats::default();

    for i in 0..30 {
        thread::sleep(Duration::from_secs(2));

        if let Ok(Some(stats_bytes)) = skel.maps.stats_map.lookup(&stats_key.to_ne_bytes(), MapFlags::ANY) {
            if stats_bytes.len() >= std::mem::size_of::<TunnelStats>() {
                let stats: TunnelStats = unsafe {
                    std::ptr::read(stats_bytes.as_ptr() as *const TunnelStats)
                };

                let encrypted_delta = stats.packets_encrypted - last_stats.packets_encrypted;
                let decrypted_delta = stats.packets_decrypted - last_stats.packets_decrypted;
                let dropped_delta = stats.packets_dropped - last_stats.packets_dropped;

                if encrypted_delta > 0 || decrypted_delta > 0 || dropped_delta > 0 {
                    println!("{:>20} {:>15} {:>15} {:>15}",
                             format!("{}s", i * 2),
                             encrypted_delta,
                             decrypted_delta,
                             dropped_delta);
                }

                last_stats = stats;
            }
        }
    }

    println!("\n=== Final Statistics ===");
    if let Ok(Some(stats_bytes)) = skel.maps.stats_map.lookup(&stats_key.to_ne_bytes(), MapFlags::ANY) {
        if stats_bytes.len() >= std::mem::size_of::<TunnelStats>() {
            let stats: TunnelStats = unsafe {
                std::ptr::read(stats_bytes.as_ptr() as *const TunnelStats)
            };

            println!("Total packets encrypted: {}", stats.packets_encrypted);
            println!("Total packets decrypted: {}", stats.packets_decrypted);
            println!("Total packets dropped:   {}", stats.packets_dropped);
            println!("Total bytes encrypted:   {}", stats.bytes_encrypted);
            println!("Total bytes decrypted:   {}", stats.bytes_decrypted);
        }
    }

    println!("\nCleaning up...");
    Ok(())
}

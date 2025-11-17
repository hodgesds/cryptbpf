use anyhow::{Result, Context};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{TcHook, ProgramInput};
use std::os::fd::AsFd;

mod crypto_context_test {
    include!(concat!(env!("OUT_DIR"), "/bpf/crypto_context_test.skel.rs"));
}

use crypto_context_test::*;

pub fn run(device: &str) -> Result<()> {
    println!("=== Crypto Context Persistence Test (kptr) ===\n");
    println!("Testing if we can persist crypto contexts in TC programs using kptr...\n");

    let if_index = nix::net::if_::if_nametoindex(device)
        .context("Failed to get interface index")?;

    println!("Step 1: Loading BPF programs...");
    let skel_builder = CryptoContextTestSkelBuilder::default();
    let mut open_object = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)
        .context("Failed to open BPF skeleton")?;
    let skel = open_skel.load().context("Failed to load BPF skeleton")?;
    println!("✓ BPF programs loaded\n");

    println!("Step 2: Creating crypto context in syscall program...");
    println!("  Algorithm: AES-256-CTR");
    println!("  Key size: 256 bits");

    match skel.progs.create_persistent_crypto_ctx.test_run(ProgramInput::default()) {
        Ok(output) => {
            if output.return_value == 0 {
                println!("✓ Crypto context created and stored as kptr!");
            } else {
                println!("⚠ Syscall program returned: {}", output.return_value);
            }
        }
        Err(e) => {
            println!("✗ Failed to create crypto context: {}", e);
            return Err(e.into());
        }
    }

    println!("\nStep 3: Attaching TC program to network interface...");
    let mut tc_hook = TcHook::new(skel.progs.tc_use_crypto_ctx.as_fd());
    tc_hook.ifindex(if_index as i32)
        .replace(true)
        .handle(1)
        .priority(1);

    match tc_hook.create() {
        Ok(_) => {
            tc_hook.attach().context("Failed to attach TC program")?;
            println!("✓ TC program attached to {}\n", device);
        }
        Err(e) => {
            println!("⚠ Failed to create TC hook: {}", e);
        }
    }

    println!("Step 4: Testing crypto context acquisition in TC...");
    println!("  Waiting for packets to trigger TC program...");
    println!("  (Generate some traffic to test)\n");

    println!("Check kernel logs: sudo dmesg | grep -E '✓|⚠'");
    println!("\nExpected output:");
    println!("  ✓ TC: Successfully acquired crypto context from kptr!");
    println!("  ✓ TC: Ready to perform crypto operations!\n");

    println!("=== Result ===");
    println!("If you see the above messages in dmesg, then:");
    println!("✅ YES! Crypto contexts CAN persist in TC programs using kptr!");
    println!("✅ The limitation CAN be fixed!");
    println!("✅ Real encryption/decryption is possible in TC programs!");

    std::thread::sleep(std::time::Duration::from_secs(5));

    Ok(())
}

// Simple prog_test_run demonstration
// Shows how to execute a BPF program without attaching it to a network interface
//
// Usage: cryptbpf prog-test-run-demo

use anyhow::Result;
use libbpf_rs::MapCore;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};

// Include the generated skeleton
mod hash_test_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf/hash_test.skel.rs"));
}
use hash_test_skel::*;

fn build_test_packet(src_ip: [u8; 4], dst_ip: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();

    // Ethernet header (14 bytes)
    packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst MAC
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // src MAC
    packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // IPv4 header (20 bytes)
    let ip_total_len = 20 + 8 + payload.len();
    packet.push(0x45); // Version 4, IHL 5
    packet.push(0x00); // DSCP/ECN
    packet.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // ID
    packet.extend_from_slice(&[0x00, 0x00]); // Flags
    packet.push(64); // TTL
    packet.push(17); // Protocol: UDP
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    packet.extend_from_slice(&src_ip);
    packet.extend_from_slice(&dst_ip);

    // UDP header (8 bytes)
    let udp_len = 8 + payload.len();
    packet.extend_from_slice(&5000u16.to_be_bytes()); // src port
    packet.extend_from_slice(&6000u16.to_be_bytes()); // dst port
    packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // checksum

    // Payload
    packet.extend_from_slice(payload);

    packet
}

pub fn run() -> Result<()> {
    println!("\n=== BPF prog_test_run Demonstration ===\n");

    println!("This example shows how to:");
    println!("  1. Load a BPF program using skeleton");
    println!("  2. Create test packet data");
    println!("  3. Execute the program with bpf_prog_test_run");
    println!("  4. Read the results\n");

    println!("Using: hash_test (hash_from_map - syscall program type)\n");

    // Step 1: Load BPF program using skeleton
    println!("--- Step 1: Loading BPF program ---");

    let skel_builder = HashTestSkelBuilder::default();
    let mut open_object = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let skel = open_skel.load()?;

    println!("✓ BPF object loaded using skeleton");
    println!("✓ Found program: hash_from_map (SEC(\"syscall\"))\n");

    // Step 2: Create test data and write to map
    println!("--- Step 2: Preparing test data in BPF map ---");

    let test_payload = b"Hello from prog_test_run!";
    let test_packet = build_test_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        test_payload,
    );

    println!("Test packet created:");
    println!("  Total size: {} bytes", test_packet.len());
    println!("  Structure: Ethernet(14) + IP(20) + UDP(8) + Payload({})", test_payload.len());
    println!("  Payload: {:?}", String::from_utf8_lossy(test_payload));

    // Write to input_data_map
    // Must match struct input_data size: u32 (4) + data[4096] = 4100 bytes
    const MAX_INPUT_SIZE: usize = 4096;
    let mut input_buf = vec![0u8; 4 + MAX_INPUT_SIZE];
    input_buf[0..4].copy_from_slice(&(test_packet.len() as u32).to_ne_bytes());
    input_buf[4..4 + test_packet.len()].copy_from_slice(&test_packet);

    let key = 0u32.to_ne_bytes();
    skel.maps.input_data_map.update(&key, &input_buf, libbpf_rs::MapFlags::ANY)?;
    println!("✓ Test data written to input_data_map\n");

    // Step 3: Execute with prog_test_run
    println!("--- Step 3: Executing with bpf_prog_test_run ---");

    // IMPORTANT: syscall programs must NOT have data_in/data_out set
    // (even empty) or test_run returns -EINVAL
    let input = libbpf_rs::ProgramInput::default();

    println!("Calling bpf_prog_test_run...");

    let output = skel.progs.hash_from_map.test_run(input)?;

    println!("✓ Execution complete!\n");

    // Step 4: Examine results
    println!("--- Step 4: Results ---");

    println!("Return value: {}", output.return_value);
    match output.return_value {
        0 => println!("  XDP_ABORTED (0) - Error/test mode"),
        1 => println!("  XDP_DROP (1) - Packet dropped"),
        2 => println!("  XDP_PASS (2) - Packet passed"),
        3 => println!("  XDP_TX (3) - Transmit packet"),
        4 => println!("  XDP_REDIRECT (4) - Redirect packet"),
        _ => println!("  Unknown value"),
    }

    println!("\n=== Demo Complete ===\n");

    println!("💡 Key Points:");
    println!("  • bpf_prog_test_run executes BPF programs without network attachment");
    println!("  • Skeleton provides type-safe access to programs and maps");
    println!("  • Perfect for unit testing and validation");
    println!("  • BPF maps avoid packet bounds checking complexity");
    println!("  • Can capture bpf_printk() output from trace_pipe\n");

    println!("💡 Why use BPF maps for data:");
    println!("  • Simpler code - no packet bounds verification");
    println!("  • Larger data sizes (4KB+ vs 64 bytes)");
    println!("  • Direct memory access without copy loops");
    println!("  • Verifier accepts it easily\n");

    println!("💡 To see BPF traces:");
    println!("  Terminal 1: sudo cat /sys/kernel/debug/tracing/trace_pipe");
    println!("  Terminal 2: cryptbpf prog-test-run-demo\n");

    Ok(())
}

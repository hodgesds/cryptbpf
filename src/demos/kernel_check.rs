// Kernel Support Check
// Verifies BPF crypto kfunc availability

use anyhow::Result;
use std::fs;
use std::process::Command;

pub fn run() -> Result<()> {
    println!("\n=== BPF Crypto Kernel Support Check ===\n");

    // 1. Kernel version
    let version = fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "unknown".to_string());
    println!("Kernel: {}", version.lines().next().unwrap_or("unknown"));

    // 2. Check kallsyms for bpf_sha256_hash
    println!("\n--- Checking /proc/kallsyms ---");
    match fs::read_to_string("/proc/kallsyms") {
        Ok(syms) => {
            let sha_syms: Vec<&str> = syms.lines()
                .filter(|line| line.contains("bpf_sha256"))
                .collect();

            if sha_syms.is_empty() {
                println!("❌ bpf_sha256_hash NOT found in kallsyms");
            } else {
                println!("✅ bpf_sha256_hash found in kallsyms:");
                for sym in sha_syms {
                    println!("   {}", sym);
                }
            }
        }
        Err(e) => println!("⚠️  Cannot read /proc/kallsyms: {}", e),
    }

    // 3. Check kernel config
    println!("\n--- Checking kernel config ---");
    let config_paths = vec![
        format!("/boot/config-{}",
                Command::new("uname").arg("-r").output()
                    .ok().and_then(|o| String::from_utf8(o.stdout).ok())
                    .unwrap_or_default().trim()),
        "/proc/config.gz".to_string(),
    ];

    let mut found_config = false;
    for path in config_paths {
        if path.ends_with(".gz") {
            if let Ok(output) = Command::new("zcat").arg(&path).output() {
                if let Ok(config) = String::from_utf8(output.stdout) {
                    check_config(&config);
                    found_config = true;
                    break;
                }
            }
        } else if let Ok(config) = fs::read_to_string(&path) {
            check_config(&config);
            found_config = true;
            break;
        }
    }

    if !found_config {
        println!("⚠️  Kernel config not accessible");
    }

    // 4. Check BTF
    println!("\n--- Checking BTF ---");
    if let Ok(output) = Command::new("bpftool")
        .args(&["btf", "dump", "file", "/sys/kernel/btf/vmlinux"])
        .output()
    {
        if let Ok(btf) = String::from_utf8(output.stdout) {
            let sha_funcs: Vec<&str> = btf.lines()
                .filter(|line| line.contains("sha256") || line.contains("SHA256"))
                .take(10)
                .collect();

            if sha_funcs.is_empty() {
                println!("⚠️  No SHA256 functions found in BTF");
            } else {
                println!("✅ Found SHA256 in BTF:");
                for func in sha_funcs {
                    println!("   {}", func.trim());
                }
            }
        }
    } else {
        println!("⚠️  bpftool not available or BTF not accessible");
    }

    // 5. Check dmesg
    println!("\n--- Recent BPF messages in dmesg ---");
    if let Ok(output) = Command::new("dmesg").output() {
        if let Ok(dmesg) = String::from_utf8(output.stdout) {
            let bpf_msgs: Vec<&str> = dmesg.lines()
                .filter(|line| line.to_lowercase().contains("bpf"))
                .rev()
                .take(10)
                .collect();

            if bpf_msgs.is_empty() {
                println!("No recent BPF messages");
            } else {
                for msg in bpf_msgs.iter().rev() {
                    println!("{}", msg);
                }
            }
        }
    }

    println!("\n=== Check Complete ===\n");

    Ok(())
}

fn check_config(config: &str) {
    let relevant_configs = vec![
        "CONFIG_BPF",
        "CONFIG_BPF_SYSCALL",
        "CONFIG_BPF_JIT",
        "CONFIG_HAVE_EBPF_JIT",
        "CONFIG_BPF_KPROBE_OVERRIDE",
        "CONFIG_CRYPTO",
        "CONFIG_CRYPTO_SHA256",
    ];

    for cfg in relevant_configs {
        for line in config.lines() {
            if line.starts_with(cfg) && !line.starts_with("#") {
                println!("   {}", line);
            }
        }
    }
}

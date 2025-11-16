// Load Balancer with Client Certificate Session Detection Demo
//
// This demo shows how to implement session-aware load balancing using
// client certificate fingerprints for session detection and affinity.
//
// Usage: cryptbpf load-balancer --device eth0 --config lb_config.toml

use anyhow::{Result, Context, bail};
use libbpf_rs::MapCore;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use p256::ecdsa::{SigningKey, signature::Verifier};
use sha2::{Digest, Sha256};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::thread;
use std::str::FromStr;

// Include the generated skeleton
mod load_balancer_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf/load_balancer.skel.rs"));
}
use load_balancer_skel::*;

const SHA256_DIGEST_SIZE: usize = 32;
const ECDSA_PUBKEY_SIZE: usize = 65;

// TOML Configuration structures
#[derive(Debug, Deserialize, Serialize)]
pub struct LoadBalancerConfig {
    pub load_balancer: LBSettings,
    pub backends: Vec<BackendConfig>,
    pub certificates: Vec<CertificateConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LBSettings {
    pub session_timeout_sec: u32,
    pub algorithm: String, // "round-robin", "least-connections", "weighted"
    pub require_cert_auth: bool,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BackendConfig {
    pub id: u32,
    pub ip: String,
    pub port: u16,
    pub enabled: bool,
    pub weight: u32,
    pub max_connections: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CertificateConfig {
    pub id: u8,
    pub name: String,
    pub generate_on_startup: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
    pub valid_until_days: u64,
}

// BPF map structures (must match BPF program)
#[repr(C)]
struct BackendServer {
    ip_addr: u32,
    port: u16,
    enabled: u8,
    health_status: u8,
    weight: u32,
    max_connections: u32,
    current_connections: u32,
    total_requests: u64,
    total_bytes: u64,
}

#[repr(C)]
struct ClientCertificate {
    pubkey: [u8; ECDSA_PUBKEY_SIZE],
    cert_hash: [u8; SHA256_DIGEST_SIZE],
    issued_at: u64,
    expires_at: u64,
    sessions_created: u32,
    valid: u8,
    reserved: [u8; 7],
}

#[repr(C)]
struct LbConfig {
    num_backends: u32,
    session_timeout_sec: u32,
    lb_algorithm: u32,  // 0=round-robin, 1=least-conn, 2=weighted
    require_cert_auth: u32,
    enabled: u32,
}

#[repr(C)]
struct LbStats {
    total_packets: u64,
    sessions_created: u64,
    sessions_reused: u64,
    auth_success: u64,
    auth_failed: u64,
    cert_invalid: u64,
    cert_expired: u64,
    no_backend_available: u64,
    load_balanced: u64,
}

impl Default for LoadBalancerConfig {
    fn default() -> Self {
        LoadBalancerConfig {
            load_balancer: LBSettings {
                session_timeout_sec: 300,
                algorithm: "round-robin".to_string(),
                require_cert_auth: true,
                enabled: true,
            },
            backends: vec![
                BackendConfig {
                    id: 0,
                    ip: "192.168.1.10".to_string(),
                    port: 8080,
                    enabled: true,
                    weight: 100,
                    max_connections: 1000,
                },
                BackendConfig {
                    id: 1,
                    ip: "192.168.1.11".to_string(),
                    port: 8080,
                    enabled: true,
                    weight: 100,
                    max_connections: 1000,
                },
                BackendConfig {
                    id: 2,
                    ip: "192.168.1.12".to_string(),
                    port: 8080,
                    enabled: true,
                    weight: 50,
                    max_connections: 500,
                },
            ],
            certificates: vec![
                CertificateConfig {
                    id: 0,
                    name: "client-cert-1".to_string(),
                    generate_on_startup: true,
                    public_key_hex: None,
                    valid_until_days: 365,
                },
                CertificateConfig {
                    id: 1,
                    name: "client-cert-2".to_string(),
                    generate_on_startup: true,
                    public_key_hex: None,
                    valid_until_days: 365,
                },
            ],
        }
    }
}

fn parse_config(config_path: &str) -> Result<LoadBalancerConfig> {
    let contents = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path))?;

    let config: LoadBalancerConfig = toml::from_str(&contents)
        .with_context(|| "Failed to parse TOML configuration")?;

    Ok(config)
}

fn ip_to_u32(ip_str: &str) -> Result<u32> {
    let ip = Ipv4Addr::from_str(ip_str)
        .with_context(|| format!("Invalid IP address: {}", ip_str))?;
    Ok(u32::from(ip))
}

fn algorithm_to_id(algo: &str) -> u32 {
    match algo {
        "round-robin" => 0,
        "least-connections" => 1,
        "weighted" => 2,
        _ => 0, // default to round-robin
    }
}

fn setup_bpf_config(
    skel: &LoadBalancerSkel,
    config: &LoadBalancerConfig,
) -> Result<()> {
    println!("--- Configuring Load Balancer ---");

    // Configure LB settings
    let lb_config = LbConfig {
        num_backends: config.backends.len() as u32,
        session_timeout_sec: config.load_balancer.session_timeout_sec,
        lb_algorithm: algorithm_to_id(&config.load_balancer.algorithm),
        require_cert_auth: if config.load_balancer.require_cert_auth { 1 } else { 0 },
        enabled: if config.load_balancer.enabled { 1 } else { 0 },
    };

    let key = 0u32.to_ne_bytes();
    let lb_config_bytes = unsafe {
        std::slice::from_raw_parts(
            &lb_config as *const LbConfig as *const u8,
            std::mem::size_of::<LbConfig>(),
        )
    };
    skel.maps.lb_config_map.update(&key, lb_config_bytes, libbpf_rs::MapFlags::ANY)?;

    println!("✓ Load balancer settings:");
    println!("  Algorithm: {}", config.load_balancer.algorithm);
    println!("  Session timeout: {}s", config.load_balancer.session_timeout_sec);
    println!("  Require auth: {}", config.load_balancer.require_cert_auth);

    // Configure backends
    println!("\n--- Configuring Backends ---");
    for backend in &config.backends {
        let backend_server = BackendServer {
            ip_addr: ip_to_u32(&backend.ip)?,
            port: backend.port,
            enabled: if backend.enabled { 1 } else { 0 },
            health_status: 1, // Assume healthy initially
            weight: backend.weight,
            max_connections: backend.max_connections,
            current_connections: 0,
            total_requests: 0,
            total_bytes: 0,
        };

        let backend_key = backend.id.to_ne_bytes();
        let backend_bytes = unsafe {
            std::slice::from_raw_parts(
                &backend_server as *const BackendServer as *const u8,
                std::mem::size_of::<BackendServer>(),
            )
        };
        skel.maps.backends_map.update(&backend_key, backend_bytes, libbpf_rs::MapFlags::ANY)?;

        println!("✓ Backend #{}: {}:{} (weight={}, max_conn={})",
                 backend.id, backend.ip, backend.port,
                 backend.weight, backend.max_connections);
    }

    Ok(())
}

fn setup_certificates(
    skel: &LoadBalancerSkel,
    config: &LoadBalancerConfig,
) -> Result<()> {
    println!("\n--- Setting Up Client Certificates ---");

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    for cert_config in &config.certificates {
        let (pubkey_bytes, cert_hash) = if cert_config.generate_on_startup {
            // Generate new keypair
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let pubkey_point = verifying_key.to_encoded_point(false);
            let pubkey_bytes = pubkey_point.as_bytes();

            // Calculate certificate hash
            let mut hasher = Sha256::new();
            hasher.update(pubkey_bytes);
            let cert_hash = hasher.finalize();

            println!("✓ Generated certificate '{}' (ID: {})", cert_config.name, cert_config.id);
            println!("  Public key (first 16 bytes): {}", hex::encode(&pubkey_bytes[..16]));
            println!("  Certificate hash: {}", hex::encode(&cert_hash));

            (pubkey_bytes.to_vec(), cert_hash.to_vec())
        } else if let Some(ref pubkey_hex) = cert_config.public_key_hex {
            // Use provided public key
            let pubkey_bytes = hex::decode(pubkey_hex)
                .with_context(|| "Invalid public key hex")?;

            let mut hasher = Sha256::new();
            hasher.update(&pubkey_bytes);
            let cert_hash = hasher.finalize();

            println!("✓ Loaded certificate '{}' (ID: {})", cert_config.name, cert_config.id);

            (pubkey_bytes, cert_hash.to_vec())
        } else {
            bail!("Certificate must have either generate_on_startup=true or public_key_hex set");
        };

        if pubkey_bytes.len() != ECDSA_PUBKEY_SIZE {
            bail!("Public key must be {} bytes (uncompressed format)", ECDSA_PUBKEY_SIZE);
        }

        let mut client_cert = ClientCertificate {
            pubkey: [0u8; ECDSA_PUBKEY_SIZE],
            cert_hash: [0u8; SHA256_DIGEST_SIZE],
            issued_at: current_time,
            expires_at: current_time + (cert_config.valid_until_days * 24 * 3600),
            sessions_created: 0,
            valid: 1,
            reserved: [0u8; 7],
        };

        client_cert.pubkey.copy_from_slice(&pubkey_bytes);
        client_cert.cert_hash.copy_from_slice(&cert_hash);

        let cert_key = [cert_config.id];
        let cert_bytes = unsafe {
            std::slice::from_raw_parts(
                &client_cert as *const ClientCertificate as *const u8,
                std::mem::size_of::<ClientCertificate>(),
            )
        };
        skel.maps.certificates_map.update(&cert_key, cert_bytes, libbpf_rs::MapFlags::ANY)?;
    }

    Ok(())
}

fn print_statistics(skel: &LoadBalancerSkel) -> Result<()> {
    let key = 0u32.to_ne_bytes();

    // Get LB statistics
    if let Some(stats_bytes) = skel.maps.lb_stats_map.lookup(&key, libbpf_rs::MapFlags::ANY)? {
        if stats_bytes.len() >= std::mem::size_of::<LbStats>() {
            let stats = unsafe {
                &*(stats_bytes.as_ptr() as *const LbStats)
            };

            println!("\n=== Load Balancer Statistics ===");
            println!("Total packets: {}", stats.total_packets);
            println!("Sessions created: {}", stats.sessions_created);
            println!("Sessions reused: {}", stats.sessions_reused);
            println!("Auth success: {}", stats.auth_success);
            println!("Auth failed: {}", stats.auth_failed);
            println!("Cert invalid: {}", stats.cert_invalid);
            println!("Cert expired: {}", stats.cert_expired);
            println!("No backend available: {}", stats.no_backend_available);
            println!("Load balanced: {}", stats.load_balanced);
        }
    }

    // Get backend statistics
    println!("\n=== Backend Statistics ===");
    for i in 0..16 {
        let backend_key = i.to_ne_bytes();
        if let Some(backend_bytes) = skel.maps.backends_map.lookup(&backend_key, libbpf_rs::MapFlags::ANY)? {
            if backend_bytes.len() >= std::mem::size_of::<BackendServer>() {
                let backend = unsafe {
                    &*(backend_bytes.as_ptr() as *const BackendServer)
                };

                if backend.enabled == 1 {
                    let ip = Ipv4Addr::from(backend.ip_addr);
                    println!("Backend #{}: {}:{}", i, ip, backend.port);
                    println!("  Status: {}", if backend.health_status == 1 { "UP" } else { "DOWN" });
                    println!("  Current connections: {}/{}", backend.current_connections, backend.max_connections);
                    println!("  Total requests: {}", backend.total_requests);
                    println!("  Total bytes: {}", backend.total_bytes);
                }
            }
        }
    }

    Ok(())
}

pub fn run(device: &str, config_path: Option<&str>) -> Result<()> {
    println!("\n=== Load Balancer with Client Certificate Session Detection ===\n");

    // Parse configuration
    let config = if let Some(path) = config_path {
        println!("Loading configuration from: {}", path);
        parse_config(path)?
    } else {
        println!("No config file specified, using default configuration");
        LoadBalancerConfig::default()
    };

    println!("\nConfiguration loaded:");
    println!("  Backends: {}", config.backends.len());
    println!("  Certificates: {}", config.certificates.len());

    // Load BPF program
    println!("\n--- Loading BPF Program ---");
    let skel_builder = LoadBalancerSkelBuilder::default();
    let mut open_object = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let skel = open_skel.load()?;
    println!("✓ BPF program loaded");

    // Setup configuration
    setup_bpf_config(&skel, &config)?;
    setup_certificates(&skel, &config)?;

    // Get network interface index
    println!("\n--- Attaching to Network Interface ---");
    let if_index = nix::net::if_::if_nametoindex(device)
        .with_context(|| format!("Failed to get interface index for {}", device))?;

    println!("Attaching to device: {} (index: {})", device, if_index);
    let _link = skel.progs.xdp_load_balancer
        .attach_xdp(if_index as i32)
        .with_context(|| "Failed to attach XDP program")?;

    println!("✓ XDP program attached successfully");

    println!("\n=== Load Balancer Running ===");
    println!("Monitoring traffic on {}...", device);
    println!("Press Ctrl+C to stop\n");

    println!("💡 How this works:");
    println!("  1. Clients send UDP packets to port 8080 with certificate info");
    println!("  2. Load balancer verifies ECDSA signature using client certificate");
    println!("  3. Sessions are tracked using certificate hash (SHA-256)");
    println!("  4. Same client always goes to same backend (session affinity)");
    println!("  5. New sessions use {} algorithm", config.load_balancer.algorithm);
    println!("\n💡 Packet format:");
    println!("  [payload][cert_header]");
    println!("  cert_header = magic(4) + cert_hash(32) + signature(64) + pubkey_id(1)");

    // Monitor loop
    loop {
        thread::sleep(Duration::from_secs(5));
        print_statistics(&skel)?;
    }
}

use anyhow::Result;
use clap::{Parser, Subcommand};

mod demos;

#[derive(Parser)]
#[command(name = "cryptbpf")]
#[command(about = "Advanced BPF Cryptography Programs", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Load the encrypted tunnel XDP program
    EncryptedTunnel {
        /// Network interface to attach to
        #[arg(short, long)]
        device: String,
    },
    /// Load the zero-knowledge packet filter TC program
    ZkpFilter {
        /// Network interface to attach to
        #[arg(short, long)]
        device: String,
    },
    /// Load the signed packet authentication XDP program
    SignedAuth {
        /// Network interface to attach to
        #[arg(short, long)]
        device: String,
    },
    /// Load the encrypted logger tracepoint program
    EncryptedLogger,
    /// Load the cryptographic rate limiting XDP program
    CryptoRatelimit {
        /// Network interface to attach to
        #[arg(short, long)]
        device: String,
        /// Proof-of-work difficulty (number of leading zero bits)
        #[arg(short = 'p', long, default_value = "16")]
        pow_difficulty: u32,
    },
    /// Load the PKI certificate validator TC program
    PkiValidator {
        /// Network interface to attach to
        #[arg(short, long)]
        device: String,
    },
    /// Load the content-addressed storage verifier XDP program
    ContentVerifier {
        /// Network interface to attach to
        #[arg(short, long)]
        device: String,
        /// Enforce allowlist
        #[arg(short = 'a', long)]
        enforce_allowlist: bool,
    },
    /// Load the crypto offload manager XDP program
    CryptoOffload {
        /// Network interface to attach to
        #[arg(short, long)]
        device: String,
    },
    /// Show statistics for all loaded programs
    Stats,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Check if running as root
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("Error: This program must be run as root (sudo)");
        std::process::exit(1);
    }

    match cli.command {
        Commands::EncryptedTunnel { device } => {
            demos::encrypted_tunnel::run(&device)
        }
        Commands::ZkpFilter { device } => {
            demos::zkp_filter::run(&device)
        }
        Commands::SignedAuth { device } => {
            demos::signed_auth::run(&device)
        }
        Commands::EncryptedLogger => {
            println!("Loading Encrypted Logger tracepoint program");
            println!("\nFeatures:");
            println!("  - Encrypted audit logging");
            println!("  - Process execution monitoring");
            println!("  - Secure ring buffer communication");
            println!("\nPress Ctrl+C to unload and exit...");
            Ok(())
        }
        Commands::CryptoRatelimit { device, pow_difficulty } => {
            demos::pow_ratelimit::run(&device, pow_difficulty)
        }
        Commands::PkiValidator { device } => {
            demos::pki_validator::run(&device)
        }
        Commands::ContentVerifier { device, enforce_allowlist } => {
            demos::content_verifier::run(&device, enforce_allowlist)
        }
        Commands::CryptoOffload { device } => {
            demos::crypto_offload::run(&device)
        }
        Commands::Stats => {
            println!("=== CryptBPF Statistics ===\n");
            println!("Program statistics would be displayed here.");
            println!("This would query BPF maps for counters from all loaded programs.");
            Ok(())
        }
    }
}

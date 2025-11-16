use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const BPF_PROGRAMS: &[&str] = &[
    "encrypted_tunnel",
    "zkp_filter",
    "signed_auth",
    "encrypted_logger",
    "crypto_ratelimit",
    "pki_validator",
    "content_verifier",
    "crypto_offload",
    "load_balancer",
    "hash_test",
    "ecdsa_test",
];

fn main() {
    let mut out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("bpf");
    std::fs::create_dir_all(&out).expect("Failed to create OUT_DIR/bpf directory");

    for program in BPF_PROGRAMS {
        let src = format!("src/bpf/{}.bpf.c", program);

        println!("cargo:rerun-if-changed={}", src);
        println!("cargo:rerun-if-changed=src/bpf/common.h");
        println!("cargo:rerun-if-changed=src/bpf/vmlinux.h");

        SkeletonBuilder::new()
            .source(&src)
            .build_and_generate(&out.join(format!("{}.skel.rs", program)))
            .unwrap_or_else(|e| panic!("Failed to build BPF skeleton for {}: {}", program, e));
    }
}

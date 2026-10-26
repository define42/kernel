use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    for path in [
        "linker.ld",
        "src/boot.S",
        "src/traps.S",
        "abi.rs",
        "userspace/main.rs",
        "userspace/fuzz.rs",
        "userspace/syscall.rs",
        "userspace/http.rs",
        "userspace/linker.ld",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    for (name, default, maximum) in [
        ("KERNEL_FUZZ_SEED", 1u64, u64::MAX),
        ("KERNEL_FUZZ_ITERATIONS", 100_000, 100_000_000),
    ] {
        println!("cargo:rerun-if-env-changed={name}");
        let value = env::var(name)
            .map(|s| s.parse::<u64>().expect("numeric fuzz configuration"))
            .unwrap_or(default);
        assert!(
            value > 0 && value <= maximum,
            "fuzz configuration out of range"
        );
        println!("cargo:rustc-env={name}={value}");
    }
    // The boot-only test deliberately has no userspace dependency.
    if env::var_os("CARGO_FEATURE_SMOKE_TEST").is_some() {
        return;
    }
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut compiler = Command::new(env::var_os("RUSTC").unwrap());
    compiler
        .arg(root.join("userspace/main.rs"))
        .args([
            "--edition=2024",
            "--crate-name=webserver",
            "--crate-type=bin",
            "--target=x86_64-unknown-none",
            "--check-cfg=cfg(userspace_test)",
            "-Cpanic=abort",
            "-Copt-level=2",
            "-Cdebuginfo=2",
            "-Crelocation-model=static",
            "-Ccode-model=small",
            "-Clink-arg=--build-id=none",
            "-Dwarnings",
        ])
        .arg(format!(
            "-Clink-arg=-T{}",
            root.join("userspace/linker.ld").display()
        ))
        .arg("-o")
        .arg(output.join("webserver.elf"));
    if [
        "CARGO_FEATURE_USERSPACE_TEST",
        "CARGO_FEATURE_PREEMPTION_TEST",
        "CARGO_FEATURE_FUZZ_TEST",
    ]
    .iter()
    .any(|key| env::var_os(key).is_some())
    {
        compiler.arg("--cfg=userspace_test");
    }
    assert!(
        compiler
            .status()
            .expect("run userspace Rust compiler")
            .success(),
        "userspace executable failed to build"
    );
    // A predictable path next to the kernel ELF makes debugging the separate
    // executable easy; the kernel embeds the exact OUT_DIR artifact below.
    let profile = output.ancestors().nth(3).expect("Cargo profile directory");
    std::fs::copy(output.join("webserver.elf"), profile.join("webserver.elf"))
        .expect("copy userspace ELF beside kernel");
}

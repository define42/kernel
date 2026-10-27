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
        "userspace/heap.rs",
        "userspace/heap_test.rs",
        "userspace/linker.ld",
        "userspace/netd.rs",
        "userspace/arp_announce.rs",
        "userspace/network_config.rs",
        "userspace/net_syscall.rs",
        "userspace/driver.rs",
        "userspace/e1000.rs",
        "userspace/services/Cargo.toml",
        "userspace/services/Cargo.lock",
        "src/abuse.rs",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=KERNEL_IR_PROBE");
    println!("cargo:rerun-if-env-changed=KERNEL_SHARED_FAULT_PROBE");
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
    for name in [
        "KERNEL_IPV4",
        "KERNEL_PREFIX",
        "KERNEL_GATEWAY",
        "KERNEL_ECHO",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    // The boot-only test deliberately has no userspace dependency.
    if env::var_os("CARGO_FEATURE_SMOKE_TEST").is_some() {
        return;
    }
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    if env::var_os("CARGO_FEATURE_STD_TEST").is_some() {
        println!("cargo:rerun-if-env-changed=KERNEL_STD_ELF");
        let image = env::var_os("KERNEL_STD_ELF")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("build/std/std-demo.elf"));
        println!("cargo:rerun-if-changed={}", image.display());
        std::fs::copy(&image, output.join("webserver.elf"))
            .expect("build the userspace std ELF first with make std-demo");
        return;
    }
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
        "CARGO_FEATURE_ISOLATION_TEST",
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
    if env::var_os("CARGO_FEATURE_USERSPACE_TEST").is_some() {
        return;
    }
    let status = Command::new(env::var_os("RUSTC").unwrap())
        .arg(root.join("userspace/driver.rs"))
        .args([
            "--edition=2024",
            "--crate-name=nic_driver",
            "--check-cfg=cfg(driver_test)",
            "--crate-type=bin",
            "--target=x86_64-unknown-none",
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
        .args(
            env::var_os("CARGO_FEATURE_ISOLATION_TEST")
                .is_some()
                .then_some("--cfg=driver_test"),
        )
        .arg("-o")
        .arg(output.join("nic-driver.elf"))
        .status()
        .expect("run driver Rust compiler");
    assert!(status.success(), "userspace driver failed to build");
    let flags = [
        "-Crelocation-model=static".to_owned(),
        "-Ccode-model=small".to_owned(),
        "-Clink-arg=--build-id=none".to_owned(),
        format!(
            "-Clink-arg=-T{}",
            root.join("userspace/linker.ld").display()
        ),
    ];
    let service_target = output.join("services-target");
    let status = Command::new(env::var_os("CARGO").unwrap())
        .args([
            "build",
            "--locked",
            "--release",
            "--target",
            "x86_64-unknown-none",
            "--manifest-path",
        ])
        .arg(root.join("userspace/services/Cargo.toml"))
        .arg("--target-dir")
        .arg(&service_target)
        .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\x1f"))
        .status()
        .expect("build userspace networking service");
    assert!(
        status.success(),
        "userspace network service failed to build"
    );
    std::fs::copy(
        service_target.join("x86_64-unknown-none/release/netd"),
        output.join("netd.elf"),
    )
    .expect("copy network service ELF");
    for name in ["nic-driver.elf", "netd.elf"] {
        std::fs::copy(output.join(name), profile.join(name))
            .expect("copy service ELF beside kernel");
    }
}

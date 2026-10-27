//! Ordinary Rust `std` executable for the kernel's initial userspace port.

use kernel_std_runtime as _;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::hint::black_box;
use std::io::{ErrorKind, Read, Write};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[path = "../../../abi.rs"]
mod abi;

thread_local! {
    static LOCAL: Cell<u32> = const { Cell::new(0) };
    static LAZY_LOCAL: RefCell<String> = RefCell::new(String::from("initial"));
}

static INITIALIZED: OnceLock<String> = OnceLock::new();

fn main() {
    match kernel_std_runtime::startup_mode() {
        0 => checks(),
        1 => panic!("intentional std panic containment probe"),
        2 => {
            let allocation = Vec::<u8>::with_capacity(black_box(abi::USER_HEAP_SIZE + 1));
            black_box(allocation);
            unexpected_survival();
        }
        3 => std::process::exit(7),
        4 => entropy_refusal(),
        mode => panic!("unexpected std probe mode {mode}"),
    }
}

fn unexpected_survival() -> ! {
    // A distinct code prevents an accidentally surviving failure probe from
    // being confused with the expected abort path.
    unsafe { kernel_std_runtime::raw(abi::SYS_EXIT, 255, 0, 0) };
    loop {
        std::hint::spin_loop();
    }
}

fn entropy_refusal() {
    LOCAL.with(|local| {
        assert_eq!(local.get(), 0, "thread-local state survived entropy abort");
        local.set(4);
    });
    LAZY_LOCAL.with(|local| {
        assert_eq!(
            *local.borrow(),
            "initial",
            "lazy TLS survived entropy abort"
        );
        local.borrow_mut().push_str(" changed");
    });
    let mut bytes = [0xa5; 32];
    // The CPU in this probe has neither RDRAND nor RDSEED. A failed entropy
    // request must not replace caller data with a partial or predictable seed.
    let result = unsafe {
        kernel_std_runtime::raw(
            abi::SYS_RANDOM_BYTES,
            bytes.as_mut_ptr() as u64,
            bytes.len() as u64,
            0,
        )
    };
    assert_eq!(result, abi::EIO);
    assert_eq!(bytes, [0xa5; 32]);
    println!("std unavailable entropy leaves output unchanged.");
    let mut map = HashMap::new();
    map.insert(1u64, 2u64);
    black_box(map);
    unexpected_survival();
}

fn checks() {
    LOCAL.with(|local| {
        assert_eq!(
            local.get(),
            0,
            "thread-local state survived process restart"
        );
        local.set(73);
    });
    assert!(
        INITIALIZED.get().is_none(),
        "OnceLock survived process restart"
    );
    LAZY_LOCAL.with(|local| {
        assert_eq!(
            *local.borrow(),
            "initial",
            "lazy TLS survived process restart"
        );
        local.borrow_mut().push_str(" changed");
    });

    let layout = Layout::from_size_align(257, 64).unwrap();
    // SAFETY: nonzero valid layout; the successful System allocation is checked,
    // accessed only within its extent, and freed exactly once with that layout.
    unsafe {
        let pointer = System.alloc(layout);
        assert!(!pointer.is_null(), "System allocator returned null");
        assert_eq!(pointer as usize % layout.align(), 0);
        assert!((pointer as u64) >= abi::USER_HEAP_BASE);
        assert!((pointer as u64) + layout.size() as u64 <= abi::USER_HEAP_END);
        pointer.write_bytes(0xa5, layout.size());
        assert!(
            std::slice::from_raw_parts(pointer, layout.size())
                .iter()
                .all(|&byte| byte == 0xa5)
        );
        System.dealloc(pointer, layout);
    }
    println!("std System allocation checks passed.");

    let mut values = Vec::new();
    values.try_reserve_exact(256).expect("fallible allocation");
    values.extend(0u32..256);
    assert_eq!(values.iter().sum::<u32>(), 32_640);
    assert!(values.try_reserve(abi::USER_HEAP_SIZE).is_err());
    assert_eq!(values.len(), 256, "failed reserve changed the Vec");
    assert_eq!(values.iter().sum::<u32>(), 32_640);
    let mut text = String::from("ring-3");
    text.push_str(" standard library");
    assert_eq!(text, "ring-3 standard library");

    let mut map = HashMap::new();
    for value in values {
        map.insert(format!("key-{value}"), value);
    }
    assert_eq!(map.len(), 256);
    assert_eq!(map.get("key-127"), Some(&127));
    assert_eq!(map.remove("key-127"), Some(127));
    assert_eq!(map.get("key-127"), None);
    println!(
        "std Vec/String/HashMap checks passed: {} entries.",
        map.len()
    );

    let mutex = Mutex::new(11u32);
    *mutex.lock().unwrap() += 4;
    assert_eq!(*mutex.try_lock().unwrap(), 15);
    assert_eq!(
        INITIALIZED.get_or_init(|| String::from("initialized")),
        "initialized"
    );
    assert_eq!(INITIALIZED.get().unwrap(), "initialized");
    LOCAL.with(|local| assert_eq!(local.get(), 73));
    LAZY_LOCAL.with(|local| assert_eq!(*local.borrow(), "initial changed"));
    println!("std thread-local/Mutex/OnceLock checks passed.");
    std::thread::current().unpark();
    std::thread::park();
    std::thread::park_timeout(Duration::ZERO);
    println!("std thread park token and zero timeout checks passed.");

    // This is a yielding, monotonic wait. No native userspace thread is created.
    let before = Instant::now();
    std::thread::sleep(Duration::from_millis(20));
    let after = Instant::now();
    assert!(after >= before);
    assert!(after.duration_since(before) >= Duration::from_millis(20));
    println!("std Instant and yielding sleep checks passed.");

    assert_eq!(std::env::args().count(), 0);
    assert_eq!(std::env::vars().count(), 0);
    assert_eq!(
        std::io::stdin().read(&mut [0u8; 1]).unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        std::process::Command::new("/unsupported")
            .spawn()
            .unwrap_err()
            .kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        std::fs::read("/unsupported").unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        std::net::TcpListener::bind("127.0.0.1:80")
            .unwrap_err()
            .kind(),
        ErrorKind::Unsupported,
    );
    assert_eq!(
        std::thread::Builder::new().spawn(|| ()).unwrap_err().kind(),
        ErrorKind::Unsupported,
    );
    println!("std unavailable OS operations return Unsupported.");

    syscall_boundaries();
    std::io::stdout()
        .write_all(b"std stdout Write checks passed.\n")
        .unwrap();
    std::io::stdout().write_all(&[0xff, 0, b'\n']).unwrap();
    eprintln!("std stderr checks passed.");
    println!("Userspace std checks passed.");
}

fn syscall_boundaries() {
    // Only byte ranges validated by the kernel are passed to the new calls.
    // Invalid addresses below are intentional ring-3 security probes.
    let mut random = [0u8; abi::MAX_RANDOM_BYTES];
    let address = random.as_mut_ptr() as u64;
    unsafe {
        assert_eq!(
            kernel_std_runtime::raw(
                abi::SYS_RANDOM_BYTES,
                address,
                abi::MAX_RANDOM_BYTES as u64,
                0
            ),
            abi::MAX_RANDOM_BYTES as i64
        );
        assert_eq!(
            kernel_std_runtime::raw(abi::SYS_RANDOM_BYTES, u64::MAX, 0, 0),
            0
        );
        assert_eq!(
            kernel_std_runtime::raw(
                abi::SYS_RANDOM_BYTES,
                address,
                abi::MAX_RANDOM_BYTES as u64 + 1,
                0
            ),
            abi::EINVAL
        );
        assert_eq!(
            kernel_std_runtime::raw(abi::SYS_RANDOM_BYTES, address, 8, 1),
            abi::EINVAL
        );
        for invalid in [
            0,
            abi::KERNEL_PROBE_ADDRESS,
            0x4000_0000, // Executable, read-only image page.
            abi::USER_HEAP_BASE - 1,
            abi::USER_HEAP_END,
            abi::DRIVER_MMIO,
            u64::MAX,
        ] {
            assert_eq!(
                kernel_std_runtime::raw(abi::SYS_RANDOM_BYTES, invalid, 1, 0),
                abi::EFAULT
            );
        }
        assert_eq!(
            kernel_std_runtime::raw(abi::SYS_RANDOM_BYTES, abi::USER_HEAP_END - 1, 2, 0),
            abi::EFAULT,
        );
        assert_eq!(kernel_std_runtime::raw(abi::SYS_WRITE, 1, u64::MAX, 0), 0);
        assert_eq!(
            kernel_std_runtime::raw(abi::SYS_WRITE, 0, address, 1),
            abi::EBADF
        );
        assert_eq!(
            kernel_std_runtime::raw(abi::SYS_WRITE, 3, address, 1),
            abi::EBADF
        );
        assert_eq!(
            kernel_std_runtime::raw(abi::SYS_WRITE, 1, address, abi::MAX_LOG as u64 + 1),
            abi::EINVAL,
        );
        for invalid in [
            0,
            abi::KERNEL_PROBE_ADDRESS,
            abi::USER_HEAP_END,
            abi::DRIVER_MMIO,
            u64::MAX,
        ] {
            assert_eq!(
                kernel_std_runtime::raw(abi::SYS_WRITE, 1, invalid, 1),
                abi::EFAULT
            );
        }
        assert_eq!(
            kernel_std_runtime::raw(abi::SYS_WRITE, 2, abi::USER_HEAP_END - 1, 2),
            abi::EFAULT,
        );
    }
    println!("std random/stdio syscall boundary checks passed.");
}

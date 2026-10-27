# Kernel userspace port of Rust `std`

This directory adds a platform backend to the **real upstream Rust standard
library**, pinned to `nightly-2026-04-15`. It is not a replacement crate named
`std`, a libc implementation, or an Axum/Tokio port. Kernel code and existing
services can continue to use `no_std`.

`apply.py` accepts the `library` directory in a disposable copy of that pinned
compiler's Rust sources. It verifies every upstream file against
`upstream.sha256` before writing any patch, then installs the files under
`overlay/`. Restore pristine sources before applying again. Do not apply it to a
shared rustup toolchain. The repository's `scripts/build_std.py` manages the
private compiler and source copy.

The target must be x86-64, use `target_os = "kernel"`, have no Unix/Windows target
family, disable native thread-local storage, and use `panic = "abort"`. Rust's
compiler-generated `main` must be called after the userspace runtime initializes
its private heap. No libc startup or system dynamic linker is used.

## Facilities

| Facility | Behavior |
| --- | --- |
| `Box`, `Vec`, `String`, collections | Process-local allocator; existing fixed 512 KiB heap and guard pages apply |
| `std::alloc::System` | Calls the runtime's direct heap exports, avoiding recursion through the global allocator |
| `HashMap` / `RandomState` | Seeds from bounded kernel random-byte requests; entropy errors abort instead of using predictable fallback keys |
| `stdout`, `stderr`, `println!`, formatting | Bounded writes to the kernel console; partial writes and `WouldBlock` are visible; no silent output loss |
| `stdin` | Empty reads return zero; nonempty reads return `Unsupported`; serial administration input belongs to the kernel console |
| `Instant` | Kernel monotonic clock, with millisecond resolution |
| `thread::sleep`, `yield_now` | Yield to the kernel scheduler; sleep rounds up, allows one clock quantum for timestamp truncation, and checks deadline arithmetic |
| `thread_local!` | Upstream single-thread storage within each process; lazy and const initialization work |
| `Mutex`, `RwLock`, `Once`, `OnceLock` | Upstream implementations for processes with only one thread |
| `thread::park`, `park_timeout`, `unpark` | Per-thread token plus scheduler yielding; waiting on a token without an unpark can wait forever |
| `available_parallelism` | One thread |
| Arguments and environment | Empty arguments and environment, absent variables |
| `process::exit` | Preserves explicit exit code through the runtime export |
| Panic, abort, allocation failure | Abort the current process with exit status 1; no unwinding |

The console is intentionally bounded and may be unavailable or backpressured.
`write_all` returns `WouldBlock` when the kernel cannot accept more output.
`println!` follows Rust's normal behavior of panicking if output fails.
Applications needing reliable sustained output should handle write errors and
retry after yielding. Successful writes mean the kernel accepted bytes, not that
a remote serial terminal has received them. The Rust stdout line buffer is
flushed by the normal std runtime cleanup.

## Unsupported operations

`std::fs`, `std::net`, child-process spawning, and thread creation use upstream
unsupported backends and return `ErrorKind::Unsupported` where the API returns an
I/O result. `thread::spawn` itself panics on failure; use
`thread::Builder::spawn` to observe that error. There is no mapping from this
port's `std::net` APIs to the existing custom network IPC yet.

APIs without a fallible return value cannot always report `Unsupported`:
`SystemTime::now` explicitly panics because the kernel exposes uptime rather than
wall-clock time. Process IDs, filesystem path discovery, environment mutation,
and condition-variable waiting have the limitations of upstream unsupported
backends. Environment mutation panics through the public std API. There is no
native TLS ABI, signal handling, shared-memory threading, dynamic loading,
unwinding, or symbolized backtrace support.

TLS destructors are not run at process exit, matching the upstream `no_threads`
backend. The kernel reclaims and zeros the entire process region on restart.
User data destructors do run normally for ordinary Rust values dropped before
exit. Panics and explicit process exits do not run stack destructors.

The single-thread TLS and synchronization choices are sound only while there is
exactly one executable thread in each process and no asynchronous userspace
signal callbacks. Adding user threads requires replacing those implementations
before threads can share an address space. Multiple isolated kernel processes
and timer preemption do not violate this condition.

## Runtime interface

The runtime exports these C ABI functions, all local to the userspace ELF:

```text
__kernel_std_alloc(size, align) -> pointer
__kernel_std_alloc_zeroed(size, align) -> pointer
__kernel_std_dealloc(pointer, size, align)
__kernel_std_realloc(pointer, old_size, align, new_size) -> pointer
__kernel_std_exit(i32) -> never
```

Allocator exports obey Rust `GlobalAlloc`'s unsafe caller contracts. Allocation
failure returns null, and a failed reallocation leaves its original allocation
intact. These functions must call the arena allocator directly, never `System`
or the global dispatch that forwards to `System`.

The backend uses the existing `int 0x80` ABI (RAX number/result, RDI/RSI/RDX
arguments): `POLL=0`, `NOW=1`, `RANDOM_BYTES=21`, and `WRITE=22`. Random requests
are at most 256 bytes; writes use descriptors 1 or 2 and at most 512 bytes.
Negative results are kernel error numbers. Empty buffers require no syscall.
Kernel syscall handlers validate user mappings, permissions, lengths, and roles.

Updating the Rust compiler requires reviewing the patch anchors, upstream
single-thread assumptions, generated ELF permissions/layout, and all runtime
validation again; changing the checksum file alone is insufficient.

# Rust kernel

A minimal x86-64 kernel that boots in QEMU. The kernel uses stable Rust,
`#![no_std]`, an Intel e1000 driver, and the allocation-free
[smoltcp](https://docs.rs/smoltcp/0.14.0/smoltcp/) network stack. A small assembly
bootstrap enters 64-bit long mode; Rust prints boot information to VGA and the
COM1 serial port, then starts an isolated **ring-3 HTTP process**. The e1000
driver, TCP/IP stack, and TCP echo service run in ring 0.

## Quick start

Install Rust with [rustup](https://rustup.rs/), plus QEMU, GNU binutils, and Make.
On Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install make binutils qemu-system-x86 python3
```

From this directory:

```sh
make setup
make run
```

`make run` builds the kernel and boots it in QEMU with serial output in your
terminal. Press **Ctrl-a**, release both keys, then press **x** to exit QEMU.
The first build needs internet access to install the Rust target and download
the locked smoltcp dependencies. Later builds use Cargo's local cache.

Expected output includes:

```text
Rust kernel
===========
CPU: x86-64 (long mode)
Paging: 4 GiB identity mapped (PCI MMIO uncached)
Memory: ...
Kernel booted successfully.
Kernel pages: RX text, R/NX constants, RW/NX data; SMEP=false SMAP=false
Timer: PIT 100 Hz; preemptive user scheduling
e1000: MAC 52-54-00-12-34-56, link up
IPv4: 10.0.2.15/24, gateway 10.0.2.2
TCP echo listening on 10.0.2.15:1234
Host: connect to 127.0.0.1:5555 (make run default)
Web: http://127.0.0.1:8080/ (make run default)
Polling network. Use Ctrl-a x to exit QEMU.
Userspace: isolated RX/R/RW pages, NX stack, guarded stack
Userspace web server: CPL=3
HTTP listening on 10.0.2.15:80
```

Use `make run-gui` to see the VGA output in a QEMU window as well. This requires
a graphical desktop and a QEMU display backend (on Ubuntu, install `qemu-system-gui`
if needed). Both modes use software emulation, so KVM access is unnecessary.

## Web server

Start the kernel with `make run`, then open **http://127.0.0.1:8080/** in your
browser. QEMU forwards this localhost port to guest TCP port 80. The
first connection after boot can take several seconds while QEMU resolves the
guest's network address.
From another terminal:

```sh
curl http://127.0.0.1:8080/
curl http://127.0.0.1:8080/healthz
curl -I http://127.0.0.1:8080/
```

The HTTP parser and home page live in `build/webserver.elf`, a separate Rust
userspace executable embedded in the boot image. `/healthz` returns `ok` followed
by a newline. Both routes support GET and HEAD, including query strings. Unknown
paths return 404, unsupported methods return 405, malformed requests return
400, and headers larger than 2048 bytes return 431.

The server accepts HTTP/1.0 and HTTP/1.1, includes Content-Length in responses,
and closes each connection after one response. HTTP/1.1 requires a Host header.
It has four connection slots with fixed buffers and no heap allocation. Partial
requests have an absolute 5-second deadline; stalled sends or closes time out
after 10 seconds. The kernel also applies connection admission and lifetime
limits described below. Request bodies, chunked transfer, persistent
connections, and TLS are not supported.

Use `make run HTTP_PORT=8081` to change the host port. The existing TCP echo
service remains available on localhost port 5555 independently of HTTP.

## Userspace and privilege boundary

The web server runs at x86 privilege level 3. It starts through `iretq` with its
own registers and 64 KiB stack. The kernel loads its ELF segments into a 2 MiB
virtual window at `0x40000000`, backed by separate physical RAM. Only the
program's pages are user accessible: code is RX, constants are read-only and NX,
data and stack are RW and NX, and a guard page below the stack is unmapped.
Kernel memory, page tables, trap stacks, NIC DMA buffers, and MMIO stay
supervisor-only. Kernel text is RX, constants are read-only and NX, and kernel
data, stacks, page tables, DMA buffers, and the physical user-memory backing are
RW and NX. The null page and guard pages below the boot, trap, and double-fault
stacks are unmapped. NX and CR0.WP enforce these permissions even for ring-0
code. SMEP and SMAP are enabled when the CPU supports them; `-cpu max` in QEMU
exercises both protections. The default QEMU CPU may report them as unavailable.

A DPL-3 `int 0x80` gate transfers control onto the TSS kernel stack. The kernel
validates each buffer's full range and page permissions, then copies bytes
through a supervisor mapping. The server cannot directly access the NIC or
smoltcp buffers. Its four socket handles are restricted to listening on port 80.
The shared ABI in `abi.rs` uses RAX for the call number/result and RDI, RSI, RDX
for arguments; failures return negative error numbers.

| Number | Call | Arguments / result |
| --- | --- | --- |
| 0 | Poll | Progress network timers, one incoming packet, and outgoing traffic |
| 1 | Clock | Milliseconds since HPET initialization |
| 2 | Socket state | Handle; returns state, readiness flags, and queued TX bytes |
| 3 / 4 | Receive / send | Handle, user buffer, length; returns byte count |
| 5 / 6 | Close / abort | Handle |
| 7 | Listen | Handle, port (80 only) |
| 8 | Log | User UTF-8 buffer, length (at most 512 bytes) |
| 9 | Exit | Exit code |

There is **one user process on one CPU**, with no userspace threads. The PIT
interrupts at 100 Hz and can preempt a user program that never calls Poll.
Userspace runs with IF set and IOPL zero; it cannot disable interrupts. The
kernel keeps IF clear while handling traps, system calls, and network state.
Between network polls, the scheduler returns to network work after 64 completed
system calls or when its 10-millisecond slice budget has elapsed, checked after
each call. This budget also prevents a loop of short system calls from starving
the NIC; kernel operations themselves are not preempted.

A user fault or exit stops the web process and aborts its sockets while the
kernel continues servicing TCP echo. There is no general process launcher,
filesystem, POSIX interface, or memory allocator. The embedded ELF is loaded
automatically at boot; timer preemption does not add multiple processes.

`make test-userspace` checks real ring-0 write-protection and NX faults, then
runs thirteen ring-3 probes: actual CPL, invalid syscalls and buffers, forbidden
kernel reads/writes, MMIO and port I/O, code write protection, NX stack
execution, stack guard, privileged instructions, direction flags, a
noncanonical stack pointer, and preemption of a busy loop. Each fault must
return safely to the kernel before the next probe starts. The test runs with
the default QEMU CPU and `-cpu max`, requiring its success message and debug-exit
33. `make test-preemption` separately checks TCP echo progress during a pure
user busy loop and a loop that makes system calls without yielding.

## Networking

`make run` attaches a QEMU **e1000 / Intel 82540EM** NIC (`8086:100e`) and uses
QEMU's user-mode network backend. No TAP interface or root permissions are
needed. The guest has a static IPv4 address of **10.0.2.15/24**, gateway
**10.0.2.2**, and a **1500-byte IP MTU**. DHCP is not used.

TCP port **1234** echoes every byte it receives. QEMU forwards
**127.0.0.1:5555** on the host to that guest port. With the kernel running,
try this from a second terminal:

```sh
python3 - <<'PYTHON'
import socket

with socket.create_connection(("127.0.0.1", 5555), timeout=5) as client:
    client.sendall(b"hello from the host\n")
    client.shutdown(socket.SHUT_WR)
    print(client.makefile("rb").read().decode(), end="")
PYTHON
```

The reply is `hello from the host`. This port provides the binary TCP echo service.
The service handles one client at a time, preserves bytes under backpressure,
flushes pending echoes after a peer half-close, and accepts a new connection
after close or reset. TCP retransmission, sequencing, checksums, and flow
control are handled by smoltcp; socket buffers are fixed at 16 KiB each.

Use `make run HOST_PORT=5556` if port 5555 is occupied, and connect to that port
instead. `QEMU_NET` can replace the complete NIC/backend arguments; for example,
`make run QEMU_NET="-nic none"` boots without networking and reports the missing
NIC. The supported model is `e1000`, not `e1000e`.

ARP and IPv4 ICMP echo replies are supported. QEMU user-mode networking does
not make the guest directly reachable by host `ping 10.0.2.15`; `make test-packets`
checks ARP and ICMP by sending Ethernet frames directly through a QEMU socket
backend. IPv6, UDP sockets, DHCP, DNS, VLANs, jumbo frames, and IPv4 fragment
reassembly are not enabled.

The kernel applies admission limits to new HTTP connections on port 80:

| Limit | Value |
| --- | --- |
| Active connections from one source IPv4 address | 3 |
| Active HTTP connections in total | 4 |
| New SYN allowance per source | Burst of 32, refilling at 16 per second |
| New SYN allowance across all sources | Burst of 64, refilling at 32 per second |
| Source tracking table | 32 entries; inactive entries expire after 30 idle seconds |
| Half-open handshake lifetime | 3 seconds |
| Total connection lifetime | 15 seconds |

Validated SYN retransmissions for an existing connection do not consume another
admission token. Established traffic and the TCP echo service do not spend these
HTTP admission tokens. Invalid IPv4/TCP checksums are rejected before admission.
The source limit leaves one slot available to another source when one address
holds three connections. These fixed limits reduce simple slot exhaustion;
they do not guarantee availability against distributed clients, spoofed sources,
or link saturation. Clients sharing a source address also share its quota.

## Commands

| Command | Result |
| --- | --- |
| `make` or `make build` | Build `build/kernel.bin`, kernel ELF, and `build/webserver.elf` |
| `make run` | Build and boot with a terminal serial console |
| `make run-gui` | Build and boot with a VGA window and serial console |
| `make test` | Run boot, isolation, preemption, admission-control, TCP, ARP/ICMP, and HTTP checks |
| `make test-net` | Exercise TCP echo through QEMU e1000 and host forwarding |
| `make test-packets` | Exercise ARP, ICMP, and checksum rejection with Ethernet frames |
| `make test-boot` | Run the original CPU/memory boot checks without a NIC |
| `make test-userspace` | Verify kernel WP/NX, user isolation, and timer preemption on two CPU models |
| `make test-preemption` | Verify TCP progress during busy and syscall-only user loops |
| `make test-host` | Run admission-control and TCP dispatch regression tests on the host |
| `make test-abuse` | Check per-source quotas, half-open expiry, and recovery in QEMU |
| `make test-http` | Exercise HTTP routes, framing, errors, concurrency, and timeouts |
| `make fuzz` | Run local HTTP, TCP, and syscall mutation campaigns |
| `make fuzz-http` / `make fuzz-tcp` | Mutate HTTP requests or raw TCP/IP frames in a private QEMU network |
| `make fuzz-syscalls` | Exercise seeded syscall arguments from the real ring-3 process |
| `make check` | Check formatting and Clippy lints |
| `make debug` | Start QEMU paused with GDB listening on `127.0.0.1:1234` |
| `make clean` | Remove generated files |

`make test` uses Python 3.10+. TCP/packet tests have a 30-second overall timeout;
the HTTP test has a 45-second timeout, and the preemption test has a 25-second
deadline. Tests use temporary localhost ports and terminate their QEMU process
on completion or failure. The TCP test verifies a 320 KiB fragmented binary
transfer, descriptor and socket buffer wrapping, FIN/EOF, repeated connections,
an empty stream, and
reset recovery. The packet test checks an ARP response, 130 ICMP echo replies
with varied payload sizes, and rejection of bad IPv4/ICMP checksums. The HTTP
test checks GET/HEAD responses, fragmented requests, error handling, repeated
and concurrent clients, resets, and request-timeout recovery.

The separate boot test has a 15-second timeout and checks the Multiboot handoff,
BSS zero initialization, initialized data, paging, PAE, and active long mode.
It requires both `Boot checks passed.` and QEMU debug-exit status 33. Its
`smoke-test` feature skips networking; its artifacts are isolated from the normal
kernel used by the network tests.

For formatting/linting, install the optional Rust tools if needed:

```sh
rustup component add rustfmt clippy
make check
```

Tools can be overridden, for example `make run QEMU=/path/to/qemu-system-x86_64`.
Append QEMU options with `QEMU_FLAGS`, for example
`make run QEMU_FLAGS="-d guest_errors -D build/qemu.log"`.

For debugging, run `make debug`, then in another terminal:

```sh
gdb target/x86_64-unknown-none/release/kernel
(gdb) target remote 127.0.0.1:1234
(gdb) hbreak kernel_main
(gdb) continue
```

The separate user symbols are in `build/webserver.elf` (also copied alongside
the kernel ELF). In GDB, `add-symbol-file build/webserver.elf` loads its fixed
virtual addresses; `hbreak _start` breaks at user entry.

Use a GDB build with x86-64 support (`gdb-multiarch` on non-x86 hosts).

## Local fuzz campaigns

The fuzz scripts start their own QEMU instance. Network mutations go only to
that child's private Ethernet socket backend; there is no remote-target option.
HTTP cases mutate requests and split them across TCP segments. TCP cases mutate
flags, options, sequence numbers, payloads, checksums, truncation, and fragment
fields, including cases with established connections. Periodic HTTP and binary
echo checks look for service failures after malformed input. The syscall
campaign runs inside ring 3, varying call numbers, handles, pointers, lengths,
and socket operations while checking results and buffer canaries.

These are seeded, mutation-based robustness tests, not coverage-guided fuzzing.
A successful campaign reports only the cases exercised; it is not a security
proof. `make test` does not run the longer fuzz campaigns.

| Make variable | Default | Applies to |
| --- | --- | --- |
| `FUZZ_SECONDS` | `30` | Target duration of each HTTP/TCP campaign |
| `FUZZ_SEED` | `1` | Input generation for all campaigns |
| `FUZZ_ITERATIONS` | `100000` | Number of syscall test cases |
| `FUZZ_TIMEOUT` | `120` | Syscall QEMU run timeout in seconds |

For example:

```sh
make fuzz
make fuzz FUZZ_SECONDS=60 FUZZ_SEED=42 FUZZ_ITERATIONS=1000000 FUZZ_TIMEOUT=120
```

Each campaign saves artifacts below `build/fuzz/`. Network runs include
`serial.log`, `stderr.log`, an input-frame trace in `frames.jsonl`, and
`summary.json` with the seed, case count, result, and `replay_cases`. HTTP runs
also preserve the latest request; failures save the last frame and failure
message. Syscall runs save serial/stderr logs and a summary; the serial log
records the compiled seed, iteration count, and any failing case.

Replay network input generation with the mode, seed, and `replay_cases` from
the saved summary. For example, to run exactly 100 HTTP cases:

```sh
python3 scripts/fuzz_network.py qemu-system-x86_64 build/kernel.bin \
  --mode http --seed 42 --cases 100
```

Use `--mode tcp` for TCP cases. Timing and guest responses can differ between
runs; the frame trace preserves what was actually sent. Replay a syscall
campaign by rebuilding with the same seed and iteration count:

```sh
make fuzz-syscalls FUZZ_SEED=42 FUZZ_ITERATIONS=1000000 FUZZ_TIMEOUT=120
```

## Boot and source layout

QEMU loads `build/kernel.bin` using the Multiboot v1 address header. The image
is linked at physical address 1 MiB. The bootstrap clears BSS, creates a 256 KiB
stack, maps the first 4 GiB with 2 MiB pages, and switches from 32-bit protected
mode to 64-bit long mode before calling Rust. The first 1 GiB remains cached;
1–4 GiB is initially uncached for PCI MMIO and the HPET timer. After installing
the GDT, TSS, and IDT, the kernel splits its own mapping into 4 KiB pages with
section-specific permissions, removes null/stack guard pages, and marks all
remaining supervisor mappings NX. Before entering userspace, the first 2 MiB
at virtual 1 GiB is replaced with cached, permissioned 4 KiB user pages; their
physical backing remains supervisor-only RW/NX RAM below 1 GiB.

| File | Purpose |
| --- | --- |
| `src/boot.S` | Multiboot header, page tables, stack, and long-mode transition |
| `src/main.rs` | Rust entry point, boot information, checks, and panic handler |
| `src/console.rs` | VGA text and polled serial output |
| `src/pci.rs` | PCI discovery and command-register setup |
| `src/e1000.rs` | Intel 82540EM MMIO and DMA receive/transmit rings |
| `src/time.rs` | Polled HPET monotonic clock for TCP timers |
| `src/timer.rs` | PIC/PIT setup and 100 Hz preemption ticks |
| `src/memory.rs` | Kernel page permissions, stack guards, and page-table audits |
| `src/abuse.rs` | HTTP SYN quotas, source tracking, and connection expiry |
| `src/net.rs` | NIC/TCP polling, echo service, and preemptive userspace scheduling |
| `src/arch.rs`, `src/traps.S` | GDT/TSS/IDT, ring transitions, IRQ handling, and fault entry |
| `src/userspace.rs` | ELF loading, protected pages, stack, and checked buffer copies |
| `src/syscall.rs`, `abi.rs` | Kernel socket system calls and the shared ABI |
| `userspace/main.rs`, `userspace/syscall.rs` | Ring-3 entry, event loop, and syscall wrappers |
| `userspace/http.rs` | Userspace HTTP parser, embedded page, and connection state |
| `userspace/linker.ld` | Separate user ELF layout at virtual address 1 GiB |
| `src/user_test.rs`, `scripts/userspace_test.py` | Kernel protection and ring-3 isolation tests |
| `scripts/preemption_test.py` | Network progress while userspace does not yield |
| `tests/host`, `scripts/abuse_test.py` | Admission-control and recovery tests |
| `scripts/fuzz_network.py` | Seeded HTTP/TCP mutation campaigns and artifacts |
| `userspace/fuzz.rs`, `scripts/fuzz_syscalls.py` | Ring-3 syscall campaigns and logs |
| `linker.ld` | Physical memory layout and bootstrap symbols |
| `.cargo/config.toml` | Bare-metal Rust target and static linking flags |
| `scripts/smoke_test.py` | Bounded QEMU boot test |
| `scripts/network_test.py` | End-to-end TCP integration test |
| `scripts/packet_test.py` | Raw Ethernet ARP/ICMP integration test |
| `scripts/http_test.py` | HTTP integration test over real QEMU TCP connections |
| `Makefile` | Build, run, test, and debug commands |

The ELF is converted to a flat Multiboot image with `objcopy`; it is not a disk
image or ISO. QEMU's `-kernel` loader performs the bootloader handoff, so GRUB,
an ISO builder, and a nightly Rust toolchain are unnecessary.

This is a starting kernel with one preemptible user process. It has no general
multi-process scheduler, heap allocator, filesystem, or keyboard input. The
kernel still uses a broad supervisor identity map, now with explicit page
permissions. The boot target is QEMU's legacy PC machine with its HPET at the
standard fixed address. The e1000 uses 64 receive and transmit descriptors with
static DMA buffers and software checksums. Networking is polled continuously,
so an idle guest uses CPU time; only the PIT supplies scheduling interrupts.
There is no ACPI discovery or UEFI boot path. The TCP sequence seed uses boot
timing and is not a cryptographic entropy source. Four HTTP slots, fixed quotas,
and fuzz campaigns do not make this a production-hardened network service; TLS
and stronger denial-of-service defenses are not implemented.

References: [Rust bare-metal target](https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html),
[Multiboot specification](https://www.gnu.org/software/grub/manual/multiboot/multiboot.html),
[QEMU options](https://www.qemu.org/docs/master/system/invocation.html),
[QEMU networking](https://www.qemu.org/docs/master/system/devices/net.html),
[Intel system programming manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
[Intel 8254x manual](https://www.intel.com/content/dam/doc/manual/pci-pci-x-family-gbe-controllers-software-dev-manual.pdf).

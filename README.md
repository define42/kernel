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
requests time out after 5 seconds; stalled sends or closes time out after
10 seconds. Request bodies, chunked transfer, persistent connections, and TLS
are not supported.

Use `make run HTTP_PORT=8081` to change the host port. The existing TCP echo
service remains available on localhost port 5555 independently of HTTP.

## Userspace and privilege boundary

The web server runs at x86 privilege level 3. It starts through `iretq` with its
own registers and 64 KiB stack. The kernel loads its ELF segments into a 2 MiB
virtual window at `0x40000000`, backed by separate physical RAM. Only the
program's pages are user accessible: code is RX, constants are read-only and NX,
data and stack are RW and NX, and a guard page below the stack is unmapped.
Kernel memory, page tables, trap stacks, NIC DMA buffers, and MMIO stay
supervisor-only. NX and CR0.WP are enabled.

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

This is **one cooperatively scheduled process**, with one CPU and no threads.
The server yields through Poll; it is not preempted by a timer. A user fault or
exit stops the web process and aborts its sockets while the kernel continues
servicing TCP echo. Code that never yields can still monopolize the CPU.
There is no general process launcher, filesystem, POSIX interface, or memory
allocator. The embedded ELF is loaded automatically at boot.

`make test-userspace` runs twelve ring-3 probes: actual CPL, invalid syscalls and
buffers, forbidden kernel reads/writes, MMIO and port I/O, code write protection,
NX stack execution, stack guard, privileged instructions, direction flags, and a
noncanonical stack pointer. Each fault must return safely to the kernel before
the next probe starts. The test requires the success message and debug-exit 33.

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

## Commands

| Command | Result |
| --- | --- |
| `make` or `make build` | Build `build/kernel.bin`, kernel ELF, and `build/webserver.elf` |
| `make run` | Build and boot with a terminal serial console |
| `make run-gui` | Build and boot with a VGA window and serial console |
| `make test` | Run CPU boot, ring-3 isolation, TCP, ARP/ICMP, and HTTP checks |
| `make test-net` | Exercise TCP echo through QEMU e1000 and host forwarding |
| `make test-packets` | Exercise ARP, ICMP, and checksum rejection with Ethernet frames |
| `make test-boot` | Run the original CPU/memory boot checks without a NIC |
| `make test-userspace` | Verify user privilege, buffer checks, and fault containment |
| `make test-http` | Exercise HTTP routes, framing, errors, concurrency, and timeouts |
| `make check` | Check formatting and Clippy lints |
| `make debug` | Start QEMU paused with GDB listening on `127.0.0.1:1234` |
| `make clean` | Remove generated files |

`make test` uses Python 3.10+. TCP/packet tests have a 30-second overall timeout;
the HTTP test has a 45-second timeout. Tests use temporary localhost ports and
terminate their QEMU process on completion or failure. The TCP test verifies a 320 KiB fragmented binary transfer, descriptor
and socket buffer wrapping, FIN/EOF, repeated connections, an empty stream, and
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

## Boot and source layout

QEMU loads `build/kernel.bin` using the Multiboot v1 address header. The image
is linked at physical address 1 MiB. The bootstrap clears BSS, creates a 256 KiB
stack, maps the first 4 GiB with 2 MiB pages, and switches from 32-bit protected
mode to 64-bit long mode before calling Rust. The first 1 GiB remains cached;
1–4 GiB is initially uncached for PCI MMIO and the HPET timer. Before entering
userspace, the first 2 MiB at virtual 1 GiB is replaced with cached, permissioned
4 KiB user pages; their physical backing remains in kernel RAM below 1 GiB.

| File | Purpose |
| --- | --- |
| `src/boot.S` | Multiboot header, page tables, stack, and long-mode transition |
| `src/main.rs` | Rust entry point, boot information, checks, and panic handler |
| `src/console.rs` | VGA text and polled serial output |
| `src/pci.rs` | PCI discovery and command-register setup |
| `src/e1000.rs` | Intel 82540EM MMIO and DMA receive/transmit rings |
| `src/time.rs` | Polled HPET monotonic clock for TCP timers |
| `src/net.rs` | NIC/TCP polling, echo service, and cooperative userspace execution |
| `src/arch.rs`, `src/traps.S` | GDT/TSS/IDT, ring transitions, and fault entry |
| `src/userspace.rs` | ELF loading, protected pages, stack, and checked buffer copies |
| `src/syscall.rs`, `abi.rs` | Kernel socket system calls and the shared ABI |
| `userspace/main.rs`, `userspace/syscall.rs` | Ring-3 entry, event loop, and syscall wrappers |
| `userspace/http.rs` | Userspace HTTP parser, embedded page, and connection state |
| `userspace/linker.ld` | Separate user ELF layout at virtual address 1 GiB |
| `src/user_test.rs`, `scripts/userspace_test.py` | Ring-3 isolation tests |
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

This is a starting kernel: external interrupts stay disabled, and execution is
cooperative. There is no preemptive scheduler, heap allocator, filesystem, or
keyboard input. The user process is isolated from the supervisor mapping; the
kernel itself still uses a broad identity map. The boot target is QEMU's
legacy PC machine with its HPET at the standard fixed address. The e1000 uses
64 receive and transmit descriptors with static DMA buffers and software
checksums. Networking is polled continuously, so an idle guest uses CPU time.
There is no interrupt-driven scheduling, ACPI discovery, or UEFI boot path.
The TCP sequence seed uses boot timing and is not a cryptographic entropy source.

References: [Rust bare-metal target](https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html),
[Multiboot specification](https://www.gnu.org/software/grub/manual/multiboot/multiboot.html),
[QEMU options](https://www.qemu.org/docs/master/system/invocation.html),
[QEMU networking](https://www.qemu.org/docs/master/system/devices/net.html),
[Intel system programming manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
[Intel 8254x manual](https://www.intel.com/content/dam/doc/manual/pci-pci-x-family-gbe-controllers-software-dev-manual.pdf).

# Validation record — 2026-10-27

Status: experimental Intel/UEFI port; generic hardware support and public
production qualification remain incomplete. The initial results below describe the hardware-port snapshot before the
serial-console additions; later checks are recorded separately below. None is a
signed release or an independent audit.

Toolchain: rustc 1.95.0 (59807616e, 2026-04-14), QEMU 8.2.2, OVMF and GRUB
x86_64 EFI. No physical hardware was used.

## Passed checks

- `make check`: formatting and strict Clippy, including normal, hardware,
  hardware/privilege-test, isolation, fuzz and service builds.
- `make test`: both legacy privilege CPU models, kernel WP/NX, preemption
  fairness, 23 host tests, abuse controls, TCP binary echo/close/reset,
  ARP/ICMP/checksum handling, HTTP behavior and service/DMA/IPC recovery.
- `make test-firmware`: UEFI/GRUB/Multiboot2 smoke handoff.
- `make test-hardware-refusal`: the full hardware image validates its memory
  map, ACPI/HPET and xAPIC in OVMF, then rejects emulated NIC assignment.
- `make test-apic`: actual ring-3 preemption and the malformed user-stack
  spurious-interrupt return regression.
- `make test-deployment`: HTTP on 10.77.0.15/24 with echo disabled; removal of
  RDSEED/RDRAND prevents network startup.
- `make test-interrupt-remapping`: nonpresent IRTE fault, DMA faults against
  the relocated kernel RX image page, and recovery. QEMU compatibility-format
  interrupt blocking remains unverified and is known incomplete in this model.
- Python compilation and `git diff --check`.
- Normal and hardware kernel symbol checks: no ring-0 smoltcp/e1000 code or
  kernel test-probe symbols.

An OVMF reserved-memory collision at 8–9 MiB was found by the full-image test.
The fixed load base is now 16 MiB; complete resident-range validation remains
mandatory. This fixes that observed collision, not arbitrary firmware layouts.

## Mutation runs

Seed 43, final default kernel:

| Campaign | Work | Elapsed | Result |
| --- | --- | --- | --- |
| HTTP | 54 cases | 62.014 s | Pass |
| TCP/IP | 1,070 cases | 61.393 s | Pass |
| Syscalls | 1,000,002 calls; 2,261 preemptions | 74.180 s | Pass |

Artifacts remain under `build/fuzz/http-43-1793084716771333995`,
`build/fuzz/tcp-43-1793084715440416206`, and
`build/fuzz/syscalls-1793084718207839194`. These short, seeded mutation runs are
regressions; they are not sustained production qualification or coverage-guided
security fuzzing.

## Dependency audit

cargo-audit 0.22.2 reported zero known vulnerabilities and no warnings for all
three lockfiles. RustSec database revision:
`3279c99911354c400e1d41e47c7d60e39258b147`, updated 2026-10-26.
Reports: `build/audit-kernel.json`, `build/audit-services.json`,
`build/audit-host.json`. This only checks published dependency advisories.

## Initial artifact identity

| Artifact | SHA-256 |
| --- | --- |
| `build/kernel.bin` | `e9f94e61b87d5629917c8c5ab3baecb33a4c5c5f1ad4f77d2ef4e02bc7b65803` |
| `build/baremetal/kernel.bin` | `6d2385acb1658ffe589822913412d39685f76d1e768397e7a20c470150db7ce4` |
| `build/baremetal/kernel.iso` | `820d7e6017c913244ebe9a3fbef072377372e4b0cb10a063a1296826da05182d` |

The hardware example uses 192.168.50.10/24, gateway 192.168.50.1 and no echo
listener. ISO hashes may change on rebuild because packaging includes metadata.
Read [hardware limits](HARDWARE.md) and [security requirements](../SECURITY.md)
before interpreting any of these results as deployment evidence.


## Serial NIC configuration follow-up — 2026-10-27

The serial console and runtime NIC configuration changed the kernel and service
images after the initial snapshot above; those hashes and seed-43 campaign
results do not identify the latest binaries.

Passed after runtime configuration was added:

- `make check` and every `make test` component, including the expanded host and
  serial tests (components were run separately).
- Live changes from 10.0.2.15 to 10.0.2.16 with HTTP on the new address and no
  response on the old address; echo disable/enable; gateway removal/restoration;
  down/configure/up; invalid settings preserving the running configuration.
- Serial input/edit/reconnect checks with 45 concurrent HTTP health requests;
  NIC commands remain refused after missing-IOMMU startup failure.
- NETWORK-only configuration getter, invalid output-buffer/size/reserved-field
  rejection, and existing process/DMA recovery checks.
- `make test-deployment`: custom compiled defaults still take effect, and missing
  CPU entropy still refuses networking.
- `make test-hardware-refusal`: rebuilt UEFI image validates firmware/APIC,
  refuses emulated device assignment, and reaches the serial console.
- Seed 47 syscall campaign: 100,002 calls, 218 preemptions, passed. Artifacts:
  `build/fuzz/syscalls-1793126933005127467`.

These are emulator/host regressions. Runtime NIC configuration has not been
validated on physical hardware; settings are volatile and serial administration
is unauthenticated.


## Multiple NIC selection follow-up — 2026-10-27

The kernel now inventories up to eight eligible e1000 adapters, with one active
adapter at a time. The console selects an adapter and preserves each adapter's
volatile IP, gateway and echo settings. This changes the binaries again; the
initial hashes above remain historical.

Passed after selection was added:

- `make check`, expanded host tests, boot and both userspace CPU variants, and
  preemption checks.
- `make test-multi-nic`: separate PCI/MAC identities, invalid selections leaving
  the current adapter unchanged, selection while stopped, live switching,
  repeated switching with saved settings, HTTP/echo on the selected adapter
  only, and continued refusal without an IOMMU.
- `make test-multi-nic-guards`: nine eligible NICs cause startup refusal before
  services start, with all nine PCI bus-master bits clear. With one root NIC and
  one bridged NIC, only the root NIC is selectable and the bridged NIC's
  bus-master bit remains clear. Reads use QMP-paused guests and private qtest
  sockets; these NICs have no host network backend.
- `make test-serial`: live settings, reconnects and 46 concurrent HTTP health
  checks.
- Service isolation and interrupt-remapping tests: old driver MMIO and DMA
  virtual addresses fault at CPL3 after revocation, followed by successful
  reconfiguration and existing process/DMA/IPC fault recovery.
- TCP, ARP/ICMP/checksum, HTTP, deployment/defaults/entropy refusal and rebuilt
  UEFI hardware-refusal checks. All default `make test` components were run
  individually.

The first connection-abuse regression failed during half-open setup. Its packet
trace showed a SYN immediately following client resets; the fixture transmitted
that SYN only once, allowing listener rearming and ARP timing to lose the reply.
The client now retransmits the identical SYN within the original two-second
deadline and validates the SYN-ACK without completing the half-open handshake.
The source-quota rejection and 3.3-second expiration checks are unchanged. Two
subsequent `make test-abuse` runs passed; traces confirmed retransmissions and
no final ACKs from the half-open clients:

- `build/test-artifacts/abuse-42-1793128364049555848`
- `build/test-artifacts/abuse-42-1793128412429589446`

No physical machine was tested. This adds adapter selection, not simultaneous
networking across interfaces or generic Intel hardware qualification. Prior
fuzzing and dependency-audit records above were not rerun for this follow-up.


## Simultaneous NIC follow-up — 2026-10-27

This supersedes the single-active-adapter behavior in the preceding follow-up.
Up to eight eligible NICs now run concurrently, each with three private processes,
its own IPC/socket state, immutable VT-d domain, translation pages and pinned DMA
pool. Console selection changes the configuration target only.

Passed checks:

- `make check`; boot, host and both userspace CPU variants; all 20 serial-console
  host tests. The normal image reserves 24 process slots with 48 MiB of private
  backing. The resident image fits the default 128 MiB guest and expanded kernel
  page-protection tables.
- `make test-multi-nic`: concurrent HTTP and held TCP echo streams on both NICs.
  Focus changes preserve both connections. Reconfiguring/stopping/restarting
  eth1 preserves eth0's original connection and 122 HTTP checks.
- `make test-multi-nic-guards`: eight interfaces have bus mastering enabled;
  eth7 down/up changes only its own PCI command bit. Nine interfaces cause
  startup refusal with every BME bit clear; bridged peers remain excluded.
- `make test-serial`: input/edit/reconnect, live configuration, isolation refusal
  and 45 concurrent HTTP health checks.
- `make test-multi-nic-isolation`: actual CPL3 peer-memory access faults and a
  real DMA write to the peer's IOVA window rejected by VT-d. The peer's original
  TCP connection and HTTP service survive 126 rounds while eth0 faults/restarts.
- `make test-multi-nic-shared-failure`: the same cross-interface checks with 122
  peer traffic rounds, followed by a synthetic shared-unit failure. Both PCI
  BME bits are clear and console up/set commands cannot bypass quarantine.
  This exercises the shared-failure latch, not an actual hardware timeout.
- `make test-services`: single-interface CPU/DMA/IPC recovery, 151/155 echo
  exchanges including three after the final fault, plus missing-IOMMU and
  unsupported-APIC refusal.
- Preemption, connection-abuse, TCP/packet/HTTP, deployment/defaults/entropy
  refusal and rebuilt UEFI hardware-refusal regressions.
- `make test-interrupt-remapping`: two active interfaces followed by a real
  nonpresent IRTE fault with unknown requester ID; both NICs quarantined with
  BME clear, HTTP/echo silent and console restart refused. The original fault
  record remains present. No unknown-source exception was introduced.
- Seed 53 syscall mutation regression: 100,002 calls, 232 preemptions, passed.
  Artifacts: `build/fuzz/syscalls-1793129986991735807`.

The first simultaneous boot found a user-driver check that accepted only the
original IOVA. It now validates the bounded, aligned per-interface range using
shared ABI constants; subsequent two- and eight-NIC tests passed.

The previous interrupt-remapping recovery fixture exposed an intentional policy
change: paused qtest inspection showed FSTS `0x2` (pending primary fault, without
overflow) and FRCD high `0x800000220000ffff` (nonpresent IRTE reason `0x22`, unknown
requester `0xffff`). QEMU's DMA-generated interrupt lacks source attribution.
The shared quarantine is required; no unknown-requester exception was added.
The updated interrupt test verifies the real denial, preserved fault record,
all-NIC DMA shutdown and refusal to restart through the console.

These are local emulator and host checks. No physical hardware, sustained network
fuzz campaign, fresh dependency audit or public-production qualification was
performed in this follow-up. The earlier artifact hashes identify older images.

All default `make test` components were run individually, plus the separate
shared-failure, interrupt-remapping, deployment and hardware-refusal targets.
Final Python compilation, Rust formatting and whitespace checks passed.

| Current artifact | SHA-256 |
| --- | --- |
| `build/kernel.bin` | `525c91a7ad3b57359a3e67dcb1bd8439e8647cd829b448a6ff1dbe5bb6b49074` |
| `build/baremetal/kernel.bin` | `1bf8103eea9ce4806e61e82b6c878df59be379ac5a5f75e6bc331ba7b8fa8a25` |
| `build/baremetal/kernel.iso` | `f42229416e12538bda7756503cc206b335c4107a91d8fcfc59465e04116535fa` |

The normal image uses 10.0.2.15/24 with gateway 10.0.2.2 and echo enabled.
The hardware image uses 192.168.50.10/24, gateway 192.168.50.1 and echo disabled.
These hashes identify tested local artifacts; they are not a signed release.


## Serial JSON setup follow-up — 2026-10-27

Added bounded serial `setup {"system":[...]}` and `setup show` for per-interface
IPv4/prefix, gateway, echo and enabled state. Every entry is validated before
changes begin; omitted fields retain each interface's current values. Unchanged
interfaces keep their connections. Settings remain volatile until reboot.

Passed: `make kernel test-host`, `make check`, `make test-setup`,
`make test-serial`, `make test-multi-nic`, `make test-multi-nic-shared-failure`,
`make test-interrupt-remapping`, and `make test-hardware-refusal`.
Python compilation, Rust test formatting and whitespace checks also passed.

The setup test rejected 16 invalid batches and overlong input without resetting
either original TCP stream. Export replay was a no-op; changing eth1 preserved
eth0's held connection and 189 HTTP checks. Batch updates changed both addresses.
Serial and simultaneous-NIC regressions completed 285 and 120 HTTP checks.
Cross-NIC CPU/DMA fault recovery preserved 124 peer traffic rounds. Both synthetic
shared failures and real unknown-source interrupt faults prevented JSON restart
or configuration changes; saved settings remained unchanged, Enabled stayed false,
and both PCI BME bits stayed clear. The real fault record remained present.

The rebuilt UEFI image booted through firmware/APIC checks and retained its
required refusal of emulated assignment. No physical hardware, fresh sustained
fuzz campaign or dependency audit was tested in this follow-up. Teardown failures
retain old settings and quarantine affected interfaces; asynchronous startup can
still fail. These results do not establish atomic hardware rollback or public
production readiness. Earlier hashes identify older images.

| Artifact after JSON setup | SHA-256 |
| --- | --- |
| `build/kernel.bin` | `b8ac6510b87cc01d3f8487114b9d1cfe539c988ba020d55a3cf0a4b8cabd3cae` |
| `build/baremetal/kernel.bin` | `0f2af95c02bcd05200bc460f5d9115f49dc5e228563b18740eb4127cc5af7f64` |
| `build/baremetal/kernel.iso` | `db64928cdac7ef85d0b7514374e919b76eb3cf37a9a55f13c1b4b5deb6af0424` |


## MAC and PCI setup follow-up — 2026-10-27

Setup now accepts a validated MAC address and a PCI selector. Interface and PCI
selectors must resolve to the same existing assignment when supplied together;
configuration cannot rebind devices. Omitted MACs retain each interface's address
across down/up and recovery. Both driver filtering and the userspace stack receive
the configured address. Bounded userspace ARP announcements refresh neighbor caches.

Passed `make kernel test-host check`: 46 serial/parser/config/log-queue tests,
eight batch-preflight tests, five announcement format/retry tests and the existing
host suites. The first QEMU integration run found driver logs interleaving with
JSON export. Fixed serial arbitration now keeps responses intact, uses bounded
log storage and yields to input under continuous logging; regression tests cover
backpressure, overflow, unterminated logs and eight-interface snapshots.

Passed emulator checks:

- `make test-setup`: 30 invalid batches and overflow rejected without resetting
  either held stream. PCI selection, partial updates, MAC-only changes at an
  unchanged IP, export replay, existing nic commands and stopped MAC swaps passed.
  Eth0's original TCP stream survived 306 HTTP checks while eth1 changed.
- Packet capture verified both configured MACs in ARP and bidirectional HTTP.
  MAC 52:54:00:ab:cd:67 had 3 ARP frames (2 announcements), 5 HTTP response frames
  and 7 request frames; :68 had 15 ARP frames (8 announcements across restarts),
  45 responses and 64 requests. No previous source MAC appeared after the change.
- `make test-multi-nic`: held TCP continuity and 102 peer HTTP checks.
- `make test-serial`: editing, overflow, reconnect, PCI and live configuration,
  plus 297 concurrent HTTP checks and missing-IOMMU refusal.
- Shared-failure and interrupt-remapping targets: cross-NIC CPU/DMA recovery with
  125 peer traffic rounds; both NICs remained quarantined with BME clear after
  shared faults. JSON containing MAC/PCI could not clear quarantine.
- Preemption: 100 echo sessions during a busy loop and 50 during syscall load.
- Syscall mutation regression, seed 53: 100,002 calls and 253 preemptions passed;
  final queued logs survived test exit. Artifacts:
  `build/fuzz/syscalls-1793132902553136505`.
- Rebuilt UEFI image/ISO passed firmware/APIC boot and emulated-assignment refusal.
  Python compilation, standalone Rust formatting and whitespace checks passed.

These are host and emulator results; no physical qualification, fresh sustained
network fuzz campaign or dependency audit was performed. ARP announcements are
best-effort cache refresh, not address conflict detection. Static neighbor entries
require administrator updates. Previous artifact hashes identify earlier builds.

| Artifact after MAC/PCI setup | SHA-256 |
| --- | --- |
| `build/kernel.bin` | `4f158968f5fc4be58a4d24ef9aa9fcafa72b75262017b426a47f9c80f1490ada` |
| `build/baremetal/kernel.bin` | `3951ba01b5abcc8602aa264e5bf882439dd7e2bafa79496c6c45b15f226e1284` |
| `build/baremetal/kernel.iso` | `6d9dd9c23e07fbd4a0af6b9e8675c5ca21bc3cbde2aa12a37c3ad5a75ee03dac` |


## Userspace heap follow-up — 2026-10-27

Added a private fixed 512 KiB RW/NX heap to every ring-3 process, using its
existing backing. ELF bounds reserve the lower guard; heap guards and the gap
before the stack remain unmapped. A userspace global allocator supports aligned
allocation, reuse/coalescing, zeroed allocation, and shrinking/growing/moving
reallocation. All three service entry points initialize it. The webserver's
bounded connection array and syscall-fuzz buffer now use `Box`.

Validated with stable rustc 1.95.0 (59807616e 2026-04-14):

- `make kernel`, `make test-host`, and `make check` passed, including all checked
  feature combinations and standalone userspace Clippy builds. The 13 allocator
  host tests cover exhaustion, full recovery, alignments through 64 KiB,
  fragmentation, canaries, zeroing, realloc preservation/failure, independent
  arenas, 30,000 seeded operations, and eight concurrent host workers. The focused
  allocator suite also passed in release mode.
- `make test-userspace` passed on both `qemu64` and `max`. Real CPL3 probes check
  `Box`/`Vec`/`String`, heap-backed syscall copies, alignment, zeroing, complete
  heap exhaustion/reuse, and rejected copies crossing guard boundaries. Both
  guard pages fault and heap execution faults with NX. An intentional 524,289-byte
  infallible allocation reaches the process panic handler and exits with code 1;
  repeating the allocation probe after restart succeeds with cleared memory.
- The first exhaustion probe exposed allocation-shim optimization: a raw
  `alloc::alloc` call used only for its null result was eliminated and assumed
  successful. That deterministic accounting assertion now calls `GlobalAlloc`
  directly; ordinary collection and fallible-reservation paths remain tested.
- `make test-http test-multi-nic` passed. Both NICs served HTTP and echo, and eth1
  reconfiguration/down/up preserved eth0's held stream through 105 HTTP checks.
- `make test-services test-multi-nic-isolation` passed. Heap checks audit every
  page, prove private physical backing, fault on peer physical aliases, verify
  checked copies, and fill/clear the entire arena on restart. Service recovery
  completed 172 of 175 echo exchanges across intentional faults; the peer NIC's
  held stream and HTTP survived 123 cross-NIC isolation/recovery rounds.
- `make test-preemption` passed with 100 echo sessions during a busy user loop
  and 50 during syscall load.
- `make fuzz-syscalls FUZZ_SEED=67 FUZZ_ITERATIONS=100000` passed with 100,002
  calls and 229 preemptions using the heap-backed mutation buffer. Artifacts:
  `build/fuzz/syscalls-1793134897893442761`.

These are host and emulator checks. No physical machine, new hardware image,
long-duration network fuzz campaign, or independent security audit was included
in this follow-up. The heap is bounded, can fragment, and does not provide a
kernel allocator, heap growth, Rust `std`, or an Actix/Axum runtime port.

| Artifact after userspace heap | SHA-256 |
| --- | --- |
| `build/kernel.bin` | `bdfb2a8714e6a750469bfac8e0f9c01e12ec46a33b04501df8346a004f181ae4` |
| `build/webserver.elf` | `d92414eb4058564b9ee17c14bd8d7b2278420dea3aed6d170a226306526f68a9` |
| `build/netd.elf` | `3b3ee7f1273fbf4a362673cb951de46078fb06e62d557ce17e6056b7237c68c5` |
| `build/nic-driver.elf` | `be8435e0494891f3d4c329d97bcbea514ce9ea846227d00a2dc752d4bfb33ef8` |


## Initial userspace Rust std port — 2026-10-27

Added a backend for the real upstream Rust standard library on the custom
`x86_64-unknown-kernel` target, with ordinary Rust `fn main()` startup in ring 3.
The repository-local compiler is pinned to `nightly-2026-04-15`, reporting
`rustc 1.97.0-nightly (a5c825cd8 2026-04-14)`. The kernel and existing services
continue to use stable rustc 1.95.0. Thirteen upstream dispatch files are hash
checked before patching and nine platform files are overlaid; the shared rustup
installation is not patched.

Validation performed:

- `make test-std check-std` passed. The normal QEMU `max` CPU run executes the
  real std binary in CPL3, checking `Vec`, `String`, `HashMap`, fallible allocation,
  direct `System` allocation, stdout/stderr, `Instant`, yielding sleep, const/lazy
  TLS, `Mutex`, `OnceLock`, and park-token consumption. Unsupported stdin,
  filesystem, TCP listener, child-process, and thread-creation operations report
  `Unsupported` through fallible APIs.
- Kernel WP/NX fault probes, RX code, every RW/NX heap page, both heap guards,
  bounded random/output syscall arguments, timer progress, and full heap clearing
  are checked. Intentional panic and 524,289-byte allocation failure exit with
  status 1; explicit exit preserves status 7. The complete ordinary program
  succeeds again after restart with cleared TLS and initialization state.
- The second `test-std` boot disables both RDRAND and RDSEED. Random-byte failure
  leaves the caller's sentinel buffer unchanged. HashMap seeding aborts rather
  than falling back to predictable keys, both before and after process restart.
- All three source-patch integrity tests passed. They check successful patching,
  source-hash mismatch, and preexisting overlays without partial mutation.
  `make -j2 setup-std std-demo` passed with serialized private-source preparation
  and compilation. Pristine backups and published ELF files use atomic renames.
- `make kernel test-host`, `make check`, and Python syntax checks passed. Host
  regressions include all 13 allocator tests and seven new strict serial-queue
  cases covering backpressure, CRLF capacity, invalid UTF-8/NUL, fragment
  boundaries, ring wrap, and interaction with legacy log truncation/overflow.
- `make test-userspace` passed on `qemu64` and `max`. `make test-http test-serial`
  passed, including 295 concurrent HTTP checks during serial administration,
  reconnects, live NIC reconfiguration, and refusal without an IOMMU.
- `make test-services` passed in the normal service architecture. Its web process
  now exercises positive and rejected random-byte/stdout calls, read-only and
  guard-crossing ranges, unchanged canaries, and preserved capability checks.
  Recovery completed 172 of 176 echo exchanges across intentional faults, with
  three successful exchanges after all containment checks. Missing-IOMMU and
  APIC-present development boots still refuse device assignment.

ELF inspection finds three load segments (RX, R, RW) and entry `0x40000000`;
loaded image memory ends at `0x40018000`, below the reserved heap guard. The
heap remains fixed at 512 KiB. The std regression image uses the separate legacy
userspace harness; it is not an Axum/Actix webserver or the normal VT-d service
image. Normal-service syscall handling is covered separately as described above.

No physical-machine test, long-duration network fuzz campaign, independent
security audit, or production qualification was performed for this port.
Sockets/filesystems, user threads, wall-clock time, and Tokio remain unsupported;
single-thread TLS/synchronization assumptions and omitted TLS destructors are
explicitly documented in `userspace/std-port/README.md`.

| Artifact after std port | SHA-256 |
| --- | --- |
| `build/std/std-demo.elf` | `c6c2c70bed69f32a616015f1cd6245c2cb0b90b5978343f06afb1c245b590e52` |
| `build/std-test/kernel.bin` | `7425317f9e3ca615b200377a6abcf001258ced09a847c5b03f48feebb80eb627` |

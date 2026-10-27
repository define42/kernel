# Security status

**Experimental; not approved for public production deployment.** The repository
contains useful isolation controls and automated tests. It has not undergone an
independent security audit or physical-platform qualification. A successful
build, clean dependency audit, or fuzz run is not a security certification.

## Threat boundary

Internet packets, HTTP clients, and each ring-3 service are untrusted. The kernel,
bootloader, firmware, CPU, IOMMU, PCI routing and hardware RNG are trusted. CPU
page permissions isolate service memory; checked IPC controls software access;
VT-d is intended to restrict NIC DMA and interrupt messages. A kernel or platform
bug can still compromise the whole machine. Physical side channels, malicious
firmware and hardware replacement are outside the implemented threat model.

The COM1 console is trusted administration. It has no login: anyone with serial
access can change IPv4 settings, reset connections, or stop networking. The QEMU
serial socket binds to localhost only. Console changes cannot override device
isolation refusal or clear quarantine, including by selecting another NIC or
applying a JSON `setup` batch. Setup uses a fixed schema and bounded, allocation-free
parser; it validates every requested interface and merged configuration before
changing any device. Invalid batches leave all settings unchanged. Hardware
teardown failures retain the previous settings and quarantine affected interfaces;
shared remapping failures still quarantine all interfaces. Configuration is volatile.
`PCI` selects only an already isolated, inventoried adapter; if `Interface` is also
provided, both identities must agree. It cannot rebind devices or change PCI
addresses. MAC changes are validated and applied through the existing stopped
service/restart path, and cannot change another interface's DMA assignment.
Up to eight eligible cards can operate concurrently. Selection changes the
console's configuration target; it does not redirect packets or stop other NICs.
Each interface has its own ring-3 driver, TCP/IP and web processes, private memory
and user stacks, bounded IPC queues, socket/admission state, and validated network
configuration. Services cannot select another interface through the syscall ABI.
Only its driver receives that interface's BAR and pinned DMA pool; each pool has
a distinct VT-d domain, translation tables and IOVA window. Administratively down
interfaces remain bus-master-disabled with absent DMA contexts.

An attributed NIC DMA fault stops and restarts only that interface's services;
its recovery preserves peer fault records. Fault overflow, an unknown requester,
or a shared remapping failure quarantines all interfaces. Failed invalidation or
protection checks latch the shared failure until reboot, and the scheduler checks
that state before returning to userspace. These controls do not remove the shared
kernel, CPU, timer, serial output or IOMMU from the failure and resource boundaries.
Traffic is not forwarded or bridged between interfaces.

## Open public-deployment requirements

- Qualify the exact Intel/UEFI board, NIC and PCI layout using
  [the hardware requirements](docs/HARDWARE.md), including firmware NMI/SMI paths.
  No physical-machine results are currently available.
- Decide the TLS boundary. The kernel currently serves plaintext HTTP only.
  A maintained TLS reverse proxy and firewall on another host can terminate
  public HTTPS and restrict access to the private backend. Direct public HTTPS,
  certificate/key lifecycle and authenticated administration are not implemented.
  A reverse proxy does not repair kernel or driver defects.
- Review TCP security and protocol conformance. Fresh CPU entropy seeds smoltcp
  on every restart, but smoltcp 0.14's internal sPCG generator is not a CSPRNG.
  This change does not establish cryptographically unpredictable sequence
  numbers. TLS is not a replacement for a transport-layer review.
- Add coverage-guided parser/state-machine fuzzing and sustained fault-injection
  campaigns. Current HTTP/TCP/syscall mutation campaigns are useful bounded
  regressions, not evidence of exhaustive coverage or long-term resilience.
- Review unsafe Rust, assembly, IOMMU lifetimes, trap return paths, speculative
  execution exposure and broad supervisor identity mappings independently.
- Establish signed/verified boot and updates, rollback, operational monitoring,
  patch ownership, incident recovery and upstream denial-of-service protection.
  None is provided by merely compiling the hardware feature.

The static server has no authentication or secret storage and should serve only
public content. Each interface's four HTTP sockets and fixed admission limits do
not provide capacity or availability guarantees for Internet traffic. Limits are
per interface; additional NICs do not create a host-wide client quota. Behind one
proxy, requests to an interface share its source-IP quota.

## Validation and dependencies

`make audit` checks all three lockfiles against RustSec; install the audit tool
separately, for example `cargo install cargo-audit --version 0.22.2 --locked`
from outside this checkout, so its bare-metal Cargo target is not inherited.
Do not ignore a finding solely because services run in ring 3. Record the exact
commit, toolchain, image hashes, advisory database revision and test artifacts
for a release candidate. Tests and fuzz scripts never contact arbitrary remote
targets; their traffic is confined to owned QEMU guests.

The [validation record](docs/VALIDATION.md) distinguishes tests actually run
from missing qualification.

The build's hardware feature is an explicit experimental port. It is not a
production mode and is never a reason to remove a failed isolation check.

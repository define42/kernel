# Experimental Intel / UEFI port

This is an implementation and qualification path, **not a production release**.
No physical machine has been tested. The default QEMU image and the hardware
image have different interrupt-isolation requirements and separate output paths.

## Build the hardware image

Install GRUB's x86_64 EFI modules, `grub-mkrescue`, `grub-file`, xorriso and mtools.
On Debian/Ubuntu the relevant packages are `grub-efi-amd64-bin xorriso mtools`;
OVMF is needed for the firmware test, not for booting a physical computer.

Example private backend address (replace with the actual deployment settings):

```sh
make baremetal-iso KERNEL_IPV4=192.168.50.10 KERNEL_PREFIX=24 \
  KERNEL_GATEWAY=192.168.50.1 KERNEL_ECHO=0
```

Outputs are `build/baremetal/kernel.iso`, `kernel.bin`, three service ELFs, and
`kernel.json` containing the image and kernel SHA-256 hashes. The hashes detect
changes; they are not signatures or a verified boot chain. The fixed load address is 16 MiB; the complete resident range must be usable
RAM. This avoids the low ACPI NVS hole found in OVMF, but is not dynamic
placement for every firmware map. The ISO uses GRUB's
Multiboot2 entry. It supports the GRUB platforms installed on the build machine;
with only x86_64 EFI modules installed it is UEFI-only. Secure Boot signing and
verification of the kernel have **not** been implemented. This command does not
write a disk, configure a router, or publish a server.

`KERNEL_GATEWAY=none` omits the default route. The address, prefix and gateway are
validated at compile time. A gateway must be another on-link unicast host.
Prefixes /1 through /32 are supported; /32 requires `none`. Hardware builds
through Make start with echo disabled. The development build retains the QEMU
address and echo defaults. `make run` networking arguments must also be changed
if a different guest subnet is selected.

These defaults initially apply to every admitted NIC. The trusted COM1 console
uses `nic select ethN` to choose which interface to configure, then `nic set` to
change its static address, prefix, gateway and echo setting, or `nic down`/`nic up`
to stop/restart that interface. Selecting an interface does not interrupt traffic.
Changing its configuration resets only its own connections; settings last until
reboot. Assign distinct addresses to NICs on the same layer-2 network. There is
no persistent per-interface configuration, forwarding, bridging or bonding.
See [console commands](../README.md#serial-command-line).

## Generic Intel support is not implemented

VT-d enabled in UEFI is insufficient for this port. Generic support still needs
PCI ECAM/segment and bridge topology discovery, ACS/requester-alias ownership,
multiple remapping units, capability-driven 48/57-bit translation, safe takeover
of firmware-active remapping, device-scoped RMRR policy, and platform interrupt
routing. Broader e1000-family support also needs controller-specific validation.
The current code rejects these configurations; it does not meet a requirement
to boot and serve safely on arbitrary Intel/UEFI machines.

## Required platform shape

The hardware path currently requires all of the following. These restrictions
are intentional; removing one requires its replacement isolation mechanism.

- Intel x86-64 bootstrap CPU; one active CPU, NX, FXSAVE/SSE2, CLFLUSH and a
  functioning RDSEED or RDRAND source. CPU RNG is a platform trust dependency.
  PAT entry 0 must be WB and entry 3 UC; the bootstrap rejects other settings.
- UEFI/GRUB Multiboot2 after ExitBootServices, with a complete memory map that
  covers the entire resident kernel, including BSS and static DMA/process pools.
- Valid ACPI RSDP/root/SDTs below 1 GiB in firmware-reserved memory. ACPI HPET
  must describe a 64-bit main counter at a 4 KiB-aligned address in 1–4 GiB.
- Enabled xAPIC with its MMIO page in the uncached 1–4 GiB map. x2APIC is rejected.
  The local APIC timer is calibrated against HPET; PIC/PIT routing is not used
  by the hardware scheduling path.
- One to eight Intel **82540EM, PCI `8086:100e`** single-function type-zero
  Ethernet endpoints directly on PCI root bus 0, with supported, nonoverlapping
  aligned 32-bit BARs. All admitted interfaces can operate concurrently. Other
  e1000-family controllers, multifunction/requester aliases, bridges and PCIe
  root-port assignments remain unsupported. Unsupported 82540EM functions stay
  bus-master-disabled and are excluded from the inventory; an inventory overflow
  fails closed.
- Enabled firmware VT-d with exactly one supported segment-zero DRHD covering
  every admitted NIC, legacy 39-bit translation, read/write draining, queued invalidation,
  and firmware-declared interrupt remapping. RMRR, multiple DRHDs, firmware-owned
  active translation, and unsupported register layouts are rejected.

The required motherboard model, firmware revision, NIC PCI ID/revision and PCI
layout must be recorded before a machine is qualified. “Intel CPU and UEFI”
alone does not establish these capabilities. Many modern Intel systems will
intentionally refuse this narrow port.

## DMA and interrupt policy

Each NIC has an immutable requester assignment, distinct VT-d domain and page
tables, and its own pinned DMA pool at a separate IOVA window. No peer NIC pool,
kernel, firmware or service memory is present in that domain. Interrupt remapping
uses an entirely nonpresent table shared by the remapping unit. Queued global
interrupt-cache invalidation must complete; translation and interrupt-remapping
status are rechecked before bus mastering. Compatibility-format interrupt
forwarding must remain disabled.

Each interface has separate ring-3 driver, TCP/IP and web processes, with private
physical memory, page tables, user stacks, IPC queues and connection state. Only
its driver can map that NIC's BAR and DMA pool. The scheduler runs these groups
on the single bootstrap CPU. Normal builds reserve 24 process slots with 48 MiB
of private backing even when fewer NICs are present; kernel tables protect the
resident image at 4 KiB granularity, within a 128 MiB physical-address limit. The
boot memory-map validation still requires the entire allocation to be usable RAM.

`nic list` shows each interface's independent state in PCI BDF order. Selecting
one changes console focus only. Stopping or reconfiguring an interface disables
its bus mastering, resets its hardware, revokes its own VT-d context, and
acknowledges global context/IOTLB invalidation with read/write draining before
its private pool is reset. Its old driver MMIO/DMA mappings are removed before
reconfiguration. Other NICs retain their own contexts, pools and processes.
Administratively down interfaces remain bus-master-disabled with absent contexts.

A DMA fault attributed to a known NIC restarts that interface's service group.
Its recovery clears only its own fault records. Fault overflow, an unknown
requester, or a shared remapping failure quarantines every interface. A failed
invalidation or protection check latches a shared failure until reboot. Console
selection and `nic up` cannot clear quarantine.

The hardware image refuses CPUs advertising a hypervisor. This is a compatibility
guard for known incomplete emulator behavior, not an adversarial hypervisor
detection mechanism. The default development image still requires QEMU without
a local APIC. In QEMU 8.2.2, interrupt-remapping state and nonpresent IRTE faults
can be exercised, but compatibility-format MSI passes through. Its DMA-generated
MSI probe reports requester ID `0xffff` (unknown) for the nonpresent IRTE fault.
The kernel therefore quarantines every NIC rather than attributing that interrupt
to one interface. `make test-interrupt-remapping` checks this denial and shared
quarantine; source-attributed DMA recovery is covered by the service and multi-NIC
isolation tests. An emulator acknowledgment cannot establish physical containment.

An all-denied interrupt table also affects platform IOAPIC messages. Firmware
NMI/SMI routing, thermal/error handling, and management firmware must be reviewed
on the actual board before enabling the hardware image. The local APIC backend also masks LINT0/LINT1, thermal, performance and CMCI
interrupt inputs. The current port does not preserve general platform-event
interrupt routing. Physical NIC reset,
PHY behavior, DMA draining and link recovery also require testing on that card.

References: [Intel VT-d specification, §§5.1.4, 5.1.7, 6.5.2 and 6.7](https://cdrdv2-public.intel.com/671081/vt-directed-io-spec.pdf),
[QEMU 8.2.2 Intel IOMMU implementation](https://github.com/qemu/qemu/blob/v8.2.2/hw/i386/intel_iommu.c#L3355),
[Multiboot2 specification](https://www.gnu.org/software/grub/manual/multiboot2/multiboot.html).

## Reproducible checks

```sh
make check test
make test-firmware test-apic test-deployment test-interrupt-remapping test-hardware-refusal
make fuzz FUZZ_SECONDS=300 FUZZ_ITERATIONS=1000000 FUZZ_TIMEOUT=180
make audit
```

`test-firmware` verifies UEFI/GRUB handoff in OVMF. `test-apic` exercises actual
ring-3 timer interrupts using the separate legacy privilege-test image; it does
not bypass the normal hardware device guard. `test-deployment` serves HTTP on
a different private subnet with echo disabled and verifies RNG refusal.
The usual service tests cover address-space, syscall, DMA and restart behavior.
All network test endpoints are private QEMU connections or localhost.

QEMU checks are component evidence only. Physical acceptance needs serial logs
and packet captures for repeated cold/warm boots, loaded preemption, DMA read/
write containment, all interrupt-message formats, reset/fault recovery, link
flaps, firmware events, and long-running malformed traffic. Also establish
remote recovery and a known-good boot entry before deployment.

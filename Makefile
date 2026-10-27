.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

CARGO ?= cargo
CLIPPY_DRIVER ?= clippy-driver
OBJCOPY ?= objcopy
QEMU ?= qemu-system-x86_64
PYTHON ?= python3
HOST_PORT ?= 5555
HTTP_PORT ?= 8080
HTTP_PORT_1 ?= 8081
HOST_PORT_1 ?= 5556
SERIAL_PORT ?= 4444
FUZZ_SECONDS ?= 30
FUZZ_SEED ?= 1
FUZZ_ITERATIONS ?= 100000
FUZZ_TIMEOUT ?= 120
HOST_TARGET := $(shell rustc -vV | sed -n 's/^host: //p')
QEMU_NET ?= -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp:127.0.0.1:$(HOST_PORT)-10.0.2.15:1234,hostfwd=tcp:127.0.0.1:$(HTTP_PORT)-10.0.2.15:80
QEMU_MULTI_NET ?= -device e1000,netdev=net0,bus=pcie.0,addr=0x02,mac=52:54:00:12:34:56 -netdev user,id=net0,hostfwd=tcp:127.0.0.1:$(HOST_PORT)-10.0.2.15:1234,hostfwd=tcp:127.0.0.1:$(HTTP_PORT)-10.0.2.15:80 -device e1000,netdev=net1,bus=pcie.0,addr=0x03,mac=52:54:00:12:34:57 -netdev user,id=net1,hostfwd=tcp:127.0.0.1:$(HOST_PORT_1)-10.0.2.15:1234,hostfwd=tcp:127.0.0.1:$(HTTP_PORT_1)-10.0.2.15:80
GRUB_MKRESCUE ?= grub-mkrescue
GRUB_FILE ?= grub-file
OVMF_CODE ?= /usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS ?= /usr/share/OVMF/OVMF_VARS_4M.fd
QEMU_FLAGS ?=

TARGET := x86_64-unknown-none
KERNEL_ELF := target/$(TARGET)/release/kernel
USER_TEST_ELF := target/userspace-test/$(TARGET)/release/kernel
USER_TEST_BIN := build/userspace-test/kernel.bin
TEST_ELF := target/smoke-test/$(TARGET)/release/kernel
KERNEL_BIN := build/kernel.bin
TEST_BIN := build/test/kernel.bin
QEMU_COMMON := -machine q35 -device intel-iommu,intremap=off -accel tcg -cpu max,-apic -m 128M -smp 1 -no-reboot -no-shutdown

.PHONY: all build kernel setup run run-gui debug test test-boot test-net test-packets test-http test-userspace test-preemption test-abuse test-host fuzz fuzz-http fuzz-tcp fuzz-syscalls check clean help

all: kernel
build: kernel

setup:
	rustup target add $(TARGET)

# Let Cargo track source changes, including the linker script via build.rs.
kernel:
	$(CARGO) build --release --target $(TARGET) --target-dir target
	@mkdir -p build
	$(OBJCOPY) -O binary $(KERNEL_ELF) $(KERNEL_BIN)
	cp target/$(TARGET)/release/webserver.elf build/webserver.elf
	cp target/$(TARGET)/release/netd.elf build/netd.elf
	cp target/$(TARGET)/release/nic-driver.elf build/nic-driver.elf

# Serial console in this terminal; Ctrl-a x exits QEMU.
run: kernel
	$(QEMU) $(QEMU_COMMON) $(QEMU_NET) -kernel $(KERNEL_BIN) -display none -serial mon:stdio $(QEMU_FLAGS)

# VGA output in a window, plus the same serial console in this terminal.
run-gui: kernel
	$(QEMU) $(QEMU_COMMON) $(QEMU_NET) -kernel $(KERNEL_BIN) -serial mon:stdio $(QEMU_FLAGS)

# Pause before boot and expose GDB on localhost:1234.
debug: kernel
	$(QEMU) $(QEMU_COMMON) $(QEMU_NET) -kernel $(KERNEL_BIN) -display none -serial mon:stdio -S -gdb tcp:127.0.0.1:1234 $(QEMU_FLAGS)

# Isolate the test feature's artifacts from the normal boot image.
test: test-boot test-userspace test-preemption test-host test-abuse test-net test-packets test-http test-services test-serial test-setup test-multi-nic test-multi-nic-guards test-multi-nic-isolation

test-boot:
	$(CARGO) build --release --features smoke-test --target $(TARGET) --target-dir target/smoke-test
	@mkdir -p build/test
	$(OBJCOPY) -O binary $(TEST_ELF) $(TEST_BIN)
	$(PYTHON) scripts/smoke_test.py "$(QEMU)" $(TEST_BIN)

test-userspace:
	$(CARGO) build --release --features userspace-test --target $(TARGET) --target-dir target/userspace-test
	@mkdir -p build/userspace-test
	$(OBJCOPY) -O binary $(USER_TEST_ELF) $(USER_TEST_BIN)
	$(PYTHON) scripts/userspace_test.py "$(QEMU)" $(USER_TEST_BIN)
	$(PYTHON) scripts/userspace_test.py "$(QEMU)" $(USER_TEST_BIN) --cpu max

test-preemption:
	$(CARGO) build --release --features preemption-test --target $(TARGET) --target-dir target/preemption-test
	@mkdir -p build/preemption-test
	$(OBJCOPY) -O binary target/preemption-test/$(TARGET)/release/kernel build/preemption-test/kernel.bin
	$(PYTHON) scripts/preemption_test.py "$(QEMU)" build/preemption-test/kernel.bin

test-host:
	@mkdir -p target/host-tests
	rustc --edition 2024 --test userspace/network_config.rs -o target/host-tests/network-config
	target/host-tests/network-config
	rustc --edition 2024 --test src/shell_input.rs -D warnings -o target/host-tests/shell-input
	target/host-tests/shell-input
	rustc --edition 2024 --test tests/serial_shell.rs -D warnings -o target/host-tests/serial-shell
	target/host-tests/serial-shell --skip shell_input::tests
	rustc --edition 2024 --test tests/setup_plan.rs -D warnings -o target/host-tests/setup-plan
	target/host-tests/setup-plan setup_plan::tests
	rustc --edition 2024 --test src/pci.rs -D warnings -o target/host-tests/pci
	target/host-tests/pci
	rustc --edition 2024 --test src/platform.rs -o target/host-tests/platform
	target/host-tests/platform
	rustc --edition 2024 --test tests/clock.rs -D warnings -o target/host-tests/clock
	target/host-tests/clock time::tests
	$(CARGO) test --manifest-path tests/host/Cargo.toml --target $(HOST_TARGET) --target-dir target/host-tests

test-abuse: kernel
	$(PYTHON) scripts/abuse_test.py "$(QEMU)" $(KERNEL_BIN)

fuzz: fuzz-http fuzz-tcp fuzz-syscalls

fuzz-http: kernel
	$(PYTHON) scripts/fuzz_network.py "$(QEMU)" $(KERNEL_BIN) --mode http --seed $(FUZZ_SEED) --seconds $(FUZZ_SECONDS)

fuzz-tcp: kernel
	$(PYTHON) scripts/fuzz_network.py "$(QEMU)" $(KERNEL_BIN) --mode tcp --seed $(FUZZ_SEED) --seconds $(FUZZ_SECONDS)

fuzz-syscalls:
	KERNEL_FUZZ_SEED=$(FUZZ_SEED) KERNEL_FUZZ_ITERATIONS=$(FUZZ_ITERATIONS) $(CARGO) build --release --features fuzz-test --target $(TARGET) --target-dir target/fuzz-test
	@mkdir -p build/fuzz-test
	$(OBJCOPY) -O binary target/fuzz-test/$(TARGET)/release/kernel build/fuzz-test/kernel.bin
	$(PYTHON) scripts/fuzz_syscalls.py "$(QEMU)" build/fuzz-test/kernel.bin --timeout $(FUZZ_TIMEOUT)

test-net: kernel
	$(PYTHON) scripts/network_test.py "$(QEMU)" $(KERNEL_BIN)

test-packets: kernel
	$(PYTHON) scripts/packet_test.py "$(QEMU)" $(KERNEL_BIN)

test-http: kernel
	$(PYTHON) scripts/http_test.py "$(QEMU)" $(KERNEL_BIN)

check:
	$(CARGO) fmt --all -- --check
	rustfmt --edition 2024 --check userspace/main.rs userspace/netd.rs userspace/driver.rs
	$(CARGO) clippy --target $(TARGET) -- -D warnings
	$(CARGO) clippy --features userspace-test --target $(TARGET) -- -D warnings
	$(CARGO) clippy --features baremetal --target $(TARGET) -- -D warnings
	$(CARGO) clippy --features userspace-test,baremetal --target $(TARGET) -- -D warnings
	$(CARGO) clippy --features preemption-test --target $(TARGET) -- -D warnings
	$(CARGO) clippy --features isolation-test --target $(TARGET) -- -D warnings
	$(CARGO) clippy --features fuzz-test --target $(TARGET) -- -D warnings
	$(CARGO) clippy --manifest-path tests/host/Cargo.toml --tests --target $(HOST_TARGET) --target-dir target/host-tests -- -D warnings
	$(CARGO) clippy --all-features --target $(TARGET) -- -D warnings
	$(CARGO) clippy --manifest-path userspace/services/Cargo.toml --target $(TARGET) --target-dir target/services-check -- -D warnings
	$(CLIPPY_DRIVER) --edition=2024 --crate-name nic_driver --check-cfg 'cfg(driver_test)' --crate-type bin --target $(TARGET) --emit=metadata -Cpanic=abort userspace/driver.rs -o target/nic-driver-check.rmeta -D warnings
	$(CLIPPY_DRIVER) --edition=2024 --crate-name nic_driver --cfg driver_test --check-cfg 'cfg(driver_test)' --crate-type bin --target $(TARGET) --emit=metadata -Cpanic=abort userspace/driver.rs -o target/nic-driver-test-check.rmeta -D warnings
	@mkdir -p target/userspace-check
	$(CLIPPY_DRIVER) --edition=2024 --crate-name webserver --crate-type bin --target $(TARGET) --emit=metadata -Cpanic=abort --check-cfg 'cfg(userspace_test)' userspace/main.rs -o target/userspace-check/webserver.rmeta -D warnings
	$(CLIPPY_DRIVER) --edition=2024 --crate-name webserver --crate-type bin --target $(TARGET) --emit=metadata -Cpanic=abort --check-cfg 'cfg(userspace_test)' --cfg userspace_test userspace/main.rs -o target/userspace-check/webserver-test.rmeta -D warnings

clean:
	$(CARGO) clean --target-dir target
	rm -rf build

help:
	@printf '%s\n' \
	  'make           Build build/kernel.bin and the ELF with debug symbols' \
	  'make setup     Install the Rust bare-metal target' \
	  'make test-std  Build the native userspace std port and test it in QEMU' \
	  'make run       Boot QEMU in this terminal (Ctrl-a x to exit)' \
	  'make run-gui   Boot QEMU with a VGA window and serial console' \
	  'make run-serial  Boot with COM1 on localhost:4444 (SERIAL_PORT overrides)' \
	  'make console   Attach to the serial socket; Ctrl-] detaches' \
	  'make test-serial  Test shell, live NIC changes, reconnects, and HTTP' \
	  'make test-setup  Test serial JSON setup, batch validation, and live NICs' \
	  'make run-multi-nic  Boot two independently active NICs' \
	  'make run-multi-nic-serial  Two NICs plus the reconnectable serial socket' \
	  'make test-multi-nic  Test simultaneous traffic and independent NIC configuration' \
	  'make test-multi-nic-guards  Test eight active NICs, inventory guards, and PCI DMA state' \
	  'make test-multi-nic-isolation  Test cross-NIC faults with peer traffic active' \
	  'make test-multi-nic-shared-failure  Test quarantine after a shared IOMMU failure' \
	  'make debug     Wait for GDB on localhost:1234 before booting' \
	  'make iso       Create build/kernel.iso using installed GRUB platforms' \
	  'make test-firmware  Verify GRUB/UEFI handoff in OVMF' \
	  'make test      Run boot, ring-3 isolation, TCP, ARP/ICMP, and HTTP checks in QEMU' \
	  'make test-net  Test TCP echo, ring wrap, reconnects, and close/reset' \
	  'make test-packets  Test ARP, IPv4/ICMP, and checksum rejection' \
	  'make test-boot Run the original CPU/memory boot checks' \
	  'make test-http Test HTTP requests, errors, concurrency, and timeouts' \
	  'make test-userspace  Test ring-3 privileges, syscalls, and fault containment' \
	  'make test-services  Test process, IPC, DMA isolation and service recovery' \
	  'make test-preemption  Verify networking during a busy or syscall-only user loop' \
	  'make test-abuse Verify per-source quotas and half-open recovery' \
	  'make fuzz      Run local HTTP, TCP, and syscall mutation campaigns' \
	  'make check     Check Rust formatting and Clippy lints' \
	  'make clean     Remove generated files'

.PHONY: test-services

test-services:
	$(CARGO) build --release --features isolation-test --target $(TARGET) --target-dir target/isolation-test
	@mkdir -p build/isolation-test
	$(OBJCOPY) -O binary target/isolation-test/$(TARGET)/release/kernel build/isolation-test/kernel.bin
	$(PYTHON) scripts/isolation_test.py "$(QEMU)" build/isolation-test/kernel.bin

# GRUB uses Multiboot2 for firmware discovery; its installed platform modules
# determine whether the image supports BIOS, UEFI, or both.
.PHONY: iso test-firmware
iso: kernel
	$(PYTHON) scripts/make_iso.py $(KERNEL_BIN) build/kernel.iso --grub-mkrescue "$(GRUB_MKRESCUE)" --grub-file "$(GRUB_FILE)"

test-firmware: test-boot
	$(PYTHON) scripts/make_iso.py $(TEST_BIN) build/test/kernel.iso --grub-mkrescue "$(GRUB_MKRESCUE)" --grub-file "$(GRUB_FILE)"
	$(PYTHON) scripts/firmware_test.py "$(QEMU)" build/test/kernel.iso --code "$(OVMF_CODE)" --vars "$(OVMF_VARS)"

$(foreach setting,KERNEL_IPV4 KERNEL_PREFIX KERNEL_GATEWAY KERNEL_ECHO,$(if $(filter undefined,$(origin $(setting))),,$(eval export $(setting))))

# Separate output prevents an experimental hardware build from replacing the
# known QEMU development image. Require deliberate address and echo settings.
.PHONY: baremetal baremetal-iso
baremetal:
	@test -n "$(KERNEL_IPV4)" -a -n "$(KERNEL_PREFIX)" -a -n "$(KERNEL_GATEWAY)" -a "$(KERNEL_ECHO)" = 0 || { echo 'Set KERNEL_IPV4, KERNEL_PREFIX, KERNEL_GATEWAY (or none), and KERNEL_ECHO=0'; exit 1; }
	$(CARGO) build --locked --release --features baremetal --target $(TARGET) --target-dir target/baremetal
	@mkdir -p build/baremetal
	$(OBJCOPY) -O binary target/baremetal/$(TARGET)/release/kernel build/baremetal/kernel.bin
	cp target/baremetal/$(TARGET)/release/webserver.elf target/baremetal/$(TARGET)/release/netd.elf target/baremetal/$(TARGET)/release/nic-driver.elf build/baremetal/

baremetal-iso: baremetal
	$(PYTHON) scripts/make_iso.py build/baremetal/kernel.bin build/baremetal/kernel.iso --grub-mkrescue "$(GRUB_MKRESCUE)" --grub-file "$(GRUB_FILE)"

.PHONY: test-deployment test-apic audit
test-deployment:
	KERNEL_IPV4=10.77.0.15 KERNEL_PREFIX=24 KERNEL_GATEWAY=10.77.0.2 KERNEL_ECHO=0 $(CARGO) build --locked --release --target $(TARGET) --target-dir target/deployment-test
	@mkdir -p build/deployment-test
	$(OBJCOPY) -O binary target/deployment-test/$(TARGET)/release/kernel build/deployment-test/kernel.bin
	$(PYTHON) scripts/deployment_test.py "$(QEMU)" build/deployment-test/kernel.bin

test-apic:
	$(CARGO) build --locked --release --features userspace-test,baremetal --target $(TARGET) --target-dir target/apic-test
	@mkdir -p build/apic-test
	$(OBJCOPY) -O binary target/apic-test/$(TARGET)/release/kernel build/apic-test/kernel.bin
	$(PYTHON) scripts/userspace_test.py "$(QEMU)" build/apic-test/kernel.bin --cpu max

# Install cargo-audit separately; this target never suppresses advisories.
audit:
	$(CARGO) audit --file Cargo.lock
	$(CARGO) audit --file userspace/services/Cargo.lock
	$(CARGO) audit --file tests/host/Cargo.lock

.PHONY: test-interrupt-remapping
test-interrupt-remapping:
	KERNEL_IR_PROBE=1 $(CARGO) build --locked --release --features isolation-test --target $(TARGET) --target-dir target/interrupt-remap-test
	@mkdir -p build/interrupt-remap-test
	$(OBJCOPY) -O binary target/interrupt-remap-test/$(TARGET)/release/kernel build/interrupt-remap-test/kernel.bin
	$(PYTHON) scripts/interrupt_remapping_test.py "$(QEMU)" build/interrupt-remap-test/kernel.bin

.PHONY: test-hardware-refusal
test-hardware-refusal:
	$(MAKE) baremetal-iso KERNEL_IPV4=192.168.50.10 KERNEL_PREFIX=24 KERNEL_GATEWAY=192.168.50.1 KERNEL_ECHO=0
	$(PYTHON) scripts/firmware_test.py "$(QEMU)" build/baremetal/kernel.iso --hardware-refusal --code "$(OVMF_CODE)" --vars "$(OVMF_VARS)"

# Raw COM1 transport, bound to loopback; the kernel owns every input byte.
.PHONY: run-serial console test-serial test-setup
run-serial: kernel
	$(QEMU) $(QEMU_COMMON) $(QEMU_NET) -kernel $(KERNEL_BIN) -display none -monitor none -chardev socket,id=com1,host=127.0.0.1,port=$(SERIAL_PORT),server=on,wait=off -serial chardev:com1 $(QEMU_FLAGS)

console:
	$(PYTHON) scripts/serial_client.py --port $(SERIAL_PORT)

test-serial: kernel
	$(PYTHON) scripts/serial_test.py "$(QEMU)" $(KERNEL_BIN)

test-setup: kernel
	$(PYTHON) scripts/setup_test.py "$(QEMU)" $(KERNEL_BIN)

# Separate user networks exercise independent active NICs; all forwards are local.
.PHONY: run-multi-nic run-multi-nic-serial test-multi-nic test-multi-nic-guards
run-multi-nic: kernel
	$(QEMU) $(QEMU_COMMON) $(QEMU_MULTI_NET) -kernel $(KERNEL_BIN) -display none -serial mon:stdio $(QEMU_FLAGS)

run-multi-nic-serial: kernel
	$(QEMU) $(QEMU_COMMON) $(QEMU_MULTI_NET) -kernel $(KERNEL_BIN) -display none -monitor none -chardev socket,id=com1,host=127.0.0.1,port=$(SERIAL_PORT),server=on,wait=off -serial chardev:com1 $(QEMU_FLAGS)

test-multi-nic: kernel
	$(PYTHON) scripts/multi_nic_test.py "$(QEMU)" $(KERNEL_BIN)

test-multi-nic-guards: kernel
	$(PYTHON) scripts/multi_nic_guard_test.py "$(QEMU)" $(KERNEL_BIN)

.PHONY: test-multi-nic-isolation test-multi-nic-shared-failure
test-multi-nic-isolation:
	$(CARGO) build --release --features isolation-test --target $(TARGET) --target-dir target/isolation-test
	@mkdir -p build/isolation-test
	$(OBJCOPY) -O binary target/isolation-test/$(TARGET)/release/kernel build/isolation-test/kernel.bin
	$(PYTHON) scripts/multi_nic_isolation_test.py "$(QEMU)" build/isolation-test/kernel.bin

test-multi-nic-shared-failure:
	KERNEL_SHARED_FAULT_PROBE=1 $(CARGO) build --release --features isolation-test --target $(TARGET) --target-dir target/shared-failure-test
	@mkdir -p build/shared-failure-test
	$(OBJCOPY) -O binary target/shared-failure-test/$(TARGET)/release/kernel build/shared-failure-test/kernel.bin
	$(PYTHON) scripts/multi_nic_isolation_test.py "$(QEMU)" build/shared-failure-test/kernel.bin --shared-failure

# A real std sysroot port, isolated from the normal stable no_std build.
.PHONY: setup-std std-demo std-kernel test-std check-std
setup-std:
	$(PYTHON) scripts/build_std.py --setup-only

std-demo:
	$(PYTHON) scripts/build_std.py

std-kernel: std-demo
	$(CARGO) build --release --features std-test --target $(TARGET) --target-dir target/std-test
	@mkdir -p build/std-test
	$(OBJCOPY) -O binary target/std-test/$(TARGET)/release/kernel build/std-test/kernel.bin

test-std: std-kernel
	$(PYTHON) scripts/std_test.py "$(QEMU)" build/std-test/kernel.bin
	$(PYTHON) scripts/std_test.py "$(QEMU)" build/std-test/kernel.bin --no-entropy

check-std: std-demo
	$(PYTHON) userspace/std-port/test_apply.py target/std-toolchain/library-pristine
	$(CARGO) clippy --features std-test --target $(TARGET) --target-dir target/std-test -- -D warnings
	rustfmt --edition 2024 --check userspace/std-runtime/src/lib.rs userspace/std-demo/src/main.rs

.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

CARGO ?= cargo
CLIPPY_DRIVER ?= clippy-driver
OBJCOPY ?= objcopy
QEMU ?= qemu-system-x86_64
PYTHON ?= python3
HOST_PORT ?= 5555
HTTP_PORT ?= 8080
FUZZ_SECONDS ?= 30
FUZZ_SEED ?= 1
FUZZ_ITERATIONS ?= 100000
FUZZ_TIMEOUT ?= 120
HOST_TARGET := $(shell rustc -vV | sed -n 's/^host: //p')
QEMU_NET ?= -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp:127.0.0.1:$(HOST_PORT)-10.0.2.15:1234,hostfwd=tcp:127.0.0.1:$(HTTP_PORT)-10.0.2.15:80
QEMU_FLAGS ?=

TARGET := x86_64-unknown-none
KERNEL_ELF := target/$(TARGET)/release/kernel
USER_TEST_ELF := target/userspace-test/$(TARGET)/release/kernel
USER_TEST_BIN := build/userspace-test/kernel.bin
TEST_ELF := target/smoke-test/$(TARGET)/release/kernel
KERNEL_BIN := build/kernel.bin
TEST_BIN := build/test/kernel.bin
QEMU_COMMON := -machine pc -accel tcg -m 128M -smp 1 -no-reboot -no-shutdown

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
test: test-boot test-userspace test-preemption test-host test-abuse test-net test-packets test-http

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
	rustfmt --edition 2024 --check userspace/main.rs
	$(CARGO) clippy --target $(TARGET) -- -D warnings
	$(CARGO) clippy --features userspace-test --target $(TARGET) -- -D warnings
	$(CARGO) clippy --features preemption-test --target $(TARGET) -- -D warnings
	$(CARGO) clippy --features fuzz-test --target $(TARGET) -- -D warnings
	$(CARGO) clippy --manifest-path tests/host/Cargo.toml --tests --target $(HOST_TARGET) --target-dir target/host-tests -- -D warnings
	$(CARGO) clippy --all-features --target $(TARGET) -- -D warnings
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
	  'make run       Boot QEMU in this terminal (Ctrl-a x to exit)' \
	  'make run-gui   Boot QEMU with a VGA window and serial console' \
	  'make debug     Wait for GDB on localhost:1234 before booting' \
	  'make test      Run boot, ring-3 isolation, TCP, ARP/ICMP, and HTTP checks in QEMU' \
	  'make test-net  Test TCP echo, ring wrap, reconnects, and close/reset' \
	  'make test-packets  Test ARP, IPv4/ICMP, and checksum rejection' \
	  'make test-boot Run the original CPU/memory boot checks' \
	  'make test-http Test HTTP requests, errors, concurrency, and timeouts' \
	  'make test-userspace  Test ring-3 privileges, syscalls, and fault containment' \
	  'make test-preemption  Verify networking during a busy or syscall-only user loop' \
	  'make test-abuse Verify per-source quotas and half-open recovery' \
	  'make fuzz      Run local HTTP, TCP, and syscall mutation campaigns' \
	  'make check     Check Rust formatting and Clippy lints' \
	  'make clean     Remove generated files'

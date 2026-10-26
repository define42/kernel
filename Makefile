.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

CARGO ?= cargo
OBJCOPY ?= objcopy
QEMU ?= qemu-system-x86_64
PYTHON ?= python3
HOST_PORT ?= 5555
HTTP_PORT ?= 8080
QEMU_NET ?= -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp:127.0.0.1:$(HOST_PORT)-10.0.2.15:1234,hostfwd=tcp:127.0.0.1:$(HTTP_PORT)-10.0.2.15:80
QEMU_FLAGS ?=

TARGET := x86_64-unknown-none
KERNEL_ELF := target/$(TARGET)/release/kernel
TEST_ELF := target/smoke-test/$(TARGET)/release/kernel
KERNEL_BIN := build/kernel.bin
TEST_BIN := build/test/kernel.bin
QEMU_COMMON := -machine pc -accel tcg -m 128M -smp 1 -no-reboot -no-shutdown

.PHONY: all build kernel setup run run-gui debug test test-boot test-net test-packets test-http check clean help

all: kernel
build: kernel

setup:
	rustup target add $(TARGET)

# Let Cargo track source changes, including the linker script via build.rs.
kernel:
	$(CARGO) build --release --target $(TARGET) --target-dir target
	@mkdir -p build
	$(OBJCOPY) -O binary $(KERNEL_ELF) $(KERNEL_BIN)

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
test: test-boot test-net test-packets test-http

test-boot:
	$(CARGO) build --release --features smoke-test --target $(TARGET) --target-dir target/smoke-test
	@mkdir -p build/test
	$(OBJCOPY) -O binary $(TEST_ELF) $(TEST_BIN)
	$(PYTHON) scripts/smoke_test.py "$(QEMU)" $(TEST_BIN)

test-net: kernel
	$(PYTHON) scripts/network_test.py "$(QEMU)" $(KERNEL_BIN)

test-packets: kernel
	$(PYTHON) scripts/packet_test.py "$(QEMU)" $(KERNEL_BIN)

test-http: kernel
	$(PYTHON) scripts/http_test.py "$(QEMU)" $(KERNEL_BIN)

check:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --target $(TARGET) -- -D warnings
	$(CARGO) clippy --all-features --target $(TARGET) -- -D warnings

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
	  'make test      Run boot, TCP, ARP/ICMP, and HTTP checks in QEMU' \
	  'make test-net  Test TCP echo, ring wrap, reconnects, and close/reset' \
	  'make test-packets  Test ARP, IPv4/ICMP, and checksum rejection' \
	  'make test-boot Run the original CPU/memory boot checks' \
	  'make test-http Test HTTP requests, errors, concurrency, and timeouts' \
	  'make check     Check Rust formatting and Clippy lints' \
	  'make clean     Remove generated files'

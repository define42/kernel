#!/usr/bin/env python3
"""Verify bounded JSON setup, batch preflight, and independent NICs in QEMU."""

import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time

from http_test import REQUEST
from multi_nic_test import BDFS, MACS, LiveTraffic, launch, progress, selected_status
from network_test import positive_timeout, show_logs, stop_qemu
from serial_test import (Console, HTTP_READY, binary_echo, check_guest,
                         nic_action, require_silent, wait_health)


LINE_CAPACITY = 2048
CHANGED_MAC = "52:54:00:ab:cd:67"
FINAL_MAC = "52:54:00:ab:cd:68"


def configuration(nic, *, ip=15, prefix=24, gateway="10.0.2.2", echo=True, enabled=True,
                  mac=None):
    return {"Interface": f"eth{nic}", "PCI": BDFS[nic],
            "MAC": MACS[nic] if mac is None else mac, "IPv4": f"10.0.2.{ip}/{prefix}",
            "Gateway": gateway, "Echo": echo, "Enabled": enabled}


def wire(entries):
    return b"setup " + json.dumps({"system": entries}, separators=(",", ":")).encode("ascii")


def export(console, expected):
    output = console.command(b"setup show\r")
    lines = [line for line in output.splitlines() if line.startswith(b'{"system":')]
    if len(lines) != 1:
        raise RuntimeError(f"setup show did not emit one JSON document: {output!r}")
    try:
        actual = json.loads(lines[0])
    except (ValueError, UnicodeError) as error:
        raise RuntimeError(f"setup show emitted invalid JSON: {output!r}") from error
    wanted = {"system": expected}
    if actual != wanted:
        raise RuntimeError(f"setup state mismatch: wanted {wanted!r}, got {actual!r}")


def apply(console, entries):
    output = console.command(wire(entries) + b"\r")
    if b"error" in output.lower() or b"unknown command" in output.lower():
        raise RuntimeError(f"setup command failed: {output!r}")


def reject(console, command):
    output = console.command(command + b"\r")
    if b"setup error:" not in output.lower():
        raise RuntimeError(f"invalid setup was not rejected: {output!r}")


def verify_changed_mac(capture):
    """Check wire identities, rather than trusting the configuration display."""
    data = capture.read_bytes()
    orders = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    if len(data) < 24 or data[:4] not in orders:
        raise RuntimeError("QEMU produced an invalid PCAP header")
    order = orders[data[:4]]
    if struct.unpack_from(order + "I", data, 20)[0] != 1:
        raise RuntimeError("QEMU PCAP is not Ethernet")
    identities = (CHANGED_MAC, FINAL_MAC)
    macs = tuple(bytes.fromhex(mac.replace(":", "")) for mac in identities)
    address = bytes((10, 0, 2, 16))
    counts = {mac: {"ARP": 0, "announcement": 0, "HTTP response": 0, "HTTP request": 0}
              for mac in macs}
    final_seen = False
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            raise RuntimeError("QEMU PCAP has a truncated record")
        length = struct.unpack_from(order + "I", data, offset + 8)[0]
        offset += 16
        if length > len(data) - offset:
            raise RuntimeError("QEMU PCAP has a truncated Ethernet frame")
        packet = data[offset:offset + length]
        offset += length
        if len(packet) < 14:
            continue
        source, destination = packet[6:12], packet[:6]
        if (len(packet) >= 42 and packet[12:14] == b"\x08\x06"
                and packet[28:32] == address):
            if source not in macs or packet[22:28] != source:
                raise RuntimeError("eth1 ARP did not use its configured MAC")
            if final_seen and source != macs[1]:
                raise RuntimeError("eth1 sent its previous MAC after applying the new MAC")
            final_seen |= source == macs[1]
            counts[source]["ARP"] += 1
            if (packet[20:22] == b"\x00\x01" and packet[38:42] == address
                    and packet[32:38] == b"\x00" * 6 and destination == b"\xff" * 6):
                counts[source]["announcement"] += 1
        if len(packet) < 54 or packet[12:14] != b"\x08\x00" or packet[23] != 6:
            continue
        header_length = (packet[14] & 15) * 4
        if header_length < 20 or len(packet) < 14 + header_length + 20:
            continue
        ports = struct.unpack_from("!HH", packet, 14 + header_length)
        if packet[26:30] == address and ports[0] == 80:
            if source not in macs:
                raise RuntimeError("eth1 HTTP did not use its configured source MAC")
            if final_seen and source != macs[1]:
                raise RuntimeError("eth1 HTTP used its previous MAC after a MAC-only change")
            final_seen |= source == macs[1]
            counts[source]["HTTP response"] += 1
        if packet[30:34] == address and ports[1] == 80 and destination in macs:
            counts[destination]["HTTP request"] += 1
    report = {identity: counts[mac] for identity, mac in zip(identities, macs)}
    if not all(value for tally in counts.values() for value in tally.values()):
        raise RuntimeError(f"configured MACs were not verified in both wire directions: {report}")
    print(f"Packet capture verified eth1 MAC changes and ARP announcements: {report}.")


def normal_checks(args, root, deadline):
    process, ports, serial, stderr = launch(args, root, deadline, iommu=True, capture=True)
    console = None
    workers = []
    try:
        console = Console(ports["console"], process, serial, deadline)
        console.command(b"\x03")
        for command in (b"setup\r", b"setup help\r"):
            output = console.command(command)
            if not all(field in output for field in (b"system", b"Interface", b"PCI", b"MAC", b"IPv4", b"Gateway")):
                raise RuntimeError(f"setup usage omitted its schema: {output!r}")
        expected = [configuration(0), configuration(1)]
        for nic in range(2):
            wait_health(ports[f"http{nic}_15"], console)
        export(console, expected)
        live0, live1 = (LiveTraffic(nic, ports, console) for nic in range(2))
        workers.extend((live0, live1))
        progress(console, live0, live1)

        # Replaying a canonical export is a no-op, including established streams.
        apply(console, expected)
        export(console, expected)
        progress(console, live0, live1)
        # PCI alone selects the same existing adapter, without changing focus.
        apply(console, [{"PCI": BDFS[1], "Echo": True}])
        export(console, expected)
        selected_status(console, 0, 15, "on")
        progress(console, live0, live1)

        # Each batch begins with a valid mutation. An invalid later entry must
        # leave both configurations and their original TCP streams unchanged.
        valid_first = {"Interface": "eth0", "IPv4": "10.0.2.16/24"}
        invalid_entries = (
            {"Interface": "eth1", "IPv4": "IPv4"},
            {"Interface": "eth1", "Prefix": 33},
            {"Interface": "eth1", "Gateway": "192.0.2.1"},
            {"Interface": "eth1", "Echo": "false"},
            {"Interface": "eth1", "Enabled": 1},
            {"Interface": "eth1", "MTU": 1500},
            {"Interface": "eth2", "Enabled": True},
            {"Interface": "eth1"},
            {"IPv4": "10.0.2.16/24"},
            {"Interface": "eth0", "Echo": False},
            {"Interface": "eth1", "PCI": BDFS[0], "Echo": False},
            {"PCI": "0000:00:04.0", "Echo": False},
            {"PCI": "0001:00:03.0", "Echo": False},
            {"PCI": "00:03.0", "Echo": False},
            {"PCI": BDFS[0], "Echo": False},
            {"Interface": "eth1", "MAC": MACS[0]},
        )
        invalid_commands = [wire([valid_first, entry]) for entry in invalid_entries]
        for mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "53:54:00:12:34:67",
                    "52-54-00-12-34-67", "52:54:00:12:34:6", "52:54:00:12:34:gg", None):
            invalid_commands.append(wire([valid_first, {"Interface": "eth1", "MAC": mac}]))
        invalid_commands += [
            wire([{"PCI": BDFS[1], "MAC": MACS[0]}]),
            b'setup {"system":[{"Interface":"eth0","Echo":false,"Echo":true}]}',
            b'setup {"system":[{"Interface":"eth0","Echo":false}],"system":[]}',
            wire([valid_first]) + b" trailing",
            wire([valid_first])[:-1],
            b'setup {"system":[]}',
            b'setup {"system":[{"Interface":"eth0","Echo":false}],"unknown":true}',
        ]
        for command in invalid_commands:
            reject(console, command)
            export(console, expected)
            progress(console, live0, live1)

        # A valid command padded beyond the exact input bound must be discarded
        # entirely, rather than applying its valid prefix after truncation.
        overlong = wire([valid_first])
        overlong += b" " * (LINE_CAPACITY + 1 - len(overlong))
        output = console.command(overlong + b"\r")
        if b"line too long" not in output.lower():
            raise RuntimeError(f"overlong setup line was not rejected: {output!r}")
        export(console, expected)
        progress(console, live0, live1)

        live1.close()
        workers.remove(live1)
        # A bare address preserves the current prefix; omitted fields preserve
        # this interface's current values, independently of console selection.
        apply(console, [{"PCI": BDFS[1], "MAC": CHANGED_MAC.upper(),
                         "IPv4": "10.0.2.16"}])
        expected[1] = configuration(1, ip=16, mac=CHANGED_MAC)
        export(console, expected)
        wait_health(ports["http1_16"], console)
        binary_echo(ports["echo1_16"], console)
        require_silent(ports["http1_15"], REQUEST, console, "eth1's old address")
        progress(console, live0)
        # The host has now cached the first custom MAC. A MAC-only update must
        # refresh that mapping so the same forwarded IP serves HTTP and echo.
        apply(console, [{"PCI": BDFS[1], "MAC": FINAL_MAC}])
        expected[1]["MAC"] = FINAL_MAC
        export(console, expected)
        wait_health(ports["http1_16"], console)
        binary_echo(ports["echo1_16"], console)
        progress(console, live0)
        apply(console, [{"Interface": "eth1", "Echo": False}])
        expected[1]["Echo"] = False
        export(console, expected)
        wait_health(ports["http1_16"], console)
        require_silent(ports["echo1_16"], b"disabled echo", console, "eth1 echo")
        progress(console, live0)
        selected_status(console, 0, 15, "on")
        apply(console, [{"Interface": "eth1", "Prefix": 25, "Gateway": None}])
        expected[1] = configuration(1, ip=16, prefix=25, gateway="none", echo=False, mac=FINAL_MAC)
        export(console, expected)
        wait_health(ports["http1_16"], console)
        progress(console, live0)
        apply(console, [{"Interface": "eth1", "Enabled": False}])
        expected[1]["Enabled"] = False
        export(console, expected)
        require_silent(ports["http1_16"], REQUEST, console, "disabled eth1")
        progress(console, live0)
        apply(console, [{"Interface": "eth1", "Enabled": True}])
        expected[1]["Enabled"] = True
        export(console, expected)
        wait_health(ports["http1_16"], console)
        progress(console, live0)
        # The existing selected-interface commands also preserve a custom MAC.
        nic_action(console, b"nic select eth1")
        nic_action(console, b"nic set 10.0.2.16/25 none echo off")
        export(console, expected)
        wait_health(ports["http1_16"], console)
        nic_action(console, b"nic down")
        expected[1]["Enabled"] = False
        export(console, expected)
        nic_action(console, b"nic up")
        expected[1]["Enabled"] = True
        export(console, expected)
        wait_health(ports["http1_16"], console)
        nic_action(console, b"nic select eth0")
        selected_status(console, 0, 15, "on")
        progress(console, live0)
        live0.close()
        workers.remove(live0)

        # Apply both interfaces with different echo/admin states, then bring up
        # the second independently. Both new-IP HTTP forwards must work.
        batch = [configuration(0, ip=16, echo=False),
                 configuration(1, ip=16, gateway="none", enabled=False, mac=FINAL_MAC)]
        apply(console, batch)
        export(console, batch)
        wait_health(ports["http0_16"], console)
        require_silent(ports["http0_15"], REQUEST, console, "eth0's old address")
        require_silent(ports["echo0_16"], b"disabled echo", console, "eth0 echo")
        require_silent(ports["http1_16"], REQUEST, console, "batch-disabled eth1")
        apply(console, [{"Interface": "eth1", "Enabled": True}])
        batch[1]["Enabled"] = True
        export(console, batch)
        wait_health(ports["http0_16"], console)
        wait_health(ports["http1_16"], console)
        binary_echo(ports["echo1_16"], console)
        # Final-state uniqueness allows a coordinated swap while both adapters
        # are down. Restore before restarting to avoid stale host ARP caches.
        apply(console, [{"Interface": f"eth{nic}", "Enabled": False} for nic in range(2)])
        for entry in batch:
            entry["Enabled"] = False
        export(console, batch)
        swapped = [dict(batch[0], MAC=FINAL_MAC), dict(batch[1], MAC=MACS[0])]
        apply(console, swapped)
        export(console, swapped)
        apply(console, batch)
        export(console, batch)
        for entry in batch:
            entry["Enabled"] = True
        apply(console, batch)
        export(console, batch)
        wait_health(ports["http0_16"], console)
        wait_health(ports["http1_16"], console)
        binary_echo(ports["echo1_16"], console)
        check_guest(process, serial)
        print(f"JSON setup rejected {len(invalid_commands)} malformed/unavailable batches and overlong input without resetting either TCP stream.")
        print(f"Independent eth1 JSON changes preserved eth0's held stream and {live0.rounds} HTTP checks; two-entry setup and export matched both NICs.")
    except BaseException:
        show_logs(serial, stderr)
        raise
    finally:
        for worker in workers:
            worker.stop.set()
        for worker in workers:
            worker.thread.join(timeout=6)
        if console is not None:
            console.close()
        stop_qemu(process)
    verify_changed_mac(root / "eth1.pcap")


def refusal_checks(args, root, deadline):
    process, ports, serial, stderr = launch(args, root, deadline, iommu=False)
    console = None
    try:
        console = Console(ports["console"], process, serial, deadline)
        console.command(b"\x03")
        export(console, [])
        reject(console, wire([{"Interface": "eth0", "Enabled": True}]))
        reject(console, wire([{"PCI": BDFS[0], "Enabled": True, "MAC": CHANGED_MAC}]))
        reject(console, wire([configuration(0), configuration(1)]))
        export(console, [])
        output = check_guest(process, serial)
        if b"CPL=3" in output or HTTP_READY in output:
            raise RuntimeError("setup started a service without IOMMU isolation")
        print("JSON setup cannot enable networking after isolation startup refusal.")
    except BaseException:
        show_logs(serial, stderr)
        raise
    finally:
        if console is not None:
            console.close()
        stop_qemu(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu")
    parser.add_argument("kernel", type=Path)
    parser.add_argument("--timeout", type=positive_timeout, default=240,
                        help="total time limit for both boots (default: 240 seconds)")
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout
    try:
        with tempfile.TemporaryDirectory(prefix="kernel-setup-test-") as directory:
            root = Path(directory)
            normal_checks(args, root, deadline)
            refusal_checks(args, root, deadline)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"JSON setup test failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

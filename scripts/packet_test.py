#!/usr/bin/env python3
"""Test kernel ARP and IPv4/ICMP over QEMU's unprivileged socket network."""

import argparse
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

from network_test import (READY_MARKER, check_process, positive_timeout,
                          remaining, show_logs, stop_qemu)


HOST_MAC = bytes.fromhex("52 54 00 12 34 01")
KERNEL_MAC = bytes.fromhex("52 54 00 12 34 56")
HOST_IP = socket.inet_aton("10.0.2.2")
KERNEL_IP = socket.inet_aton("10.0.2.15")
IDENTIFIER = 0x4B52
INVALID_SEQUENCES = {65000, 65001}
ECHO_COUNT = 130


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(destination: bytes, protocol: int, packet: bytes) -> bytes:
    return (destination + HOST_MAC + struct.pack("!H", protocol) + packet).ljust(60, b"\x00")


def arp(operation: int, target_mac: bytes, target_ip: bytes) -> bytes:
    return (struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation)
            + HOST_MAC + HOST_IP + target_mac + target_ip)


def echo_request(sequence: int, payload: bytes) -> bytes:
    icmp = struct.pack("!BBHHH", 8, 0, 0, IDENTIFIER, sequence) + payload
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), sequence,
                     0, 64, 1, 0, HOST_IP, KERNEL_IP)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ethernet(KERNEL_MAC, 0x0800, ip + icmp)


class PacketStream:
    def __init__(self, connection: socket.socket, deadline: float,
                 process: subprocess.Popen):
        self.connection = connection
        self.deadline = deadline
        self.process = process

    def send(self, frame: bytes) -> None:
        check_process(self.process)
        self.connection.settimeout(remaining(self.deadline))
        # QEMU net/socket.c net_socket_receive: uint32_t htonl(size), then frame.
        # https://raw.githubusercontent.com/qemu/qemu/master/net/socket.c
        self.connection.sendall(struct.pack("!I", len(frame)) + frame)

    def read_exact(self, size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            check_process(self.process)
            self.connection.settimeout(min(0.1, remaining(self.deadline)))
            try:
                data = self.connection.recv(size - len(result))
            except socket.timeout:
                continue
            require(bool(data), "QEMU closed its Ethernet socket unexpectedly")
            result.extend(data)
        return bytes(result)

    def receive(self) -> bytes:
        length, = struct.unpack("!I", self.read_exact(4))
        require(14 <= length <= 65536, f"Invalid Ethernet frame length: {length}")
        return self.read_exact(length)

    def answer_arp(self, frame: bytes) -> None:
        if len(frame) >= 42 and frame[12:14] == b"\x08\x06":
            if frame[20:22] == b"\x00\x01" and frame[38:42] == HOST_IP:
                self.send(ethernet(frame[22:28], 0x0806,
                                   arp(2, frame[22:28], frame[28:32])))


def check_arp(stream: PacketStream) -> None:
    stream.send(ethernet(b"\xff" * 6, 0x0806,
                         arp(1, b"\x00" * 6, KERNEL_IP)))
    while True:
        frame = stream.receive()
        stream.answer_arp(frame)
        if frame[12:14] != b"\x08\x06":
            continue
        require(len(frame) >= 42, "Truncated ARP packet")
        if frame[20:22] != b"\x00\x02":
            continue
        expected = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
                    + KERNEL_MAC + KERNEL_IP + HOST_MAC + HOST_IP)
        require(frame[:12] == HOST_MAC + KERNEL_MAC, "ARP Ethernet MAC addresses differ")
        require(frame[14:42] == expected, "ARP reply addresses or protocol fields differ")
        return


def check_echo(stream: PacketStream, sequence: int, payload: bytes) -> None:
    while True:
        frame = stream.receive()
        stream.answer_arp(frame)
        if frame[12:14] != b"\x08\x00":
            continue
        require(frame[:12] == HOST_MAC + KERNEL_MAC, "IPv4 Ethernet MAC addresses differ")
        ip = frame[14:]
        require(len(ip) >= 20 and ip[0] >> 4 == 4, "Invalid IPv4 header")
        header_length = (ip[0] & 15) * 4
        total_length, = struct.unpack("!H", ip[2:4])
        require(20 <= header_length <= total_length <= len(ip), "Invalid IPv4 packet length")
        require(checksum(ip[:header_length]) == 0, "IPv4 reply header checksum is invalid")
        require(ip[12:20] == KERNEL_IP + HOST_IP, "IPv4 reply addresses differ")
        require(ip[8] > 0, "IPv4 reply TTL is zero")
        fragment, = struct.unpack("!H", ip[6:8])
        require(fragment & 0x3FFF == 0, "Unexpected fragmented IPv4 reply")
        require(ip[9] == 1, f"Expected ICMP, received IPv4 protocol {ip[9]}")
        icmp = ip[header_length:total_length]
        require(len(icmp) >= 8, "Truncated ICMP reply")
        require(checksum(icmp) == 0, "ICMP reply checksum is invalid")
        kind, code, _, identifier, reply_sequence = struct.unpack("!BBHHH", icmp[:8])
        require(kind == 0 and code == 0, f"Expected echo reply, received ICMP {kind}/{code}")
        require(identifier == IDENTIFIER, "ICMP echo identifier differs")
        require(reply_sequence not in INVALID_SEQUENCES,
                f"Kernel answered packet with a bad checksum (sequence {reply_sequence})")
        require(reply_sequence == sequence,
                f"ICMP echo sequence {reply_sequence}, expected {sequence}")
        require(icmp[8:] == payload, f"ICMP echo payload differs for sequence {sequence}")
        return


def run_packet_checks(stream: PacketStream) -> None:
    try:
        check_arp(stream)
    except TimeoutError as error:
        raise TimeoutError(f"waiting for ARP reply: {error}") from error
    print("ARP who-has reply fields and MAC addresses passed.", flush=True)

    # Corrupt one header checksum and one ICMP checksum. A valid echo after
    # these packets is the processing barrier; no arbitrary quiet-time sleep.
    bad_ip = bytearray(echo_request(65000, b"invalid IPv4 checksum"))
    bad_ip[24] ^= 1  # Ethernet header (14) + IPv4 checksum offset (10).
    stream.send(bytes(bad_ip))
    bad_icmp = bytearray(echo_request(65001, b"invalid ICMP checksum"))
    bad_icmp[36] ^= 1  # Ethernet (14) + IPv4 (20) + ICMP checksum offset (2).
    stream.send(bytes(bad_icmp))

    # Include odd lengths and full-MTU packets; 130 replies wrap a 64-entry
    # descriptor ring twice and catch RX recycling and TX reuse failures.
    lengths = (0, 1, 7, 56, 255, 1023, 1472)
    pattern = bytes(range(256)) * 6
    for sequence in range(ECHO_COUNT):
        length = lengths[sequence % len(lengths)]
        payload = bytes((byte + sequence) % 256 for byte in pattern[:length])
        try:
            stream.send(echo_request(sequence, payload))
            check_echo(stream, sequence, payload)
        except TimeoutError as error:
            raise TimeoutError(
                f"waiting for ICMP echo reply {sequence}/{ECHO_COUNT - 1} "
                f"({len(payload)} payload bytes): {error}"
            ) from error
    print(f"IPv4/ICMP echo, payloads, checksums, and ring reuse passed ({ECHO_COUNT} packets).")
    print("Malformed IPv4 and ICMP checksum rejection passed.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu", help="QEMU executable name or path")
    parser.add_argument("kernel", type=Path, help="normal kernel binary to boot")
    parser.add_argument("--timeout", type=positive_timeout, default=30.0,
                        help="total boot and packet time limit in seconds (default: 30)")
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout
    process = None
    with tempfile.TemporaryDirectory(prefix="kernel-packet-test-") as directory:
        serial_path = Path(directory) / "serial.log"
        stderr_path = Path(directory) / "stderr.log"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                port = listener.getsockname()[1]
                command = [
                    args.qemu, "-machine", "pc", "-accel", "tcg", "-m", "128M",
                    "-smp", "1", "-kernel", str(args.kernel), "-display", "none",
                    "-serial", "stdio", "-monitor", "none", "-no-reboot", "-no-shutdown",
                    "-netdev", f"socket,id=net0,connect=127.0.0.1:{port}",
                    "-device", "e1000,netdev=net0,mac=52:54:00:12:34:56",
                ]
                with serial_path.open("wb") as serial, stderr_path.open("wb") as stderr:
                    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                               stdout=serial, stderr=stderr)
                while True:
                    check_process(process)
                    listener.settimeout(min(0.1, remaining(deadline)))
                    try:
                        connection, _ = listener.accept()
                        break
                    except socket.timeout:
                        pass
                with connection:
                    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    while READY_MARKER not in serial_path.read_bytes():
                        check_process(process)
                        time.sleep(min(0.02, remaining(deadline)))
                    run_packet_checks(PacketStream(connection, deadline, process))
                    check_process(process)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            print(f"QEMU packet test failed: {error}", file=sys.stderr)
            stop_qemu(process)
            show_logs(serial_path, stderr_path)
            return 1
        finally:
            stop_qemu(process)
    print("QEMU e1000/ARP/IPv4/ICMP packet test passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

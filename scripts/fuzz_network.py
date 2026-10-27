#!/usr/bin/env python3
"""Seeded HTTP/TCP robustness campaigns against a QEMU instance started here.

There is deliberately no remote target option. All frames go to the private
socket backend of the child QEMU. Replay a run with its seed, mode, and cases.
This is mutation-based testing, not coverage-guided fuzzing.
"""
import argparse
from contextlib import AbstractContextManager
import json
from pathlib import Path
import random
import select
import socket
import struct
import subprocess
import sys
import time

from network_test import check_process, positive_timeout, stop_qemu
from packet_test import HOST_MAC, KERNEL_MAC, KERNEL_IP, checksum, ethernet


def tcp_frame(source: bytes, port: int, destination: int, sequence: int,
              acknowledgement: int, flags: int, payload: bytes = b"",
              options: bytes = b"", window: int = 32768) -> bytes:
    options = options[:40]
    options += b"\x01" * (-len(options) % 4)
    tcp = struct.pack("!HHIIBBHHH", port, destination, sequence & 0xffffffff,
                      acknowledgement & 0xffffffff, ((20 + len(options)) // 4) << 4,
                      flags, window, 0, 0) + options + payload
    pseudo = source + KERNEL_IP + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     source, KERNEL_IP)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ethernet(KERNEL_MAC, 0x0800, ip + tcp)


class Lab(AbstractContextManager):
    def __init__(self, args):
        self.args = args
        self.process = None
        self.connection = None
        self.pending = bytearray()
        self.directory = args.artifacts / f"{args.mode}-{args.seed}-{time.time_ns()}"
        self.directory.mkdir(parents=True)
        self.serial = self.directory / "serial.log"
        self.stderr = self.directory / "stderr.log"
        self.trace = (self.directory / "frames.jsonl").open("w")
        self.started = time.monotonic()
        self.last_input = b""

    def __enter__(self):
        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(10)
                command = [self.args.qemu, "-machine", "q35", "-device", "intel-iommu,intremap=off", "-accel", "tcg", "-cpu", "max,-apic",
                           "-m", "128M", "-smp", "1", "-kernel", str(self.args.kernel),
                           "-display", "none", "-monitor", "none", "-serial", "stdio",
                           "-no-reboot", "-no-shutdown", "-netdev",
                           f"socket,id=net0,connect=127.0.0.1:{listener.getsockname()[1]}",
                           "-device", "e1000,netdev=net0,mac=52:54:00:12:34:56"]
                with self.serial.open("wb") as serial, self.stderr.open("wb") as stderr:
                    self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                                    stdout=serial, stderr=stderr)
                self.connection, _ = listener.accept()
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            deadline = time.monotonic() + 10
            while b"HTTP listening on" not in self.serial.read_bytes():
                self.check()
                if time.monotonic() >= deadline:
                    raise TimeoutError("userspace HTTP readiness deadline")
                time.sleep(0.01)
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def check(self):
        check_process(self.process)
        serial = self.serial.read_bytes()
        for marker in (b"KERNEL PANIC", b"Userspace fault:", b"Userspace panic:",
                       b"Web process stopped", b"Service restart scheduled", b"Networking quarantined",
                       b"Contained NIC DMA fault", b"heartbeat expired", b"RPC deadline expired"):
            if marker in serial:
                raise RuntimeError(f"guest failure marker: {marker!r}")

    def send(self, frame: bytes, label: str = "input"):
        self.check()
        self.last_input = frame
        self.trace.write(json.dumps({"seconds": time.monotonic() - self.started,
                                    "kind": label, "hex": frame.hex()}) + "\n")
        self.trace.flush()
        self.connection.settimeout(3)
        self.connection.sendall(struct.pack("!I", len(frame)) + frame)

    def receive(self, timeout: float):
        deadline = time.monotonic() + timeout
        while True:
            self.check()
            if len(self.pending) >= 4:
                length, = struct.unpack("!I", self.pending[:4])
                if not 14 <= length <= 65536:
                    raise RuntimeError(f"invalid QEMU output length {length}")
                if len(self.pending) >= length + 4:
                    frame = bytes(self.pending[4:length + 4])
                    del self.pending[:length + 4]
                    self.trace.write(json.dumps({"seconds": time.monotonic() - self.started,
                                                "kind": "output", "hex": frame.hex()}) + "\n")
                    if frame[12:14] == b"\x08\x06" and len(frame) >= 42 and frame[20:22] == b"\x00\x01":
                        target = frame[38:42]
                        if target[:3] == b"\x0a\x00\x02" and target != KERNEL_IP:
                            arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
                            arp += HOST_MAC + target + frame[22:28] + frame[28:32]
                            self.send(ethernet(frame[22:28], 0x0806, arp), "arp")
                        continue
                    return frame
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            readable, _, _ = select.select([self.connection], [], [], min(remaining, 0.05))
            if readable:
                data = self.connection.recv(65536)
                if not data:
                    raise RuntimeError("QEMU closed packet backend")
                self.pending.extend(data)

    def __exit__(self, kind, error, traceback):
        stop_qemu(self.process)
        if self.connection:
            self.connection.close()
        self.trace.close()
        if error:
            (self.directory / "last-frame.bin").write_bytes(self.last_input)
            (self.directory / "failure.txt").write_text(str(error) + "\n")
            print(f"Failure artifacts: {self.directory}", file=sys.stderr)
            if self.serial.exists():
                print(self.serial.read_text(errors="replace")[-5000:], file=sys.stderr)
        return False


def decode_tcp(frame: bytes):
    if len(frame) < 54 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], "big")
    if ip[9] != 6 or not 20 <= ihl <= total <= len(ip):
        return None
    tcp = ip[ihl:total]
    if len(tcp) < 20:
        raise RuntimeError("guest emitted short TCP header")
    thl = (tcp[12] >> 4) * 4
    if not 20 <= thl <= len(tcp) or checksum(ip[:ihl]) != 0:
        raise RuntimeError("guest emitted invalid IP/TCP header")
    if checksum(ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp)) + tcp) != 0:
        raise RuntimeError("guest emitted invalid TCP checksum")
    return (ip[16:20], int.from_bytes(tcp[2:4], "big"),
            int.from_bytes(tcp[4:8], "big"), int.from_bytes(tcp[8:12], "big"),
            tcp[13], tcp[thl:])


class Client:
    def __init__(self, lab, rng, source=2, destination=80):
        self.lab = lab
        self.source = bytes((10, 0, 2, source))
        self.port = rng.randrange(20000, 65000)
        self.destination = destination
        self.sequence = rng.getrandbits(32)
        self.ack = 0
        self.initial = self.sequence

    def send(self, flags, data=b"", options=b"", label="tcp"):
        self.lab.send(tcp_frame(self.source, self.port, self.destination, self.sequence,
                               self.ack, flags, data, options), label)
        self.sequence = (self.sequence + len(data) + bool(flags & 2) + bool(flags & 1)) & 0xffffffff

    def receive(self, seconds=2):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            frame = self.lab.receive(max(0.001, deadline - time.monotonic()))
            if frame is None:
                return None
            tcp = decode_tcp(frame)
            if tcp and tcp[:2] == (self.source, self.port):
                return tcp
        return None

    def begin_handshake(self, seconds=2):
        # Keep one tuple/ISN and a fixed total deadline. A SYN sent immediately
        # after other clients' RSTs can precede userspace listener rearming;
        # neighbor discovery can also delay its response. Retransmit the exact
        # segment as TCP does, without consuming another sequence number.
        options = b"\x02\x04\x05\xb4"
        syn = tcp_frame(self.source, self.port, self.destination, self.sequence,
                        self.ack, 2, options=options)
        deadline = time.monotonic() + seconds
        self.send(2, options=options)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("TCP handshake failed: SYN-ACK deadline")
            reply = self.receive(min(0.5, remaining))
            if reply is not None:
                if reply[4] & 0x12 != 0x12 or reply[4] & 4 or reply[3] != self.sequence:
                    raise RuntimeError(f"TCP handshake failed: {reply!r}")
                self.ack = (reply[2] + 1) & 0xffffffff
                return  # Deliberately no ACK: callers may test a half-open socket.
            if time.monotonic() < deadline:
                self.lab.send(syn, "syn-retransmit")

    def open(self):
        self.begin_handshake()
        self.send(16)

    def collect(self, seconds=2, allow_reset=False):
        result = bytearray()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            reply = self.receive(max(0.001, deadline - time.monotonic()))
            if reply is None:
                break
            _, _, sequence, _, flags, data = reply
            if flags & 4:
                if allow_reset:
                    return bytes(result)
                raise RuntimeError("unexpected TCP reset")
            if sequence != self.ack:
                self.send(16)  # Re-ACK retransmissions; never append twice.
                continue
            result.extend(data)
            if len(result) > 65536:
                raise RuntimeError("unbounded response")
            self.ack = (self.ack + len(data) + bool(flags & 1)) & 0xffffffff
            if data or flags & 1:
                self.send(16)
            if flags & 1:
                self.send(0x11)
                return bytes(result)
        if allow_reset:
            return bytes(result)
        raise TimeoutError("TCP response/FIN deadline")

    def reset(self):
        self.send(0x14)


def health(lab, rng):
    # Separate source avoids confusing deliberate per-source admission limits
    # with a service failure during mutated-input runs.
    client = Client(lab, rng, source=200)
    client.open()
    client.send(0x18, b"GET /healthz HTTP/1.1\r\nHost: kernel\r\n\r\n")
    response = client.collect()
    if not response.startswith(b"HTTP/1.1 200 OK\r\n") or not response.endswith(b"\r\n\r\nok\n"):
        raise RuntimeError(f"health response differs: {response[:200]!r}")
    client.reset()
    echo = Client(lab, rng, source=200, destination=1234)
    echo.open()
    payload = rng.randbytes(257)
    echo.send(0x19, payload)
    if echo.collect() != payload:
        raise RuntimeError("binary TCP echo changed after mutated traffic")
    echo.reset()


HTTP_SEEDS = [b"GET /healthz HTTP/1.1\r\nHost: kernel\r\n\r\n",
              b"HEAD / HTTP/1.0\r\n\r\n", b"POST / HTTP/1.1\r\nHost: kernel\r\nContent-Length: 1\r\n\r\nx",
              b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
              b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
              b"GET / HTTP/1.1\r\nHost: a\r\nX: " + b"a" * 2048 + b"\r\n\r\n"]


def mutate(rng, value):
    data = bytearray(value)
    for _ in range(rng.randrange(1, 8)):
        action = rng.randrange(4)
        offset = rng.randrange(len(data) + 1)
        if action == 0 and offset < len(data):
            data[offset] ^= 1 << rng.randrange(8)
        elif action == 1:
            data[offset:offset] = rng.randbytes(rng.randrange(1, 32))
        elif action == 2:
            del data[offset:offset + rng.randrange(1, 32)]
        else:
            data[offset:offset] = rng.choice([b"\r\n", b"\x00", b"\xff", b"Content-Length: 0\r\n"])
    return bytes(data[:4096])


def http_case(lab, rng, index):
    client = Client(lab, rng, source=2 + index % 8)
    client.open()
    request = mutate(rng, rng.choice(HTTP_SEEDS))
    (lab.directory / "last-http.bin").write_bytes(request)
    position = 0
    while position < len(request):
        size = rng.randrange(1, 300)
        client.send(0x18, request[position:position + size], label="http-mutation")
        position += size
    client.send(0x11)  # Incomplete headers must reach the EOF/error path too.
    response = client.collect(1.0, allow_reset=True)
    if response:
        header, separator, body = response.partition(b"\r\n\r\n")
        if not separator or not header.startswith(b"HTTP/1.1 "):
            raise RuntimeError(f"malformed response to case {index}: {response[:200]!r}")
        status = int(header.split(b" ", 2)[1])
        if status not in (200, 400, 404, 405, 431):
            raise RuntimeError(f"unexpected response status {status}")
        lengths = [line.split(b":", 1)[1].strip() for line in header.split(b"\r\n")
                   if line.lower().startswith(b"content-length:")]
        if len(lengths) != 1 or (not request.startswith(b"HEAD ") and int(lengths[0]) != len(body)):
            raise RuntimeError("response body framing mismatch")
        if len(body) > 2048:
            raise RuntimeError("response unexpectedly large")
    client.reset()


def tcp_case(lab, rng, index):
    # Some cases start established, ensuring checksums/handshake do not keep
    # all mutations outside the TCP state machine. Others exercise listeners.
    client = Client(lab, rng, source=2 + index % 8, destination=1234)
    established = index % 4 == 0
    if established:
        client.open()
    reset_sequences = {client.sequence}
    for packet in range(8):
        flags = rng.choice([2, 0x10, 0x18, 0x11, 4, 0, 0xff, 0x12, 0x22])
        sequence = client.sequence if packet % 2 == 0 else rng.getrandbits(32)
        acknowledgement = client.ack if packet % 3 else rng.getrandbits(32)
        frame = bytearray(tcp_frame(client.source, client.port, 1234, sequence,
                                   acknowledgement, flags, rng.randbytes(rng.randrange(0, 256)),
                                   options=rng.randbytes(rng.randrange(0, 40)),
                                   window=rng.randrange(65536)))
        variant = rng.randrange(5)
        if variant == 0:
            frame = bytearray(mutate(rng, frame))
        elif variant == 1:
            frame = frame[:rng.randrange(14, len(frame) + 1)]
        elif variant == 2:
            frame[20:22] = struct.pack("!H", rng.choice([1, 0x2000, 0x3fff]))
            frame[24:26] = b"\x00\x00"
            frame[24:26] = struct.pack("!H", checksum(bytes(frame[14:34])))
        # Variants3/4 retain correct checksums and malformed TCP options/flags.
        # Record possible RCV.NXT values before injection. A valid SYN can
        # create a half-open socket even if its SYN-ACK is delayed; resetting
        # with the pre-SYN sequence would correctly be rejected by TCP.
        reset_sequences.add(sequence)
        reset_sequences.add((sequence + 1) & 0xffffffff)
        reset_sequences.add((sequence + len(frame) - 54) & 0xffffffff)
        lab.send(bytes(frame), "tcp-mutation")
        for _ in range(4):
            reply_frame = lab.receive(0.002)
            if reply_frame is None:
                break
            reply = decode_tcp(reply_frame)
            if reply and reply[:2] == (client.source, client.port) and reply[4] & 16 and not reply[4] & 4:
                client.sequence = reply[3]
                client.ack = (reply[2] + len(reply[5]) + bool(reply[4] & 3)) & 0xffffffff
    # Correct tuple reset restores the echo listener, even after hostile state.
    client.reset()
    for sequence in sorted(reset_sequences):
        lab.send(tcp_frame(client.source, client.port, 1234, sequence, client.ack, 0x14), "cleanup-reset")
    for _ in range(16):
        reply_frame = lab.receive(0.01)
        if reply_frame is None:
            break
        reply = decode_tcp(reply_frame)
        # A challenge ACK supplies RCV.NXT for a corrected reset. A RST|ACK
        # response merely acknowledges a rejected input, so never use its ACK
        # as the sequence of an established connection.
        if reply and reply[:2] == (client.source, client.port) and reply[4] & 16 and not reply[4] & 4:
            client.sequence = reply[3]
            client.ack = (reply[2] + len(reply[5]) + bool(reply[4] & 3)) & 0xffffffff
            client.reset()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu")
    parser.add_argument("kernel", type=Path)
    parser.add_argument("--mode", choices=["http", "tcp"], default="http")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--seconds", type=positive_timeout, default=30)
    parser.add_argument("--cases", type=int, default=0, help="exact case count instead of duration")
    parser.add_argument("--artifacts", type=Path, default=Path("build/fuzz"))
    args = parser.parse_args()
    if args.cases < 0:
        parser.error("cases must be nonnegative")
    rng = random.Random(args.seed)
    lab = Lab(args)
    completed = 0
    succeeded = False
    start = time.monotonic()
    try:
        with lab:
            health(lab, rng)
            end = time.monotonic() + args.seconds
            while completed < args.cases if args.cases else time.monotonic() < end:
                case_started = time.monotonic()
                (http_case if args.mode == "http" else tcp_case)(lab, rng, completed)
                completed += 1
                # Exercise protocol parsing below the intentional SYN rate
                # limit; admission overload has a separate regression test.
                time.sleep(max(0, 0.05 - (time.monotonic() - case_started)))
                if completed % 8 == 0:
                    health(lab, rng)
                    print(f"{args.mode}: seed={args.seed} cases={completed}", flush=True)
            health(lab, rng)
            succeeded = True
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"{args.mode} campaign failed at case {completed}: {error}", file=sys.stderr)
    finally:
        summary = {"mode": args.mode, "seed": args.seed, "cases": completed,
                   "passed": succeeded, "seconds": round(time.monotonic() - start, 3),
                   "replay_cases": completed if succeeded else completed + 1}
        (lab.directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Artifacts: {lab.directory}", flush=True)
    return 0 if succeeded else 1


if __name__ == "__main__":
    sys.exit(main())

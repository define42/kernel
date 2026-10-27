#!/usr/bin/env python3
"""Check custom IPv4, disabled echo, and fail-closed CPU RNG in private QEMU."""

import argparse
from contextlib import ExitStack
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from http_test import REQUEST, read_response, validate
from network_test import check_process, remaining, show_logs, stop_qemu


def boot(args, root, *, entropy):
    serial = root / ("ready.log" if entropy else "no-entropy.log")
    stderr = serial.with_suffix(".err")
    with ExitStack() as stack:
        ports = []
        for _ in range(2):
            reservation = stack.enter_context(socket.socket())
            reservation.bind(("127.0.0.1", 0))
            ports.append(reservation.getsockname()[1])
        http, echo = ports
    command = [
        args.qemu, "-machine", "q35", "-device", "intel-iommu,intremap=off",
        "-accel", "tcg", "-cpu", "max,-apic" + ("" if entropy else ",-rdrand,-rdseed"),
        "-m", "128M", "-smp", "1", "-kernel", str(args.kernel),
        "-display", "none", "-serial", "stdio", "-monitor", "none",
        "-no-reboot", "-no-shutdown", "-device", "e1000,netdev=net0",
        "-netdev", "user,id=net0,net=10.77.0.0/24,"
        f"hostfwd=tcp:127.0.0.1:{http}-10.77.0.15:80,"
        f"hostfwd=tcp:127.0.0.1:{echo}-10.77.0.15:1234",
    ]
    with serial.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
    deadline = time.monotonic() + 20
    try:
        marker = b"HTTP listening on port 80" if entropy else b"Hardware entropy unavailable; refusing network startup."
        while marker not in serial.read_bytes():
            check_process(process)
            if b"KERNEL PANIC" in serial.read_bytes():
                raise RuntimeError("kernel panicked")
            time.sleep(min(0.02, remaining(deadline)))
        if not entropy:
            time.sleep(0.2)
            if b"CPL=3" in serial.read_bytes():
                raise RuntimeError("service started without CPU RNG")
            print("Missing hardware RNG: network startup refused.")
            return
        with socket.create_connection(("127.0.0.1", http), remaining(deadline)) as client:
            client.sendall(REQUEST)
            validate(read_response(client, deadline, process), 200, body=b"ok\n")
        output = serial.read_bytes()
        if b"IPv4: 10.77.0.15/24, gateway 10.77.0.2" not in output:
            raise RuntimeError("configured address/gateway not used")
        if b"TCP echo listening" in output:
            raise RuntimeError("disabled echo listener started")
        try:
            with socket.create_connection(("127.0.0.1", echo), 1) as client:
                client.settimeout(1)
                client.sendall(b"echo must be disabled")
                data = client.recv(64)
                if data:
                    raise RuntimeError("disabled echo service returned data")
        except (ConnectionError, TimeoutError):
            pass
        print("Custom subnet HTTP works; echo is disabled.")
    except BaseException:
        show_logs(serial, stderr)
        raise
    finally:
        stop_qemu(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu")
    parser.add_argument("kernel", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="kernel-deployment-") as directory:
        boot(args, Path(directory), entropy=True)
        boot(args, Path(directory), entropy=False)


if __name__ == "__main__":
    main()

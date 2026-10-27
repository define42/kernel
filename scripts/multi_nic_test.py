#!/usr/bin/env python3
"""Verify simultaneous independent NIC service and console configuration in QEMU."""

import argparse
from contextlib import ExitStack
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

from http_test import REQUEST
from network_test import (connect as echo_connect, exchange as echo_exchange,
                          positive_timeout, remaining, show_logs, stop_qemu)
from serial_test import (Console, HTTP_READY, PROMPT, REFUSAL, binary_echo,
                         check_guest, health, nic_action, require_config,
                         require_help, require_silent, wait_health)


MACS = ("52:54:00:12:34:56", "52:54:00:12:34:57")
BDFS = ("0000:00:02.0", "0000:00:03.0")


def launch(args, root, deadline, *, iommu, capture=False):
    serial = root / ("multi.log" if iommu else "multi-no-iommu.log")
    stderr = serial.with_suffix(".err")
    for attempt in range(3):
        with ExitStack() as reservations:
            ports = {}
            names = ["console"] + [f"{service}{nic}_{ip}" for nic in range(2)
                                   for service in ("http", "echo") for ip in (15, 16)]
            for name in names:
                reserve = reservations.enter_context(socket.socket())
                reserve.bind(("127.0.0.1", 0))
                ports[name] = reserve.getsockname()[1]
        command = [
            args.qemu, "-machine", "q35", "-accel", "tcg", "-cpu", "max,-apic",
            "-m", "128M", "-smp", "1", "-kernel", str(args.kernel),
            "-display", "none", "-monitor", "none", "-no-reboot", "-no-shutdown",
            "-chardev", f"socket,id=com1,host=127.0.0.1,port={ports['console']},"
            f"server=on,wait=off,logfile={serial},logappend=off",
            "-serial", "chardev:com1",
        ]
        control_dir = getattr(args, "control_dir", None)
        if control_dir is not None:
            command += ["-qmp", f"unix:{control_dir}/qmp,server=on,wait=off",
                        "-qtest", f"unix:{control_dir}/qtest,server=on,wait=off",
                        "-qtest-log", "/dev/null"]
        if iommu:
            mode = "on" if getattr(args, "interrupt_remapping", False) else "off"
            command += ["-device", f"intel-iommu,intremap={mode}"]
        for nic in range(2):
            forwards = ",".join(
                f"hostfwd=tcp:127.0.0.1:{ports[f'{service}{nic}_{ip}']}-10.0.2.{ip}:{guest}"
                for service, guest in (("http", 80), ("echo", 1234)) for ip in (15, 16)
            )
            command += [
                "-netdev", f"user,id=net{nic}," + forwards,
                "-device", f"e1000,netdev=net{nic},bus=pcie.0,addr=0x{nic + 2:02x},mac={MACS[nic]}",
            ]
            if capture:
                command += ["-object", f"filter-dump,id=capture{nic},netdev=net{nic},"
                            f"file={root / f'eth{nic}.pcap'}"]
        with stderr.open("wb") as errors:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=errors)
        try:
            while True:
                if process.poll() is not None:
                    message = stderr.read_text(errors="replace")
                    if attempt < 2 and ("Address already in use" in message
                                        or "Could not set up host forwarding rule" in message):
                        break
                output = check_guest(process, serial)
                if PROMPT in output and (HTTP_READY if iommu else REFUSAL) in output:
                    return process, ports, serial, stderr
                time.sleep(min(0.01, remaining(deadline)))
        except BaseException:
            stop_qemu(process)
            show_logs(serial, stderr)
            raise
        stop_qemu(process)
    raise RuntimeError("could not reserve multi-NIC forwarding ports after three attempts")


def selected_status(console, nic, ip, echo, *, state="up", gateway="10.0.2.2"):
    output = console.command(b"nic show\r")
    require_config(output, f"10.0.2.{ip}/24", gateway, echo, state=state)
    if f"Interface: eth{nic}".encode() not in output:
        raise RuntimeError(f"wrong selected NIC: {output!r}")
    if state == "up":
        for field in (f"PCI: {BDFS[nic]}", f"MAC: {MACS[nic]}"):
            if field.encode() not in output:
                raise RuntimeError(f"selected NIC identity is wrong: {output!r}")
    return output


def interface_list(console, *, selected=0, states=("up", "up")):
    output = console.command(b"nic list\r")
    for nic in range(2):
        marker = " selected" if nic == selected else ""
        row = f"eth{nic} {BDFS[nic]} 8086:100e {states[nic]}{marker}\r\n".encode()
        if row not in output:
            raise RuntimeError(f"NIC list omitted eth{nic}'s identity/state/selection: {output!r}")
    if re.search(rb"\beth[2-7]\b", output):
        raise RuntimeError(f"NIC list invented an extra adapter: {output!r}")


class LiveTraffic:
    """Keep one TCP stream open while repeatedly checking the same NIC's HTTP."""

    def __init__(self, nic, ports, console):
        self.nic, self.ports, self.console = nic, ports, console
        self.stop = threading.Event()
        self.failures = []
        self.rounds = 0
        self.thread = threading.Thread(target=self.run, name=f"eth{nic}-traffic")
        self.thread.start()

    def run(self):
        try:
            deadline = min(self.console.deadline, time.monotonic() + 5)
            with echo_connect(self.ports[f"echo{self.nic}_15"], deadline) as connection:
                while not self.stop.is_set():
                    deadline = min(self.console.deadline, time.monotonic() + 5)
                    payload = (f"eth{self.nic} stream {self.rounds}:".encode()
                               + bytes(range(256)) * 3)
                    echo_exchange(connection, payload, deadline, self.console.process,
                                  half_close=False)
                    health(self.ports[f"http{self.nic}_15"], deadline, self.console.process)
                    self.rounds += 1
                    self.stop.wait(0.1)  # Stay below the per-source 16/s SYN allowance.
                deadline = min(self.console.deadline, time.monotonic() + 5)
                echo_exchange(connection, b"finish held stream", deadline,
                              self.console.process, half_close=True)
        except (OSError, RuntimeError) as error:
            self.failures.append(error)

    def check(self):
        if self.failures:
            raise RuntimeError(f"eth{self.nic} established stream/HTTP failed: {self.failures[0]}")

    def close(self):
        self.stop.set()
        self.thread.join(timeout=6)
        if self.thread.is_alive():
            raise RuntimeError(f"eth{self.nic} traffic worker did not stop")
        self.check()


def progress(console, *workers):
    before = [worker.rounds for worker in workers]
    deadline = min(console.deadline, time.monotonic() + 6)
    while True:
        check_guest(console.process, console.serial)
        for worker in workers:
            worker.check()
        if all(worker.rounds > count for worker, count in zip(workers, before)):
            return
        time.sleep(min(0.02, remaining(deadline)))


def rejected(console, command):
    output = console.command(command + b"\r")
    if b"NIC error:" not in output:
        raise RuntimeError(f"invalid/unavailable NIC action was accepted: {output!r}")


def normal_checks(args, root, deadline):
    process, ports, serial, stderr = launch(args, root, deadline, iommu=True)
    console = None
    workers = []
    try:
        console = Console(ports["console"], process, serial, deadline)
        console.command(b"\x03")
        for nic in range(2):
            wait_health(ports[f"http{nic}_15"], console)
            binary_echo(ports[f"echo{nic}_15"], console)
        interface_list(console)
        selected_status(console, 0, 15, "on")
        live0, live1 = (LiveTraffic(nic, ports, console) for nic in range(2))
        workers.extend((live0, live1))
        progress(console, live0, live1)

        # Both TCP streams remain established throughout admin-focus switches.
        # Reconnecting per command would miss an implementation that resets NICs.
        for nic in (1, 0, 1, 0):
            nic_action(console, f"nic select eth{nic}".encode())
            selected_status(console, nic, 15, "on")
            interface_list(console, selected=nic)
            progress(console, live0, live1)
        for invalid in (b"nic select eth2", b"nic select eth8", b"nic select eth01",
                        b"nic select unknown", b"nic select eth1 extra"):
            rejected(console, invalid)
            selected_status(console, 0, 15, "on")
            progress(console, live0, live1)
        live1.close()
        workers.remove(live1)

        # Reconfigure only eth1 while eth0's original stream keeps exchanging.
        nic_action(console, b"nic select eth1")
        nic_action(console, b"nic set 10.0.2.16/24 none echo off")
        wait_health(ports["http1_16"], console)
        selected_status(console, 1, 16, "off", gateway="none")
        require_silent(ports["http1_15"], REQUEST, console, "eth1's previous IP")
        require_silent(ports["echo1_16"], b"disabled echo", console, "eth1 echo")
        progress(console, live0)
        rejected(console, b"nic select eth2")
        selected_status(console, 1, 16, "off", gateway="none")
        health(ports["http1_16"], deadline, process)

        nic_action(console, b"nic down")
        selected_status(console, 1, 16, "off", state="down", gateway="none")
        interface_list(console, selected=1, states=("up", "down"))
        require_silent(ports["http1_16"], REQUEST, console, "administratively stopped eth1")
        progress(console, live0)
        nic_action(console, b"nic select eth0")
        selected_status(console, 0, 15, "on")
        interface_list(console, states=("up", "down"))
        progress(console, live0)

        # Editing a down NIC preserves its own down state across selection.
        nic_action(console, b"nic select eth1")
        nic_action(console, b"nic set 10.0.2.15/24 10.0.2.2")
        selected_status(console, 1, 15, "off", state="down")
        require_silent(ports["http1_15"], REQUEST, console, "reconfigured but still stopped eth1")
        nic_action(console, b"nic up")
        wait_health(ports["http1_15"], console)
        selected_status(console, 1, 15, "off")
        require_silent(ports["echo1_15"], b"still disabled", console, "saved eth1 echo setting")
        progress(console, live0)
        nic_action(console, b"nic set 10.0.2.15/24 10.0.2.2 echo on")
        wait_health(ports["http1_15"], console)
        live1 = LiveTraffic(1, ports, console)
        workers.append(live1)
        progress(console, live0, live1)
        interface_list(console, selected=1)
        require_help(console.command(b"help\r"))
        progress(console, live0, live1)
        for worker in workers:
            worker.close()
        workers.clear()
        check_guest(process, serial)
        print("Two NICs served HTTP/echo simultaneously; console selection preserved both held TCP streams.")
        print(f"Independent eth1 configuration/down/up preserved eth0's original stream and {live0.rounds} HTTP checks.")
    except BaseException:
        show_logs(serial, stderr)
        raise
    finally:
        # Request shutdown together; each worker has a bounded I/O deadline.
        for worker in workers:
            worker.stop.set()
        for worker in workers:
            worker.thread.join(timeout=6)
        if console is not None:
            console.close()
        stop_qemu(process)


def refusal_checks(args, root, deadline):
    process, ports, serial, stderr = launch(args, root, deadline, iommu=False)
    console = None
    try:
        console = Console(ports["console"], process, serial, deadline)
        console.command(b"\x03")
        for command in (b"nic select eth1", b"nic up", b"nic set 10.0.2.16/24 none echo off"):
            rejected(console, command)
            output = console.command(b"nic show\r")
            require_config(output, "10.0.2.15/24", "10.0.2.2", "on", state="unavailable")
        require_help(console.command(b"help\r"))
        output = check_guest(process, serial)
        if b"CPL=3" in output or HTTP_READY in output:
            raise RuntimeError("NIC selection started a service without isolation")
        print("Two-NIC selection cannot bypass unavailable IOMMU isolation.")
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
    parser.add_argument("--timeout", type=positive_timeout, default=90,
                        help="total time limit for both boots (default: 90 seconds)")
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout
    try:
        with tempfile.TemporaryDirectory(prefix="kernel-multi-nic-test-") as directory:
            root = Path(directory)
            normal_checks(args, root, deadline)
            refusal_checks(args, root, deadline)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Multi-NIC test failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Attach a POSIX terminal to QEMU's raw localhost COM1 socket (Ctrl-] detaches)."""

import argparse
import os
import select
import signal
import socket
import sys
import termios
import time
import tty


SEND_CHUNK = 4
SEND_INTERVAL = 0.01
MAX_PENDING = 8192
DETACH = b"\x1d"


def port_number(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


class Interrupted(Exception):
    def __init__(self, signum: int):
        self.signum = signum


def interrupted(signum, _frame):
    raise Interrupted(signum)


def terminal(connection: socket.socket) -> str:
    descriptor = sys.stdin.fileno()
    attributes = termios.tcgetattr(descriptor)
    handlers = {}
    pending = bytearray()
    next_send = 0.0
    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            handlers[signum] = signal.signal(signum, interrupted)
        tty.setraw(descriptor, when=termios.TCSANOW)
        connection.setblocking(False)
        while True:
            now = time.monotonic()
            # Always watch terminal input so Ctrl-] also detaches during a paste.
            readers = [connection, descriptor]
            writers = [connection] if pending and now >= next_send else []
            timeout = max(0.0, next_send - now) if pending and not writers else None
            readable, writable, _ = select.select(readers, writers, [], timeout)
            if connection in readable:
                try:
                    data = connection.recv(4096)
                except BlockingIOError:
                    data = None
                if data == b"":
                    return "Serial connection closed."
                if data:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
            if descriptor in readable:
                data = os.read(descriptor, 1024)
                if not data:
                    return "Console input closed."
                if DETACH in data:
                    return "Detached; QEMU is still running."
                if len(pending) + len(data) > MAX_PENDING:
                    raise RuntimeError("paste exceeded the 8 KiB input queue; reconnect and press Ctrl-C")
                pending.extend(data)
            if connection in writable and pending:
                try:
                    sent = connection.send(pending[:SEND_CHUNK])
                except BlockingIOError:
                    sent = 0
                if sent:
                    del pending[:sent]
                    # A paste must not overrun the guest's small UART FIFO.
                    next_send = time.monotonic() + SEND_INTERVAL
    finally:
        try:
            termios.tcsetattr(descriptor, termios.TCSANOW, attributes)
        finally:
            for signum, handler in handlers.items():
                signal.signal(signum, handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=port_number, default=4444,
                        help="localhost serial port (default: 4444)")
    args = parser.parse_args()
    if not sys.stdin.isatty():
        parser.error("an interactive terminal is required")
    try:
        with socket.create_connection(("127.0.0.1", args.port), timeout=5) as connection:
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            print(f"Connected to 127.0.0.1:{args.port}. Ctrl-] detaches; Ctrl-C goes to the guest.",
                  file=sys.stderr, flush=True)
            message = terminal(connection)
        print(f"\n{message}", file=sys.stderr)
        return 0
    except Interrupted as error:
        print("\nConsole interrupted; terminal restored.", file=sys.stderr)
        return 128 + error.signum
    except (OSError, RuntimeError, termios.error) as error:
        print(f"\nSerial console: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

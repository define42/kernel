#!/usr/bin/env python3
"""Verify connection quotas and recovery using isolated QEMU Ethernet clients."""
import argparse
from pathlib import Path
import random
import sys
import time
from fuzz_network import Lab, Client, health


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu")
    parser.add_argument("kernel", type=Path)
    args = parser.parse_args()
    args.mode, args.seed, args.artifacts = "abuse", 42, Path("build/test-artifacts")
    rng = random.Random(args.seed)
    try:
        with Lab(args) as lab:
            clients = [Client(lab, rng) for _ in range(3)]
            for client in clients:
                client.open()
                client.send(0x18, b"GET / HTTP/1.1\r\nHost: ")
            fourth = Client(lab, rng)
            fourth.send(2)
            if fourth.receive(0.2) is not None:
                raise RuntimeError("fourth connection from one IP was admitted")
            health(lab, rng)
            print("Three same-source clients cannot consume another source's reserved slot.")
            for client in clients:
                client.reset()
            # Half-open clients cannot hold slots indefinitely even without
            # completing a TCP handshake or running application request logic.
            half_open = [Client(lab, rng, source=3) for _ in range(3)]
            for client in half_open:
                client.send(2)
                reply = client.receive()
                if reply is None or reply[4] & 0x12 != 0x12:
                    raise RuntimeError("half-open setup failed")
                client.ack = (reply[2] + 1) & 0xffffffff
            deadline = time.monotonic() + 3.3
            while time.monotonic() < deadline:
                lab.receive(min(0.05, deadline - time.monotonic()))
            recovered = Client(lab, rng, source=3)
            recovered.open()
            recovered.reset()
            health(lab, rng)
            print("Half-open connection deadline and subsequent HTTP/TCP recovery passed.")
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Connection control test failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

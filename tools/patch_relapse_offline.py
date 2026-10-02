#!/usr/bin/env python3
"""Offline KASLR fallback for the relapse exploit copy.

Relapse's leakKernelBase() aborts with "kaslr: no interface has an address"
when no interface has an IPv4 address (Wi-Fi off, no cable). The routing
socket only needs a destination that has a route: the loopback address
always does, even with no NIC configured, and nothing is ever sent.

The payload side (src/net_offline.c) normally configures a synthetic
interface before the browser opens; this patch adds a last-resort fallback
so the chain still proceeds when that was not possible.

Idempotent: exits 0 when the fallback is already present, 1 when the
upstream code changed and could not be patched.
"""
import pathlib
import sys

OLD = """    const dst = await this.firstInterfaceAddress();
    if (!dst) throw new Error("kaslr: no interface has an address");"""

NEW = """    let dst = await this.firstInterfaceAddress();
    if (!dst) dst = [127, 0, 0, 1]; // offline fallback: lo0 always has a route even with no NIC configured
    if (!dst) throw new Error("kaslr: no interface has an address");"""


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <relapse-copy>", file=sys.stderr)
        return 2
    target = pathlib.Path(sys.argv[1]) / "src" / "relapse_exploit.js"
    if not target.is_file():
        print(f"error: {target} not found", file=sys.stderr)
        return 2
    text = target.read_text(encoding="utf-8").replace("\r\n", "\n")
    if OLD not in text:
        if NEW in text:
            print("relapse: offline KASLR fallback already applied.")
            return 0
        print("error: firstInterfaceAddress call not found — exploit changed upstream?",
              file=sys.stderr)
        return 1
    target.write_text(text.replace(OLD, NEW, 1), encoding="utf-8", newline="\n")
    print("relapse: offline KASLR fallback applied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

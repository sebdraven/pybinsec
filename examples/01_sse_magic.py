"""End-to-end example: build an SSE script and run it on a binary.

Reproduces (in spirit) the Binsec ``magic`` tutorial from
https://binsec.github.io/sse/quickstart.html.

Prerequisites:
    - ``binsec`` available (on PATH or via PYBINSEC_BINARY)
    - the ``magic`` binary from binsec/binsec/examples/sse/quickstart

Usage:
    python examples/01_sse_magic.py /path/to/magic
"""

from __future__ import annotations

import sys

from pybinsec import Binsec, ScriptBuilder, SSERunner
from pybinsec.sse import BinOp, Reg


def main(binary_path: str) -> int:
    bs = Binsec()
    print(f"[+] Using {bs.path} ({bs.info.version})")

    script = (
        ScriptBuilder()
        .starting_from(0x804805C)
        .reach(
            0x8048071,
            such_that=BinOp(Reg("al"), "<>", 0),
            then="print @[esp + 4, 4]",
        )
        .build()
    )

    print("[+] SSE script:")
    for line in script.to_sse().splitlines():
        print(f"      {line}")

    runner = SSERunner(bs)
    result = runner.run(script, binary_path, timeout=60)

    print(f"[+] Exit code: {result.returncode}")
    print(f"[+] Reached:   {len(result.reached)} point(s)")
    for rp in result.reached:
        print(f"      path {rp.path_id} at 0x{rp.address:x}")
        for k, v in rp.values.items():
            print(f"        {k} = 0x{v:x}")
    print(f"[+] Cuts:      {len(result.cuts)}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <binary>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))

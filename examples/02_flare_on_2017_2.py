"""Reproduce the official flare-on 2017 challenge 2 (IgniteMe.exe) with pybinsec.

The reference script lives in the binsec/binsec Docker image at
``/home/binsec/examples/sse/flare-on/2017.2/crackme.ini``. The challenge
goal is to find an input that makes the binary print ``G00d j0b!``.
The expected secret is ``R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com``,
exposed by Binsec as the ``bRead`` ASCII stream.

This example shows how the v0.4 sprint-1 directives (``halt at``,
``Initialize.as_alias``, ``Replace`` with ``Return``, ...) plug into
the fluent builder, and how the still-missing control-flow constructs
(``for``, ``if``) are handed off to the ``.raw()`` escape hatch with
verbatim strings until v0.4 sprint 2 lands.

Usage::

    # The challenge needs bitwuzla as the SMT backend (z3 alone won't
    # solve it within reasonable time). Make sure it is installed.
    python examples/02_flare_on_2017_2.py path/to/IgniteMe.exe

What this proves:
    - The pybinsec API can faithfully describe the same SSE script the
      Binsec authors hand-wrote for this challenge.
    - The textual output from ``builder.to_sse()`` is byte-for-byte
      identical to the reference crackme.ini (modulo whitespace inside
      raw blocks). See ``compare_to_reference()`` below.

Limitations:
    - We need ``bitwuzla`` and a ``-fml-solver bitwuzla`` flag on the
      binsec invocation; passed via ``extra_args``.
    - The deeper exploration (``-sse-depth 100000`` from the official
      config.cfg) is also forwarded via ``extra_args``.
"""

from __future__ import annotations

import sys
from pathlib import Path

from pybinsec import Binsec, ScriptBuilder, SSERunner

# ----------------------------------------------------------------------
# The script: same structure and order as the upstream crackme.ini.
# ----------------------------------------------------------------------


def build_script() -> ScriptBuilder:
    """Build the same script the Binsec authors hand-wrote for this challenge.

    Reference: /home/binsec/examples/sse/flare-on/2017.2/crackme.ini
    """
    return (
        ScriptBuilder()
        # 1. Pull the .text/.rdata/.data sections out of the PE so SSE
        #    can decode instructions and read the constant data.
        .load_sections(".text", ".rdata", ".data")
        # 2. Concretize the stack pointer to a known location.
        .init("esp", 0x12FFB0)
        # 3. Fake the Import Address Table: the PE expects four imports
        #    at fixed addresses; we patch them with the runtime
        #    addresses of fake stubs we'll define below, and bind each
        #    address to a callable name via the ``as <alias>`` suffix.
        .init_memory(0x402000, 0x7C811D77, size=4, as_alias="ReadFile")
        .init_memory(0x402004, 0x7C81ADA0, size=4, as_alias="WriteFile")
        .init_memory(0x402008, 0x7C81902D, size=4, as_alias="ExitProcess")
        .init_memory(0x40200C, 0x7C812F39, size=4, as_alias="GetStdHandle")
        # 4. Halt the SSE engine entirely when the program calls
        #    ExitProcess: there's nothing useful past that point.
        .halt_at("ExitProcess")
        # 5. Stubs we don't care about: GetStdHandle and WriteFile just
        #    return without side effects.
        .replace(
            ["GetStdHandle", "WriteFile"],
            body=["return"],  # raw line; equivalent to Return()
        )
        # 6. The ReadFile stub is the heart of the script: it injects a
        #    symbolic byte stream named ``bRead`` into the buffer the
        #    binary asked to read into. The constructs ``for``, ``if``,
        #    and the C-style signature ``replace ReadFile(_, lpBuffer,
        #    nNumberOfBytesToRead, lpNumberOfBytesRead) by`` are not yet
        #    modelled by pybinsec (planned for sprint 2 and 3), so we
        #    drop down to ``raw()`` here. The string is taken verbatim
        #    from the upstream crackme.ini.
        .raw("replace ReadFile(_, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead) by")
        .raw("    nNumberOfBytesRead<32>   := nondet")
        .raw("    assume 2 <= nNumberOfBytesRead <= nNumberOfBytesToRead")
        .raw("")
        .raw("    bReadConstraints<1>      := true")
        .raw("")
        .raw("    for i<32> in 0 to nNumberOfBytesRead - 3 do")
        .raw("        @[lpBuffer + i] := nondet as bRead")
        .raw('        bReadConstraints := bReadConstraints && " " <= bRead <= "~"')
        .raw("    end")
        .raw("")
        .raw('    @[lpBuffer + i] := "\\r"')
        .raw('    @[lpBuffer + i + 1] := "\\n"')
        .raw("")
        .raw("    assume bReadConstraints")
        .raw("")
        .raw("    if lpNumberOfBytesRead <> 0 then")
        .raw("        @[lpNumberOfBytesRead, 4] := nNumberOfBytesRead")
        .raw("    end")
        .raw("")
        .raw("    return 1")
        .raw("end")
        # 7. Goal: reach WriteFile with the string the binary writes
        #    being "G00d j0b!". When SSE finds this, it dumps the
        #    bRead stream as ASCII --- that's the flag.
        .reach(
            "WriteFile",
            such_that='@[@[esp + 8, 4], 9] = "G00d j0b!"',
            then="print ascii stream bRead",
        )
        # 8. Cut: don't waste time on the failure branch that prints
        #    "N0t t00 h0t R we? 7ry 4ga1nz plzzz!".
        .cut_at(
            "WriteFile",
            if_cond='@[@[esp + 8, 4], 35] = "N0t t00 h0t R we? 7ry 4ga1nz plzzz!"',
        )
    )


# ----------------------------------------------------------------------
# Diff against the upstream reference
# ----------------------------------------------------------------------


def compare_to_reference(generated: str, reference_path: Path) -> None:
    """Best-effort line-by-line diff against the upstream crackme.ini.

    Differences in pure whitespace (blank lines, indentation inside
    raw blocks) are tolerated; everything else is reported.
    """
    if not reference_path.is_file():
        print(f"(reference not found at {reference_path}; skipping diff)")
        return

    def _normalize(text: str) -> list[str]:
        # Strip comment lines and blank lines so we focus on directives.
        out = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            out.append(stripped)
        return out

    gen_lines = _normalize(generated)
    ref_lines = _normalize(reference_path.read_text())

    if gen_lines == ref_lines:
        print(f"[+] generated script matches {reference_path.name} (modulo comments)")
        return

    print(f"[!] differences vs {reference_path.name}:")
    from difflib import unified_diff

    for diff_line in unified_diff(
        ref_lines,
        gen_lines,
        fromfile=str(reference_path),
        tofile="generated",
        lineterm="",
    ):
        print(f"    {diff_line}")


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------


def main(binary_path: str) -> int:
    bs = Binsec()
    print(f"[+] Using {bs.path} ({bs.info.version})")

    builder = build_script()
    text = builder.to_sse()

    print("[+] Generated SSE script:")
    print("    " + text.replace("\n", "\n    "))

    # If the user has the official crackme.ini next to the binary,
    # show how close we are.
    ref = Path(binary_path).parent / "crackme.ini"
    compare_to_reference(text, ref)

    runner = SSERunner(bs)
    print("[+] Running binsec (this can take a few minutes with bitwuzla)...")
    result = runner.run(
        builder.build(),
        binary_path,
        timeout=600,  # 10 min; bitwuzla on PE crackmes is slow
        extra_args=[
            # -fml-solver bitwuzla: bitwuzla solves bitvector
            # constraints much faster than z3 on this kind of problem.
            "-fml-solver",
            "bitwuzla",
            # Extra exploration depth (from the upstream config.cfg).
            "-sse-depth",
            "100000",
        ],
    )

    print(f"[+] Exit code: {result.returncode}")
    print(f"[+] Reached:   {len(result.reached)}")
    for rp in result.reached:
        sym = f" ({rp.symbol})" if rp.symbol else ""
        print(f"      path {rp.path_id} at 0x{rp.address:x}{sym}")
        for k, v in rp.values.items():
            print(f"        {k} = {v!r}")

    # Look for the documented secret in the printed output. The Binsec
    # log line for an ascii stream looks like:
    #   [sse:result] Ascii stream bRead : "R_y0u_H0t_3n0ugH..."
    expected = "R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com"
    if expected in result.stdout:
        print(f"[+] SECRET RECOVERED: {expected}")
        return 0

    print("[!] Did not find the documented secret in stdout. First 4 KiB:", file=sys.stderr)
    print(result.stdout[:4096], file=sys.stderr)
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path/to/IgniteMe.exe>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))

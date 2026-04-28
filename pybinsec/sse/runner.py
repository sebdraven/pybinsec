"""Run an SSE :class:`Script` through Binsec and parse the textual results.

The runner takes care of:

- writing the script to a temporary file,
- invoking ``binsec -sse -sse-script <script> <binary>``,
- collecting stdout/stderr,
- parsing the most useful lines into a structured :class:`SSEResult`.

The parsing in this version is intentionally minimal: it covers the
"directive reached / cut", the "Value" lines that follow ``then print``,
and the high-level summary counts. Richer parsing (full SMT model
extraction, per-path traces) belongs to the v0.4 ``formula`` module.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from pybinsec._binsec import Binsec
from pybinsec.exceptions import ParseError
from pybinsec.sse.script import Script

# Regexes for the lines we currently understand. Binsec prefixes log
# lines with the producing channel in square brackets, e.g.
# ``[sse:result] Directive :: path 0 reached address 08048071 (0 to go)``.

_REACHED_RE = re.compile(
    r"\[sse:result\]\s+Directive\s+::\s+path\s+(?P<path>\d+)\s+"
    r"reached\s+address\s+(?P<address>[0-9a-fA-Fx]+)"
)
_VALUE_RE = re.compile(
    r"\[sse:result\]\s+Value\s+(?P<expr>.+?)\s*:\s*(?P<value>0x[0-9a-fA-F]+)\s*$"
)
_CUT_RE = re.compile(
    r"\[sse:warning\]\s+Cut\s+@\s+\((?P<address>[0-9a-fA-Fx]+),\s*\d+\)"
)


@dataclass(frozen=True, slots=True)
class ReachedPoint:
    """One ``reach`` directive that fired during exploration."""

    path_id: int
    address: int
    values: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CutPoint:
    """One path that was cut by Binsec (either via a ``cut`` directive
    or because of an unsupported instruction)."""

    address: int


@dataclass(frozen=True, slots=True)
class SSEResult:
    """Structured outcome of one SSE run.

    Attributes:
        returncode: Binsec exit status. 0 on success.
        stdout: Raw captured stdout, useful as a fallback when parsing
            misses something.
        stderr: Raw captured stderr.
        reached: Each ``reach`` event we parsed, in order.
        cuts: Each cut event we parsed.
        script_text: The exact script text fed to Binsec, for debugging.
        command: The full argv that was executed.
    """

    returncode: int
    stdout: str
    stderr: str
    reached: list[ReachedPoint]
    cuts: list[CutPoint]
    script_text: str
    command: list[str]

    @property
    def ok(self) -> bool:
        """True if the run completed without error."""
        return self.returncode == 0


class SSERunner:
    """High-level driver: feed an SSE :class:`Script` and a binary, get an
    :class:`SSEResult` back.

    Example:
        >>> from pybinsec import Binsec
        >>> from pybinsec.sse import ScriptBuilder, SSERunner
        >>> bs = Binsec()
        >>> script = ScriptBuilder().starting_from(0x401234).reach(0x401300).build()
        >>> runner = SSERunner(bs)
        >>> result = runner.run(script, "/path/to/binary")
        >>> result.ok and result.reached
        True
    """

    def __init__(self, binsec: Binsec) -> None:
        self._binsec = binsec

    def run(
        self,
        script: Script,
        binary: str | os.PathLike[str],
        *,
        timeout: float | None = None,
        extra_args: list[str] | None = None,
        keep_workdir: bool = False,
    ) -> SSEResult:
        """Run ``binsec -sse`` on ``binary`` with the given script.

        Args:
            script: The SSE script to execute.
            binary: Path to the target binary.
            timeout: Per-call timeout in seconds. ``None`` means no
                timeout from our side; the script can still pin a
                Binsec-side timeout via ``-sse-timeout``.
            extra_args: Additional Binsec command-line flags appended
                after our own. Useful for ``-sse-timeout``,
                ``-fml-solver z3``, etc.
            keep_workdir: If True, the temporary directory holding the
                script file is not cleaned up. Useful for debugging.

        Returns:
            An :class:`SSEResult` summarising the run.
        """
        binary_path = Path(binary)
        if not binary_path.is_file():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        script_text = script.to_sse()
        workdir = Path(tempfile.mkdtemp(prefix="pybinsec-"))
        try:
            script_path = workdir / "script.cfg"
            script_path.write_text(script_text, encoding="utf-8")

            args = [
                "-sse",
                "-sse-script",
                str(script_path),
                str(binary_path),
            ]
            if extra_args:
                args.extend(extra_args)

            proc = self._binsec.run(
                args,
                cwd=workdir,
                timeout=timeout,
                check=False,
            )

            reached, cuts = _parse_output(proc.stdout + "\n" + proc.stderr)

            return SSEResult(
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                reached=reached,
                cuts=cuts,
                script_text=script_text,
                command=[str(self._binsec.path), *args],
            )
        finally:
            if not keep_workdir:
                shutil.rmtree(workdir, ignore_errors=True)


def _parse_output(text: str) -> tuple[list[ReachedPoint], list[CutPoint]]:
    """Parse Binsec's combined stdout+stderr into structured events.

    The parser scans line by line, attaching ``Value`` lines to the
    most recently-seen ``reached`` event. This matches the way Binsec
    emits results: the directive's address is logged first, then any
    expressions printed via ``then print`` follow on subsequent lines.
    """
    reached: list[ReachedPoint] = []
    cuts: list[CutPoint] = []
    current_values: dict[str, int] = {}
    pending: ReachedPoint | None = None

    def flush() -> None:
        nonlocal pending, current_values
        if pending is not None:
            # Replace the placeholder with one carrying the accumulated
            # values. ReachedPoint is frozen so we rebuild it.
            reached[-1] = ReachedPoint(
                path_id=pending.path_id,
                address=pending.address,
                values=dict(current_values),
            )
        pending = None
        current_values = {}

    for line in text.splitlines():
        m = _REACHED_RE.search(line)
        if m:
            flush()
            try:
                addr = int(m.group("address"), 16)
            except ValueError as exc:
                raise ParseError(f"Cannot parse reach address: {line!r}") from exc
            pending = ReachedPoint(path_id=int(m.group("path")), address=addr)
            reached.append(pending)
            continue

        m = _VALUE_RE.search(line)
        if m and pending is not None:
            try:
                current_values[m.group("expr").strip()] = int(m.group("value"), 16)
            except ValueError as exc:
                raise ParseError(f"Cannot parse value line: {line!r}") from exc
            continue

        m = _CUT_RE.search(line)
        if m:
            try:
                cuts.append(CutPoint(address=int(m.group("address"), 16)))
            except ValueError as exc:
                raise ParseError(f"Cannot parse cut address: {line!r}") from exc

    flush()
    return reached, cuts

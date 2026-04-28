"""Tests for the SSE runner: output parsing and script-feeding plumbing.

These tests do not need a real Binsec. They exercise the parser on
canned output and use a tiny fake binary to satisfy the path check.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from pybinsec import Binsec
from pybinsec.sse import ScriptBuilder, SSERunner
from pybinsec.sse.runner import _parse_output
from tests.test_binsec_detection import _make_fake_binsec

# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------


class TestParseOutput:
    def test_single_reach_with_values(self) -> None:
        # Lifted from the Binsec ``magic`` tutorial output (older format).
        text = (
            "[sse:result] Directive :: path 0 reached address 08048071 (0 to go)\n"
            "[sse:result] Value @[(esp<32> + 4<32>),4] : 0x80808000\n"
            "[sse:result] Value eax<32>{0,7} : 0x00\n"
            "[sse:info] SMT queries\n"
        )
        reached, cuts = _parse_output(text)
        assert len(reached) == 1
        assert len(cuts) == 0
        rp = reached[0]
        assert rp.path_id == 0
        assert rp.address == 0x08048071
        assert rp.symbol is None
        assert rp.values == {
            "@[(esp<32> + 4<32>),4]": 0x80808000,
            "eax<32>{0,7}": 0x00,
        }

    def test_new_format_with_symbol(self) -> None:
        # Format observed in master builds of Binsec (the official
        # binsec/binsec:latest image at digest c50725e8...).
        text = "[sse:result] Path 3 reached address 0x401106 (<target>) (0 to go)\n"
        reached, cuts = _parse_output(text)
        assert len(reached) == 1
        assert cuts == []
        rp = reached[0]
        assert rp.path_id == 3
        assert rp.address == 0x401106
        assert rp.symbol == "<target>"
        assert rp.values == {}

    def test_new_format_without_symbol(self) -> None:
        # The symbol is optional in the new format too; binsec only
        # prints it when the address resolves to a known symbol.
        text = "[sse:result] Path 0 reached address 0x401234 (0 to go)\n"
        reached, _ = _parse_output(text)
        assert len(reached) == 1
        assert reached[0].address == 0x401234
        assert reached[0].symbol is None

    def test_multiple_reaches(self) -> None:
        text = (
            "[sse:result] Directive :: path 0 reached address 0x401300\n"
            "[sse:result] Value eax : 0x2a\n"
            "[sse:result] Directive :: path 1 reached address 0x401400\n"
            "[sse:result] Value eax : 0x0\n"
        )
        reached, _ = _parse_output(text)
        assert len(reached) == 2
        assert reached[0].path_id == 0
        assert reached[0].values == {"eax": 0x2A}
        assert reached[1].path_id == 1
        assert reached[1].values == {"eax": 0x0}

    def test_cut_lines(self) -> None:
        text = "[sse:warning] Cut @ (0804815b, 0) : #unsupported cd 80\n"
        _, cuts = _parse_output(text)
        assert len(cuts) == 1
        assert cuts[0].address == 0x0804815B

    def test_value_line_without_pending_reach_is_dropped(self) -> None:
        # If we see a Value before any Directive line, we have nothing to
        # attach it to, so it is silently ignored. This matches the
        # current parser's behavior; a future strict mode could change it.
        text = "[sse:result] Value eax : 0x42\n"
        reached, cuts = _parse_output(text)
        assert reached == []
        assert cuts == []

    def test_empty_text(self) -> None:
        reached, cuts = _parse_output("")
        assert reached == []
        assert cuts == []


# ---------------------------------------------------------------------------
# Runner plumbing
# ---------------------------------------------------------------------------


class TestSSERunner:
    def test_missing_binary_raises(self, tmp_path: Path) -> None:
        fake_binsec = _make_fake_binsec(tmp_path)
        runner = SSERunner(Binsec(fake_binsec))
        script = ScriptBuilder().starting_from(0x401234).reach(0x401300).build()
        with pytest.raises(FileNotFoundError):
            runner.run(script, tmp_path / "does-not-exist")

    def test_run_writes_script_and_invokes_binsec(self, tmp_path: Path) -> None:
        fake_binsec = _make_fake_binsec(tmp_path)
        # Create a fake target binary; content does not matter, only its
        # existence is checked.
        target = tmp_path / "target.elf"
        target.write_bytes(b"\x7fELF")

        runner = SSERunner(Binsec(fake_binsec))
        script = ScriptBuilder().starting_from(0x401234).reach(0x401300).build()

        # Capture the args passed to Binsec.run() so we can assert the
        # CLI we constructed is what we expect.
        captured: dict[str, object] = {}

        def fake_run(
            self: Binsec, args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            captured["args"] = args
            captured["cwd"] = kwargs.get("cwd")
            # Simulate a successful Binsec run that reached the target.
            stdout = (
                "[sse:result] Directive :: path 0 reached address 0x401300\n"
                "[sse:result] Value eax : 0x2a\n"
            )
            return subprocess.CompletedProcess(
                args=[str(self.path), *args],
                returncode=0,
                stdout=stdout,
                stderr="",
            )

        with patch.object(Binsec, "run", fake_run):
            result = runner.run(script, target)

        # Argv inspection.
        args = captured["args"]
        assert isinstance(args, list)
        assert "-sse" in args
        assert "-sse-script" in args
        # The script path should be the next arg after -sse-script and
        # should point to a file that exists at run time. We can no
        # longer check existence here (workdir is cleaned up), but we
        # can verify the position.
        idx = args.index("-sse-script")
        assert args[idx + 1].endswith("script.cfg")
        assert args[-1] == str(target)

        # Result inspection.
        assert result.ok
        assert result.returncode == 0
        assert len(result.reached) == 1
        assert result.reached[0].address == 0x401300
        assert result.reached[0].values == {"eax": 0x2A}
        assert result.script_text.startswith("starting from 0x401234")

    def test_extra_args_are_appended(self, tmp_path: Path) -> None:
        fake_binsec = _make_fake_binsec(tmp_path)
        target = tmp_path / "target.elf"
        target.write_bytes(b"\x7fELF")
        runner = SSERunner(Binsec(fake_binsec))
        script = ScriptBuilder().starting_from(0x401234).build()

        captured: dict[str, object] = {}

        def fake_run(
            self: Binsec, args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            captured["args"] = args
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        with patch.object(Binsec, "run", fake_run):
            runner.run(script, target, extra_args=["-sse-timeout", "30", "-fml-solver", "z3"])

        args = captured["args"]
        assert isinstance(args, list)
        assert "-sse-timeout" in args
        assert args[args.index("-sse-timeout") + 1] == "30"
        assert "-fml-solver" in args
        assert args[args.index("-fml-solver") + 1] == "z3"

"""Tests for the fluent SSE script builder."""

from __future__ import annotations

import pytest

from pybinsec.exceptions import ScriptError
from pybinsec.sse import BinOp, Initialize, Mem, Reg, ScriptBuilder, Var


class TestBuilderBasics:
    def test_chaining_returns_same_builder(self) -> None:
        b = ScriptBuilder()
        assert b.starting_from(0x1234) is b
        assert b.reach(0x5678) is b
        assert b.cut_at(0x9ABC) is b

    def test_minimal_script(self) -> None:
        text = ScriptBuilder().starting_from(0x401234).reach(0x401300).to_sse()
        assert text == "starting from 0x401234\nreach 0x401300\n"


class TestInitShortcuts:
    def test_register_init_via_string(self) -> None:
        text = ScriptBuilder().init("rsp", 0x7FFFFFFFD8E0).to_sse()
        assert text == "rsp := 0x7fffffffd8e0\n"

    def test_typed_variable_init_via_string_and_size(self) -> None:
        text = ScriptBuilder().init("goal", 0x401234, size=64).to_sse()
        assert text == "goal<64> := 0x401234\n"

    def test_init_accepts_var_directly(self) -> None:
        text = ScriptBuilder().init(Var("len", 64), 188).to_sse()
        assert text == "len<64> := 0xbc\n"

    def test_init_memory(self) -> None:
        text = ScriptBuilder().init_memory(Reg("rdi"), "nondet", size=8).to_sse()
        assert text == "@[rdi, 8] := nondet\n"


class TestReplaceShortcut:
    def test_single_symbol_string(self) -> None:
        text = (
            ScriptBuilder()
            .replace(
                "__isoc99_scanf",
                body=[
                    Initialize(Var("caller", 64), Mem(Reg("rsp"), 8)),
                ],
            )
            .to_sse()
        )
        expected = "replace <__isoc99_scanf> by\n    caller<64> := @[rsp, 8]\nend\n"
        assert text == expected

    def test_multiple_symbols(self) -> None:
        text = (
            ScriptBuilder()
            .replace(
                ["puts", "printf"],
                body=["caller<64> := @[rsp, 8]", "rsp := rsp + 8", "jump at caller"],
            )
            .to_sse()
        )
        expected = (
            "replace <puts>, <printf> by\n"
            "    caller<64> := @[rsp, 8]\n"
            "    rsp := rsp + 8\n"
            "    jump at caller\n"
            "end\n"
        )
        assert text == expected


class TestRawEscapeHatch:
    def test_raw_line_passes_through(self) -> None:
        text = (
            ScriptBuilder()
            .starting_from("main")
            .raw("for i<64> in 0 to 10 do")
            .raw("    @[rsi + i, 1] := nondet")
            .raw("end")
            .to_sse()
        )
        expected = (
            "starting from <main>\nfor i<64> in 0 to 10 do\n    @[rsi + i, 1] := nondet\nend\n"
        )
        assert text == expected


class TestRealisticScript:
    def test_fcsc_inspired_script(self) -> None:
        # Inspired by the FCSC 2023 write-up: reach a goal symbol while
        # cutting on the failure addresses, with stubbed I/O functions.
        text = (
            ScriptBuilder()
            .starting_from("core")
            .init("goal", 0x5555555553A3, size=64)
            .init("rsp", 0x7FFFFFFFD8E0)
            .replace(
                ["puts", "printf"],
                body=[
                    "caller<64> := @[rsp, 8]",
                    "rsp := rsp + 8",
                    "jump at caller",
                ],
            )
            .reach("goal")
            .cut_at(0x55555555533F)
            .cut_at(0x55555555534C)
            .assert_(BinOp(Reg("rax"), "=", 0))
            .to_sse()
        )
        # Sanity-check the salient pieces rather than the whole blob.
        assert "starting from core" in text
        assert "goal<64> := 0x5555555553a3" in text
        assert "replace <puts>, <printf> by" in text
        assert "    jump at caller" in text
        assert "reach <goal>" in text
        assert "cut at 0x55555555533f" in text
        assert "assert (rax = 0x0)" in text


# ---------------------------------------------------------------------------
# v0.4 sprint 1: builder methods for the new directives
# ---------------------------------------------------------------------------


class TestBuilderAlias:
    def test_init_with_alias(self) -> None:
        text = ScriptBuilder().init("strncpy_addr", 0xDEADBEEF, as_alias="strncpy").to_sse()
        assert text == "strncpy_addr := 0xdeadbeef as strncpy\n"

    def test_init_memory_with_alias(self) -> None:
        # The PLT-aliasing pattern from sse/google/crackme.ini.
        text = (
            ScriptBuilder()
            .init_memory(0x604208, 0x7FFFF7F45F30, size=8, as_alias="strncpy")
            .to_sse()
        )
        assert text == "@[0x604208, 8] := 0x7ffff7f45f30 as strncpy\n"


class TestBuilderHaltAbort:
    def test_halt_at_symbol(self) -> None:
        assert ScriptBuilder().halt_at("exit").to_sse() == "halt at <exit>\n"

    def test_abort_at_multiple(self) -> None:
        text = ScriptBuilder().abort_at("errx", "__libc_start_main", "__gmon_start__").to_sse()
        assert text == "abort at <errx>, <__libc_start_main>, <__gmon_start__>\n"

    def test_abort_at_empty_raises(self) -> None:
        with pytest.raises(ScriptError):
            ScriptBuilder().abort_at()


class TestBuilderLoading:
    def test_load_sections(self) -> None:
        text = ScriptBuilder().load_sections(".text", ".rdata", ".data").to_sse()
        assert text == "load sections .text, .rdata, .data from file\n"

    def test_load_sections_empty_raises(self) -> None:
        with pytest.raises(ScriptError):
            ScriptBuilder().load_sections()

    def test_load_from_file_address(self) -> None:
        # ``size`` is rendered in decimal: that's the natural form for a
        # byte count and matches what the reference scripts use.
        text = ScriptBuilder().load_from_file(0x402000, 256).to_sse()
        assert text == "@[0x402000, 256] from file\n"

    def test_load_from_file_symbol(self) -> None:
        # The flare-on/2015.1 pattern: load a section by name.
        text = ScriptBuilder().load_from_file("<.text>", 512).to_sse()
        assert text == "@[<.text>, 512] from file\n"


class TestBuilderFlareOn2015_1Replication:
    """Stitch the new builders together to reproduce a meaningful prefix
    of the canonical sse/flare-on/2015.1/crackme.ini script.

    The whole script needs control-flow constructs (case, if/then,
    for) that are out of scope for sprint 1, so we only assert the
    prefix that uses sprint-1 directives. This still gives us a real
    end-to-end check that the new builders compose cleanly.
    """

    def test_prefix(self) -> None:
        text = (
            ScriptBuilder()
            .init("esp", 0x32FF5C)
            .init_memory("esp", 0x7B454CEF, size=4, as_alias="return_address")
            .load_from_file("<.text>", 512)
            .load_from_file("<.data>", 512)
            .init_memory(0x402058, 0x7B431A7C, size=4, as_alias="GetStdHandle")
            .init_memory(0x402064, 0x7B442EF0, size=4, as_alias="WriteFile")
            .init_memory(0x402068, 0x7B442E00, size=4, as_alias="ReadFile")
            .abort_at(
                "LoadLibraryA",
                "GetProcAddress",
                "GetLastError",
                "AttachConsole",
                "WriteConsoleA",
            )
            .to_sse()
        )
        # Prefix matches the official script line by line.
        expected_prefix = (
            "esp := 0x32ff5c\n"
            "@[esp, 4] := 0x7b454cef as return_address\n"
            "@[<.text>, 512] from file\n"
            "@[<.data>, 512] from file\n"
            "@[0x402058, 4] := 0x7b431a7c as GetStdHandle\n"
            "@[0x402064, 4] := 0x7b442ef0 as WriteFile\n"
            "@[0x402068, 4] := 0x7b442e00 as ReadFile\n"
            "abort at <LoadLibraryA>, <GetProcAddress>, <GetLastError>, "
            "<AttachConsole>, <WriteConsoleA>\n"
        )
        assert text == expected_prefix

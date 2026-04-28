"""Tests for the fluent SSE script builder."""

from __future__ import annotations

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

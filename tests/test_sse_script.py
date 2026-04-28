"""Tests for the SSE script AST and its text rendering.

These tests are pure: they verify that the AST nodes produce the
expected SSE script text, with no real Binsec invocation. Reference
fragments are taken from the Binsec ``magic`` tutorial and from the
FCSC 2023 write-up linked in the project notes.
"""

from __future__ import annotations

import pytest

from pybinsec.exceptions import ScriptError
from pybinsec.sse import (
    NONDET,
    Abort,
    Assert,
    Assume,
    BinOp,
    Const,
    Cut,
    Halt,
    Initialize,
    LoadFromFile,
    LoadSections,
    Mem,
    Print,
    Reach,
    Reg,
    Replace,
    Return,
    Script,
    StartingFrom,
    Sym,
    Var,
)


class TestExpressions:
    def test_const_unsized(self) -> None:
        assert Const(0x1234).to_sse() == "0x1234"

    def test_const_with_size(self) -> None:
        assert Const(0x401234, 64).to_sse() == "0x401234<64>"

    def test_var(self) -> None:
        assert Var("goal", 64).to_sse() == "goal<64>"

    def test_var_unsized(self) -> None:
        assert Var("len").to_sse() == "len"

    def test_reg(self) -> None:
        assert Reg("rsp").to_sse() == "rsp"

    def test_mem_with_int_address(self) -> None:
        assert Mem(0x404010, 4).to_sse() == "@[0x404010, 4]"

    def test_mem_with_register_address(self) -> None:
        assert Mem(Reg("rsp"), 8).to_sse() == "@[rsp, 8]"

    def test_mem_with_binop_address(self) -> None:
        # @[(rsp + 4), 4] is the canonical form Binsec emits.
        expr = Mem(BinOp(Reg("rsp"), "+", 4), 4)
        assert expr.to_sse() == "@[(rsp + 0x4), 4]"

    def test_sym_wraps_bare_name(self) -> None:
        assert Sym("main").to_sse() == "<main>"

    def test_sym_passes_through_pre_wrapped(self) -> None:
        assert Sym("<__isoc99_scanf>").to_sse() == "<__isoc99_scanf>"

    def test_nondet(self) -> None:
        assert NONDET.to_sse() == "nondet"


class TestStartingFrom:
    def test_address(self) -> None:
        assert StartingFrom(0x401234).to_sse() == "starting from 0x401234"

    def test_symbol(self) -> None:
        # Bare names get wrapped.
        assert StartingFrom("main").to_sse() == "starting from <main>"

    def test_core_dump(self) -> None:
        assert StartingFrom("core").to_sse() == "starting from core"

    def test_pre_wrapped_symbol(self) -> None:
        assert StartingFrom("<main>").to_sse() == "starting from <main>"


class TestInitialize:
    def test_register(self) -> None:
        assert Initialize(Reg("rsp"), 0x7FFFFFFFD8E0).to_sse() == "rsp := 0x7fffffffd8e0"

    def test_typed_variable(self) -> None:
        assert Initialize(Var("goal", 64), 0x401234).to_sse() == "goal<64> := 0x401234"

    def test_memory_with_nondet(self) -> None:
        assert Initialize(Mem(Reg("rdi"), 8), NONDET).to_sse() == "@[rdi, 8] := nondet"

    def test_bool_rendering(self) -> None:
        # Booleans should render as words, not as 0x1 / 0x0.
        assert Initialize(Var("flag", 1), True).to_sse() == "flag<1> := true"
        assert Initialize(Var("flag", 1), False).to_sse() == "flag<1> := false"


class TestReach:
    def test_simple(self) -> None:
        assert Reach(0x401300).to_sse() == "reach 0x401300"

    def test_n_times(self) -> None:
        assert Reach(0x401300, times=3).to_sse() == "reach 0x401300 3 times"

    def test_such_that(self) -> None:
        cond = BinOp(Reg("eax"), "=", 0x2A)
        assert Reach(0x401300, such_that=cond).to_sse() == "reach 0x401300 such that (eax = 0x2a)"

    def test_then_action(self) -> None:
        assert Reach(0x401300, then="print eax").to_sse() == "reach 0x401300 then print eax"

    def test_full_form(self) -> None:
        cond = BinOp(Reg("al"), "<>", 0)
        assert (
            Reach("magic:last", times=1, such_that=cond, then="print arg").to_sse()
            == "reach <magic:last> 1 times such that (al <> 0x0) then print arg"
        )


class TestCut:
    def test_simple(self) -> None:
        assert Cut(0x401400).to_sse() == "cut at 0x401400"

    def test_with_condition(self) -> None:
        cond = BinOp(Reg("eax"), "=", 0)
        assert Cut(0x401400, if_cond=cond).to_sse() == "cut at 0x401400 if (eax = 0x0)"


class TestAssumeAssert:
    def test_assume(self) -> None:
        assert Assume(BinOp(Var("len", 64), "=", 188)).to_sse() == "assume (len<64> = 0xbc)"

    def test_assert(self) -> None:
        assert Assert(BinOp(Reg("eax"), "=", 0x2A)).to_sse() == "assert (eax = 0x2a)"


class TestPrint:
    def test_print_register(self) -> None:
        assert Print(Reg("eax")).to_sse() == "print eax"

    def test_print_raw_string(self) -> None:
        # Raw strings pass through unchanged, useful for expressions
        # the AST does not model.
        assert Print("@[esp + 4, 4]").to_sse() == "print @[esp + 4, 4]"


class TestReplace:
    def test_single_symbol_with_initialize_body(self) -> None:
        block = Replace(
            symbols=["__isoc99_scanf"],
            body=[
                Initialize(Var("caller", 64), Mem(Reg("rsp"), 8)),
            ],
        ).to_sse()
        expected = "replace <__isoc99_scanf> by\n    caller<64> := @[rsp, 8]\nend"
        assert block == expected

    def test_multiple_symbols(self) -> None:
        block = Replace(
            symbols=["puts", "printf"],
            body=[
                Initialize(Var("caller", 64), Mem(Reg("rsp"), 8)),
                "rsp := rsp + 8",
                "jump at caller",
            ],
        ).to_sse()
        expected = (
            "replace <puts>, <printf> by\n"
            "    caller<64> := @[rsp, 8]\n"
            "    rsp := rsp + 8\n"
            "    jump at caller\n"
            "end"
        )
        assert block == expected

    def test_empty_symbols_raises(self) -> None:
        with pytest.raises(ScriptError):
            Replace(symbols=[], body=[]).to_sse()


class TestScriptComposition:
    def test_empty_script(self) -> None:
        assert Script().to_sse() == ""

    def test_directives_one_per_line(self) -> None:
        script = (
            Script()
            .add(StartingFrom(0x401234))
            .add(Initialize(Reg("rsp"), 0x7FFFFFFFD8E0))
            .add(Reach(0x401300))
            .add(Cut(0x401400))
        )
        expected = (
            "starting from 0x401234\nrsp := 0x7fffffffd8e0\nreach 0x401300\ncut at 0x401400\n"
        )
        assert script.to_sse() == expected

    def test_magic_tutorial_minimal(self) -> None:
        # Reproduces the minimal viable script from the Binsec ``magic``
        # tutorial: start at one address, reach another, print a stack
        # argument and the return value.
        script = (
            Script()
            .add(StartingFrom(0x804805C))
            .add(
                Reach(
                    0x8048071,
                    such_that=BinOp(Reg("al"), "<>", 0),
                    then="print @[esp + 4, 4]",
                )
            )
        )
        expected = (
            "starting from 0x804805c\n"
            "reach 0x8048071 such that (al <> 0x0) then print @[esp + 4, 4]\n"
        )
        assert script.to_sse() == expected


# ---------------------------------------------------------------------------
# v0.4 sprint 1: scalar directives
# ---------------------------------------------------------------------------


class TestInitializeWithAlias:
    """The ``as <alias>`` suffix on Initialize.

    Two real-world uses, both lifted from the official Google CTF
    crackme.ini in the binsec/binsec image:

    1. Symbolic stream: ``@[buf+i, 1] := nondet as bRead``
       The bytes are symbolic, but binsec exposes them under the
       ``bRead`` stream so ``print ascii stream bRead`` can dump them.
    2. PLT alias: ``@[0x604208, 8] := 0x7ffff7f45f30 as strncpy``
       Binds the runtime address to a callable name so later
       directives can say ``replace strncpy by ...``.
    """

    def test_register_alias_omitted(self) -> None:
        # Backwards-compat: the new field defaults to None.
        assert Initialize(Reg("rsp"), 0x1234).to_sse() == "rsp := 0x1234"

    def test_stream_alias_on_memory(self) -> None:
        node = Initialize(
            Mem(BinOp("lpBuffer", "+", Var("i", 32)), 1),
            NONDET,
            as_alias="bRead",
        )
        assert node.to_sse() == "@[(lpBuffer + i<32>), 1] := nondet as bRead"

    def test_plt_alias_on_memory(self) -> None:
        node = Initialize(
            Mem(0x604208, 8),
            0x7FFFF7F45F30,
            as_alias="strncpy",
        )
        assert node.to_sse() == "@[0x604208, 8] := 0x7ffff7f45f30 as strncpy"


class TestReturn:
    def test_bare(self) -> None:
        assert Return().to_sse() == "return"

    def test_with_int_value(self) -> None:
        assert Return(value=1).to_sse() == "return 0x1"

    def test_with_register_value(self) -> None:
        assert Return(value=Reg("rdi")).to_sse() == "return rdi"

    def test_in_replace_body(self) -> None:
        """``Return`` directives are accepted in :class:`Replace` bodies.

        Mirrors the canonical Google CTF stub ``replace puts, printf by
        return end``.
        """
        block = Replace(
            symbols=["puts", "printf"],
            body=[Return()],
        ).to_sse()
        expected = "replace <puts>, <printf> by\n    return\nend"
        assert block == expected

    def test_return_value_in_replace_body(self) -> None:
        # flare-on/2017.2's ReadFile stub ends with ``return 1``.
        block = Replace(
            symbols=["ReadFile"],
            body=[
                Initialize(Mem("lpNumberOfBytesRead", 4), Var("nNumberOfBytesRead", 32)),
                Return(value=1),
            ],
        ).to_sse()
        expected = (
            "replace <ReadFile> by\n"
            "    @[lpNumberOfBytesRead, 4] := nNumberOfBytesRead<32>\n"
            "    return 0x1\n"
            "end"
        )
        assert block == expected


class TestHalt:
    def test_at_symbol(self) -> None:
        # The canonical ``halt at exit`` from sse/google/exit.stub.
        assert Halt("exit").to_sse() == "halt at <exit>"

    def test_at_address(self) -> None:
        assert Halt(0x401234).to_sse() == "halt at 0x401234"


class TestAbort:
    def test_single_target(self) -> None:
        # Single argument still uses the ``abort at`` form (not ``cut
        # at``) because the user asked for abort semantics.
        assert Abort(addresses=["errx"]).to_sse() == "abort at <errx>"

    def test_multiple_targets(self) -> None:
        # Lifted from sse/google/crackme.ini.
        node = Abort(
            addresses=[
                "errx",
                "__libc_start_main",
                "__gmon_start__",
                "__ctype_b_loc",
            ]
        )
        expected = "abort at <errx>, <__libc_start_main>, <__gmon_start__>, <__ctype_b_loc>"
        assert node.to_sse() == expected

    def test_empty_raises(self) -> None:
        with pytest.raises(ScriptError):
            Abort(addresses=[]).to_sse()


class TestLoadSections:
    def test_single_section(self) -> None:
        assert LoadSections(sections=[".text"]).to_sse() == "load sections .text from file"

    def test_multiple_sections(self) -> None:
        # From sse/flare-on/2017.2/crackme.ini.
        node = LoadSections(sections=[".text", ".rdata", ".data"])
        assert node.to_sse() == "load sections .text, .rdata, .data from file"

    def test_empty_raises(self) -> None:
        with pytest.raises(ScriptError):
            LoadSections(sections=[]).to_sse()


class TestLoadFromFile:
    def test_at_symbol(self) -> None:
        # ``@[<.text>, 512] from file`` from sse/flare-on/2015.1.
        assert LoadFromFile("<.text>", 512).to_sse() == "@[<.text>, 512] from file"

    def test_at_address(self) -> None:
        # ``size`` is rendered in decimal (natural form for a byte count).
        assert LoadFromFile(0x402000, 256).to_sse() == "@[0x402000, 256] from file"

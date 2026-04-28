"""Tests for the Layer 3 Project / SimulationManager API."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from pybinsec import Binsec
from pybinsec.project import (
    Project,
    SimulationManager,
    State,
    SymbolicValue,
)
from pybinsec.sse.runner import CutPoint, ReachedPoint, SSEResult
from tests.test_binsec_detection import _make_fake_binsec

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_project(tmp_path: Path) -> Project:
    """Build a Project backed by a fake binsec and a fake binary file."""
    fake_binsec = _make_fake_binsec(tmp_path)
    binary = tmp_path / "target.elf"
    binary.write_bytes(b"\x7fELF")
    return Project(binary, binsec=Binsec(fake_binsec))


def _patch_runner(reached: list[ReachedPoint], cuts: list[CutPoint] | None = None):
    """Patch :class:`SSERunner.run` to return a canned :class:`SSEResult`.

    Returns a context manager that yields a dict with the captured
    script and arguments so tests can assert on what was sent.
    """
    captured: dict[str, object] = {}

    from pybinsec.sse.runner import SSERunner

    def fake_run(self: SSERunner, script, binary, *, timeout=None, extra_args=None, **_kw):
        captured["script_text"] = script.to_sse()
        captured["binary"] = str(binary)
        captured["timeout"] = timeout
        captured["extra_args"] = list(extra_args) if extra_args else []
        return SSEResult(
            returncode=0,
            stdout="",
            stderr="",
            reached=list(reached),
            cuts=list(cuts or []),
            script_text=script.to_sse(),
            command=[],
        )

    return patch.object(SSERunner, "run", fake_run), captured


# ---------------------------------------------------------------------------
# Project basics
# ---------------------------------------------------------------------------


class TestProject:
    def test_missing_binary_raises(self, tmp_path: Path) -> None:
        fake_binsec = _make_fake_binsec(tmp_path)
        with pytest.raises(FileNotFoundError):
            Project(tmp_path / "does-not-exist", binsec=Binsec(fake_binsec))

    def test_factory_returns_states_and_simgr(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        assert isinstance(state, State)
        # Default entry is the "main" symbol.
        assert state.entry == "main"

        simgr = proj.factory.simulation_manager(state)
        assert isinstance(simgr, SimulationManager)

    def test_blank_state_takes_explicit_addr(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.blank_state(addr=0x401234)
        assert state.entry == 0x401234

    def test_entry_state_with_custom_symbol(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state(addr="custom_entry")
        assert state.entry == "custom_entry"


# ---------------------------------------------------------------------------
# State configuration -> SSE directives
# ---------------------------------------------------------------------------


class TestStateConfiguration:
    def test_register_int_assignment(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        state.regs.rsp = 0x7FFFFFFFD8E0
        text = state._builder.to_sse()
        assert text == "rsp := 0x7fffffffd8e0\n"

    def test_register_via_setitem(self, tmp_path: Path) -> None:
        # state.regs["rsp"] = ... is supported for dynamic register names.
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        state.regs["rsp"] = 0x1234
        assert state._builder.to_sse() == "rsp := 0x1234\n"

    def test_memory_store(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        state.mem.store(0x404010, 0xDEADBEEF, size=4)
        assert state._builder.to_sse() == "@[0x404010, 4] := 0xdeadbeef\n"

    def test_solver_bvs_emits_nondet_init(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        sv = state.solver.BVS("arg0", 64)
        assert isinstance(sv, SymbolicValue)
        assert sv.name == "arg0"
        assert sv.size == 64
        assert state._builder.to_sse() == "arg0<64> := nondet\n"

    def test_assigning_symbolic_to_register(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        arg0 = state.solver.BVS("arg0", 64)
        state.regs.rdi = arg0
        # Order matters: BVS first, then the register assignment.
        assert state._builder.to_sse() == ("arg0<64> := nondet\nrdi := arg0<64>\n")

    def test_add_constraint(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        state.add_constraint("rax = 0x2a")
        assert state._builder.to_sse() == "assume rax = 0x2a\n"

    def test_bvs_rejects_bad_size(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        with pytest.raises(ValueError):
            state.solver.BVS("x", 0)
        with pytest.raises(ValueError):
            state.solver.BVS("x", -1)

    def test_bvs_rejects_bad_name(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        with pytest.raises(ValueError):
            state.solver.BVS("1bad", 32)
        with pytest.raises(ValueError):
            state.solver.BVS("", 32)

    def test_register_rejects_unsupported_type(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        with pytest.raises(TypeError):
            state.regs.rsp = 3.14  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# SimulationManager: script generation
# ---------------------------------------------------------------------------


class TestScriptCompilation:
    def test_minimal_script_layout(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state(addr="main")
        simgr = proj.factory.simulation_manager(state)

        ctx, captured = _patch_runner(reached=[])
        with ctx:
            simgr.explore(find="target")

        text = captured["script_text"]
        assert isinstance(text, str)
        assert text == "starting from <main>\nreach <target>\n"

    def test_full_script_layout(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state(addr="main")
        state.regs.rsp = 0x7FFFFFFFD8E0
        arg0 = state.solver.BVS("arg0", 64)
        state.regs.rdi = arg0
        state.add_constraint("rax >= 0")

        simgr = proj.factory.simulation_manager(state)
        ctx, captured = _patch_runner(reached=[])
        with ctx:
            simgr.explore(find="target", avoid=[0x401200, "fail"])

        text = captured["script_text"]
        assert isinstance(text, str)
        # Order is significant: starting_from -> inits -> reach -> cut.
        # The reach now carries an auto-print clause for the BVS.
        expected_lines = [
            "starting from <main>",
            "rsp := 0x7fffffffd8e0",
            "arg0<64> := nondet",
            "rdi := arg0<64>",
            "assume rax >= 0",
            "reach <target> then print arg0<64>",
            "cut at 0x401200",
            "cut at <fail>",
            "",  # trailing newline
        ]
        assert text.split("\n") == expected_lines

    def test_explore_requires_target(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        simgr = proj.factory.simulation_manager(proj.factory.entry_state())
        with pytest.raises(ValueError, match=r"find=|avoid="):
            simgr.explore()

    def test_explore_requires_entry(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        # blank_state with addr=None bypasses the API but force-feed it.
        state = proj.factory.entry_state(addr="main")
        state._entry = None  # simulate forgotten entry
        simgr = proj.factory.simulation_manager(state)
        with pytest.raises(ValueError, match="entry point"):
            simgr.explore(find=0x401000)

    def test_extra_args_forwarded(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        simgr = proj.factory.simulation_manager(proj.factory.entry_state())
        ctx, captured = _patch_runner(reached=[])
        with ctx:
            simgr.explore(
                find="target",
                timeout=30,
                extra_args=["-sse-timeout", "20", "-fml-solver", "z3"],
            )
        assert captured["timeout"] == 30
        assert captured["extra_args"] == ["-sse-timeout", "20", "-fml-solver", "z3"]


# ---------------------------------------------------------------------------
# SimulationManager: result mapping
# ---------------------------------------------------------------------------


class TestResultMapping:
    def test_match_by_address(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        simgr = proj.factory.simulation_manager(proj.factory.entry_state())

        rp = ReachedPoint(path_id=0, address=0x401234, symbol=None, values={})
        ctx, _ = _patch_runner(reached=[rp])
        with ctx:
            simgr.explore(find=0x401234)

        assert len(simgr.found) == 1
        assert simgr.found[0].addr == 0x401234

    def test_match_by_symbol(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        simgr = proj.factory.simulation_manager(proj.factory.entry_state())

        rp = ReachedPoint(path_id=3, address=0x401106, symbol="<target>", values={})
        ctx, _ = _patch_runner(reached=[rp])
        with ctx:
            simgr.explore(find="target")

        assert len(simgr.found) == 1
        found = simgr.found[0]
        assert found.symbol == "<target>"
        assert found.addr == 0x401106
        assert found.path_id == 3

    def test_unmatched_reach_is_dropped(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        simgr = proj.factory.simulation_manager(proj.factory.entry_state())

        # Binsec reached an address we did not ask for; should not show
        # up in `found`.
        rp = ReachedPoint(path_id=0, address=0xCAFE, symbol=None, values={})
        ctx, _ = _patch_runner(reached=[rp])
        with ctx:
            simgr.explore(find=0x1234)

        assert simgr.found == []

    def test_cuts_are_exposed(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        simgr = proj.factory.simulation_manager(proj.factory.entry_state())

        cut = CutPoint(address=0x401200)
        ctx, _ = _patch_runner(reached=[], cuts=[cut])
        with ctx:
            simgr.explore(find="target", avoid=[0x401200])

        assert len(simgr.avoided) == 1
        assert simgr.avoided[0].address == 0x401200

    def test_multiple_finds(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        simgr = proj.factory.simulation_manager(proj.factory.entry_state())

        rps = [
            ReachedPoint(path_id=0, address=0x1111, symbol=None, values={}),
            ReachedPoint(path_id=1, address=0x2222, symbol=None, values={}),
        ]
        ctx, _ = _patch_runner(reached=rps)
        with ctx:
            simgr.explore(find=[0x1111, 0x2222])

        assert {fs.addr for fs in simgr.found} == {0x1111, 0x2222}


# ---------------------------------------------------------------------------
# FoundState: solver.eval semantics
# ---------------------------------------------------------------------------


class TestFoundSolver:
    def test_eval_by_symbolic_value(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        arg0 = state.solver.BVS("arg0", 64)
        simgr = proj.factory.simulation_manager(state)

        rp = ReachedPoint(
            path_id=0,
            address=0x401234,
            symbol=None,
            values={"arg0<64>": 0xCAFEBABE},
        )
        ctx, _ = _patch_runner(reached=[rp])
        with ctx:
            simgr.explore(find=0x401234)

        assert len(simgr.found) == 1
        found = simgr.found[0]
        assert found.solver.eval(arg0) == 0xCAFEBABE
        assert found.solver.has(arg0) is True

    def test_eval_by_string_key(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        simgr = proj.factory.simulation_manager(proj.factory.entry_state())

        rp = ReachedPoint(
            path_id=0,
            address=0x4242,
            symbol=None,
            values={"@[(esp + 4),4]": 0x80808000},
        )
        ctx, _ = _patch_runner(reached=[rp])
        with ctx:
            simgr.explore(find=0x4242)

        found = simgr.found[0]
        assert found.solver.eval("@[(esp + 4),4]") == 0x80808000

    def test_eval_missing_raises_with_diagnostics(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        simgr = proj.factory.simulation_manager(proj.factory.entry_state())

        rp = ReachedPoint(
            path_id=0,
            address=0x4242,
            symbol=None,
            values={"a": 1, "b": 2},
        )
        ctx, _ = _patch_runner(reached=[rp])
        with ctx:
            simgr.explore(find=0x4242)

        found = simgr.found[0]
        with pytest.raises(KeyError) as exc_info:
            found.solver.eval("c")
        # The error message should mention the available keys so the
        # caller can fix their script.
        assert "'a'" in str(exc_info.value)
        assert "'b'" in str(exc_info.value)


# ---------------------------------------------------------------------------
# v0.3.1: auto-print of BVS on reach events
# ---------------------------------------------------------------------------


class TestAutoPrint:
    """Auto-printing of BVS variables and ``print_on_reach`` expressions.

    Without auto-print, every BVS would be invisible after the run and
    ``FoundSolver.eval`` would always raise ``KeyError``. These tests
    pin the contract: the script generated by ``simgr.explore`` must
    carry a ``then print ...`` clause on each reach for every tracked
    expression, in declaration order, and the result must be readable
    via ``found.solver.eval``.
    """

    def test_bvs_is_tracked_for_print(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        arg0 = state.solver.BVS("arg0", 64)
        # The exact rendering returned by SymbolicValue.to_sse() is the
        # key used both in the script and in the printed result, so
        # tracked_prints must agree with it.
        assert state.tracked_prints == [arg0.to_sse()]

    def test_multiple_bvs_kept_in_declaration_order(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        a = state.solver.BVS("a", 32)
        b = state.solver.BVS("b", 64)
        c = state.solver.BVS("c", 8)
        assert state.tracked_prints == [a.to_sse(), b.to_sse(), c.to_sse()]

    def test_print_on_reach_appends_after_bvs(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        a = state.solver.BVS("a", 32)
        state.print_on_reach("rax")
        state.print_on_reach("@[rsp, 8]")
        assert state.tracked_prints == [a.to_sse(), "rax", "@[rsp, 8]"]

    def test_print_on_reach_dedupes_extras(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        state.print_on_reach("rax")
        state.print_on_reach("rax")
        state.print_on_reach("rbx")
        assert state.tracked_prints == ["rax", "rbx"]

    def test_no_bvs_no_then_clause(self, tmp_path: Path) -> None:
        """State without symbolic vars must not get a `then print` clause."""
        proj = _make_project(tmp_path)
        simgr = proj.factory.simulation_manager(proj.factory.entry_state())
        ctx, captured = _patch_runner(reached=[])
        with ctx:
            simgr.explore(find="target")
        assert captured["script_text"] == "starting from <main>\nreach <target>\n"

    def test_then_clause_with_single_bvs(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        state.solver.BVS("arg0", 64)
        simgr = proj.factory.simulation_manager(state)

        ctx, captured = _patch_runner(reached=[])
        with ctx:
            simgr.explore(find="target")
        text = captured["script_text"]
        assert isinstance(text, str)
        assert "reach <target> then print arg0<64>" in text

    def test_then_clause_joins_multiple_bvs(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        state.solver.BVS("a", 32)
        state.solver.BVS("b", 64)
        simgr = proj.factory.simulation_manager(state)

        ctx, captured = _patch_runner(reached=[])
        with ctx:
            simgr.explore(find="target")
        text = captured["script_text"]
        assert isinstance(text, str)
        assert "reach <target> then print a<32>; print b<64>" in text

    def test_then_clause_applied_to_every_reach(self, tmp_path: Path) -> None:
        """All reach directives carry the same auto-print clause.

        Otherwise, paths reaching different targets would yield
        FoundStates with inconsistent value sets.
        """
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        state.solver.BVS("arg0", 64)
        simgr = proj.factory.simulation_manager(state)

        ctx, captured = _patch_runner(reached=[])
        with ctx:
            simgr.explore(find=[0x1111, 0x2222])
        text = captured["script_text"]
        assert isinstance(text, str)
        # Both reach lines must include the print clause.
        assert text.count("then print arg0<64>") == 2

    def test_auto_print_disabled(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        state.solver.BVS("arg0", 64)
        simgr = proj.factory.simulation_manager(state)

        ctx, captured = _patch_runner(reached=[])
        with ctx:
            simgr.explore(find="target", auto_print=False)
        text = captured["script_text"]
        assert isinstance(text, str)
        assert "then" not in text
        assert "print" not in text

    def test_eval_after_explore_with_auto_print(self, tmp_path: Path) -> None:
        """End-to-end (mocked) check: BVS is auto-printed and evalable.

        Mirrors what a real Binsec run would produce, with a Value
        line keyed by ``arg0<64>`` matching the auto-printed expression.
        Without auto-print, ``solver.eval`` would raise.
        """
        proj = _make_project(tmp_path)
        state = proj.factory.entry_state()
        arg0 = state.solver.BVS("arg0", 64)
        simgr = proj.factory.simulation_manager(state)

        rp = ReachedPoint(
            path_id=0,
            address=0x401234,
            symbol="<target>",
            values={"arg0<64>": 0xCAFEBABE},
        )
        ctx, _ = _patch_runner(reached=[rp])
        with ctx:
            simgr.explore(find="target")

        assert len(simgr.found) == 1
        # The point of the whole feature: this used to KeyError.
        assert simgr.found[0].solver.eval(arg0) == 0xCAFEBABE

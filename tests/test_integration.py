"""End-to-end integration tests against a real Binsec binary.

These tests exercise the full pipeline: compile a tiny C program on
the fly with gcc, build an SSE script with the fluent API, hand it to
the runner, and verify that the resulting :class:`SSEResult` reflects
what we asked for.

They are skipped unless ``binsec`` is on ``$PATH`` or ``PYBINSEC_BINARY``
is set. In CI, the ``test-binsec`` job extracts the binary from the
official ``binsec/binsec`` Docker image (pinned by digest) before
running pytest, which is when these tests actually fire.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from pybinsec import Binsec, Project, ScriptBuilder, SSERunner

# Apply the marker to every test in this module: the CI ignores them on
# the lint and test-no-bin jobs and runs them only where binsec is set up.
pytestmark = pytest.mark.requires_binsec


def _binsec_available() -> bool:
    return shutil.which("binsec") is not None or bool(os.environ.get("PYBINSEC_BINARY"))


def _gcc_available() -> bool:
    return shutil.which("gcc") is not None


# Tiny C program with a "target" function we want SSE to reach. No I/O,
# no glibc calls in the reachable path beyond the entry stub, so the
# symbolic engine doesn't have to model libc. ``argv[1]`` is read from
# whatever symbolic memory binsec gives us, which is enough for SSE to
# branch on the two character comparisons.
_C_SOURCE = r"""
int target(void) {
    return 42;
}

int main(int argc, char **argv) {
    if (argc >= 2 && argv[1][0] == 'O' && argv[1][1] == 'K') {
        return target();
    }
    return 0;
}
"""


@pytest.fixture(scope="module")
def compiled_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Compile the test C program once per session.

    Skips the whole module if either gcc or binsec is missing, instead
    of letting individual tests fail with a confusing error.
    """
    if not _gcc_available():
        pytest.skip("gcc not available on this runner")
    if not _binsec_available():
        pytest.skip("real binsec not available")

    work = tmp_path_factory.mktemp("integration")
    src = work / "check.c"
    src.write_text(_C_SOURCE)
    binary = work / "check"

    # -O0 keeps the source structure recognisable.
    # -no-pie keeps load addresses fixed at 0x400000+, simpler for SSE.
    # -fno-stack-protector avoids __stack_chk_fail being pulled in.
    # No -static: smaller binary, and our reachable path doesn't enter
    # libc anyway.
    subprocess.run(
        [
            "gcc",
            "-O0",
            "-no-pie",
            "-fno-stack-protector",
            "-o",
            str(binary),
            str(src),
        ],
        check=True,
    )
    return binary


# Second fixture: a binary where reaching ``target`` forces a single
# 64-bit input (the first integer argument of ``magic``) to a known
# concrete value. Lets us assert that auto-printed BVS values can be
# read back via FoundSolver.eval against the real binsec.
_NUMERIC_C_SOURCE = r"""
__attribute__((noinline))
int target(void) {
    return 42;
}

__attribute__((noinline))
int magic(long x) {
    if (x == 0xCAFEBABE) {
        return target();
    }
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    return magic((long)argc);
}
"""


@pytest.fixture(scope="module")
def numeric_check_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Binary with a single 64-bit integer guard on a target function."""
    if not _gcc_available():
        pytest.skip("gcc not available on this runner")
    if not _binsec_available():
        pytest.skip("real binsec not available")

    work = tmp_path_factory.mktemp("integration_numeric")
    src = work / "numeric.c"
    src.write_text(_NUMERIC_C_SOURCE)
    binary = work / "numeric"
    subprocess.run(
        [
            "gcc",
            "-O0",
            "-no-pie",
            "-fno-stack-protector",
            "-o",
            str(binary),
            str(src),
        ],
        check=True,
    )
    return binary


class TestBinsecBasics:
    """Smoke checks that prove the extracted Binsec works at all."""

    def test_version_is_parsed(self) -> None:
        bs = Binsec()
        # We do not enforce a specific version string here: tagged builds
        # produce ``0.10.1``, master builds produce a 7-char git hash.
        # Either is fine, both are non-empty.
        assert bs.info.version is not None
        assert bs.info.raw_version_output

    def test_disasm_runs_on_binary(self, compiled_binary: Path) -> None:
        """``binsec -disasm`` should accept the freshly compiled ELF."""
        bs = Binsec()
        proc = bs.run(["-disasm", str(compiled_binary)], timeout=30)
        # Binsec prints disassembly to stdout, info logs to stderr.
        combined = proc.stdout + proc.stderr
        assert "Linear disassembly" in combined or "<main>" in combined


class TestSSEEndToEnd:
    """Full builder+runner round-trip against a real binsec."""

    def test_reach_target_by_symbol(self, compiled_binary: Path) -> None:
        """SSE starting from ``main`` should reach the ``target`` symbol."""
        bs = Binsec()
        script = ScriptBuilder().starting_from("main").reach("target").build()
        runner = SSERunner(bs)
        result = runner.run(script, compiled_binary, timeout=60)

        # Always print captured output on failure so the CI log is useful
        # without re-running locally.
        if not result.reached:
            print(f"\n=== Binsec returncode: {result.returncode} ===")
            print("=== Script fed ===")
            print(result.script_text)
            print("=== Stdout (first 2000 chars) ===")
            print(result.stdout[:2000])
            print("=== Stderr (first 2000 chars) ===")
            print(result.stderr[:2000])

        assert result.reached, "expected at least one reach event"
        # The reach symbol resolves to the address of <target>; we don't
        # hard-code it here because it varies with the toolchain version.
        assert result.reached[0].path_id >= 0

    def test_script_text_is_preserved_in_result(self, compiled_binary: Path) -> None:
        """``SSEResult.script_text`` must reflect what the builder produced."""
        bs = Binsec()
        builder = ScriptBuilder().starting_from("main").reach("target")
        expected_text = builder.to_sse()

        runner = SSERunner(bs)
        result = runner.run(builder.build(), compiled_binary, timeout=60)

        assert result.script_text == expected_text
        assert "starting from <main>" in result.script_text
        assert "reach <target>" in result.script_text


class TestV3ProjectEndToEnd:
    """End-to-end exercise of the angr-style Project / SimulationManager API.

    Mirrors :class:`TestSSEEndToEnd` but goes through the higher-level
    surface (Project / factory / state / simulation_manager). The intent
    is to catch any regression in the v0.3 layer the same way the v0.2
    integration test caught the parser drift between Binsec versions.
    """

    def test_explore_finds_target_by_symbol(self, compiled_binary: Path) -> None:
        proj = Project(compiled_binary)
        state = proj.factory.entry_state(addr="main")
        simgr = proj.factory.simulation_manager(state)

        simgr.explore(find="target", timeout=60)

        # Diagnostic dump on failure: the captured SSEResult is the same
        # data structure the v0.2 integration test inspects.
        if not simgr.found and simgr.last_result is not None:
            print(f"\n=== returncode: {simgr.last_result.returncode} ===")
            print("=== Script ===")
            print(simgr.last_result.script_text)
            print("=== Stdout (first 2000) ===")
            print(simgr.last_result.stdout[:2000])
            print("=== Stderr (first 2000) ===")
            print(simgr.last_result.stderr[:2000])

        assert simgr.found, "explore() should have populated simgr.found"
        found = simgr.found[0]
        # The new-format Binsec output always includes the symbol next
        # to the address; v0.3 surfaces it on FoundState.symbol.
        assert found.symbol == "<target>"
        assert found.addr > 0
        assert found.path_id >= 0

    def test_explore_finds_target_by_address(self, compiled_binary: Path) -> None:
        """Resolve <target> via a first run, then re-explore by address.

        This double-pass also confirms that two Project instances over
        the same binary do not interfere with each other.
        """
        # First pass: get the address of <target> from the symbol match.
        proj = Project(compiled_binary)
        state = proj.factory.entry_state(addr="main")
        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find="target", timeout=60)
        assert simgr.found, "first pass must resolve <target> by symbol"
        target_addr = simgr.found[0].addr

        # Second pass: same target, but expressed as a raw integer.
        proj2 = Project(compiled_binary)
        state2 = proj2.factory.entry_state(addr="main")
        simgr2 = proj2.factory.simulation_manager(state2)
        simgr2.explore(find=target_addr, timeout=60)

        assert simgr2.found, "second pass should match by integer address"
        assert simgr2.found[0].addr == target_addr

    def test_blank_state_with_explicit_entry(self, compiled_binary: Path) -> None:
        """``blank_state`` with an explicit address starts where we say.

        We start from the resolved address of ``main`` (computed via a
        first symbol-based pass) and verify the run still hits target.
        """
        proj = Project(compiled_binary)

        # Resolve the address of main via a smoke run from the symbol.
        state0 = proj.factory.entry_state(addr="main")
        simgr0 = proj.factory.simulation_manager(state0)
        simgr0.explore(find="main", timeout=60)
        if not simgr0.found:
            pytest.skip("could not resolve <main> address on this binary")
        main_addr = simgr0.found[0].addr

        # Now use blank_state with the resolved integer entry.
        state = proj.factory.blank_state(addr=main_addr)
        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find="target", timeout=60)

        assert simgr.found, "explore from explicit main address should still reach target"


class TestV31AutoPrintEndToEnd:
    """End-to-end auto-print: a BVS reaches Binsec, gets printed, comes back.

    The numeric_check_binary has ``magic(long x)`` guarded by
    ``x == 0xCAFEBABE`` before calling ``target``. Starting symbolic
    execution from ``magic`` with a BVS plugged into rdi, the only way
    to reach ``target`` is for x to equal 0xCAFEBABE, so Binsec's
    printed concrete value must be exactly that.

    This is the test that justified the v0.3.1 feature: without
    auto-print, ``found.solver.eval(arg)`` would always raise
    KeyError, making the API unusable in practice.
    """

    def test_solver_eval_returns_concrete_input(self, numeric_check_binary: Path) -> None:
        proj = Project(numeric_check_binary)
        # Start at <magic> directly: rdi already holds the long arg per
        # System V x86-64 ABI, so we don't need to model main's prologue.
        state = proj.factory.entry_state(addr="magic")
        arg = state.solver.BVS("arg", 64)
        state.regs.rdi = arg

        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find="target", timeout=60)

        if not simgr.found and simgr.last_result is not None:
            print(f"\n=== returncode: {simgr.last_result.returncode} ===")
            print("=== Script ===")
            print(simgr.last_result.script_text)
            print("=== Stdout (first 2000) ===")
            print(simgr.last_result.stdout[:2000])
            print("=== Stderr (first 2000) ===")
            print(simgr.last_result.stderr[:2000])

        assert simgr.found, "target should be reachable when arg == 0xCAFEBABE"
        found = simgr.found[0]

        # The printed key must match the auto-print output produced by
        # SimulationManager. Surface it for diagnostics on failure.
        if not found.solver.has(arg):
            print(f"\n=== values printed by Binsec: {found.values} ===")
            if simgr.last_result is not None:
                print("=== Stdout (first 4000) ===")
                print(simgr.last_result.stdout[:4000])

        assert found.solver.has(arg), "BVS should have been auto-printed by Binsec"
        assert found.solver.eval(arg) == 0xCAFEBABE

    def test_auto_print_disabled_drops_values(self, numeric_check_binary: Path) -> None:
        """With ``auto_print=False``, Binsec prints nothing for the BVS.

        Confirms that the explicit opt-out works end-to-end and that
        :meth:`FoundSolver.eval` correctly raises when no value was
        recorded.
        """
        proj = Project(numeric_check_binary)
        state = proj.factory.entry_state(addr="magic")
        arg = state.solver.BVS("arg", 64)
        state.regs.rdi = arg

        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find="target", timeout=60, auto_print=False)

        assert simgr.found, "target should still be reachable"
        found = simgr.found[0]
        assert not found.solver.has(arg)
        with pytest.raises(KeyError):
            found.solver.eval(arg)


class TestOfficialMagicQuickstart:
    """Reproduce Binsec's canonical ``magic`` SSE quickstart with pybinsec.

    The ``magic`` binary and the reference ``crackme.ini`` script live
    in the official binsec/binsec Docker image at
    ``/home/binsec/examples/sse/quickstart``. The CI's ``test-binsec``
    job extracts the binary alongside the binsec executable and exposes
    its path through the ``PYBINSEC_OFFICIAL_MAGIC`` env var.

    The reference script is::

        starting from <magic>
        esp := 0xffffccf1
        return_address<32> := 0x0804812b
        @[esp, 4] := return_address
        arg<32> := @[esp + 4, 4]
        reach return_address such that al <> 0 then print arg
        cut at return_address

    Expected Binsec output (from the official README):

        [sse:result] Value arg<32> : 0xc0dedead

    If pybinsec reaches the same conclusion via the same script
    structure, we can claim parity with the canonical reference
    workflow on this benchmark.
    """

    @pytest.fixture(scope="class")
    def magic_binary(self) -> Path:
        """Path to the official magic binary, exposed by the CI."""
        path = os.environ.get("PYBINSEC_OFFICIAL_MAGIC")
        if not path:
            pytest.skip(
                "PYBINSEC_OFFICIAL_MAGIC env var not set; the canonical "
                "magic binary is only available in the test-binsec CI job "
                "that extracts it from the binsec/binsec Docker image."
            )
        binary = Path(path)
        if not binary.is_file():
            pytest.skip(f"PYBINSEC_OFFICIAL_MAGIC points to a missing file: {path}")
        return binary

    def test_recover_secret_with_script_builder(self, magic_binary: Path) -> None:
        """Low-level :class:`ScriptBuilder` reproduction of crackme.ini.

        Mirrors examples/01_sse_magic.py one for one and checks that
        Binsec recovers the documented secret 0xc0dedead in the
        captured ``arg<32>`` variable.
        """
        return_addr = 0x0804812B
        bs = Binsec()
        script = (
            ScriptBuilder()
            .starting_from("magic")
            .init("esp", 0xFFFFCCF1)
            .init("return_address", return_addr, size=32)
            .init_memory("esp", "return_address", size=4)
            .init("arg", "@[esp + 4, 4]", size=32)
            .reach(return_addr, such_that="al <> 0", then="print arg")
            .cut_at(return_addr)
            .build()
        )
        runner = SSERunner(bs)
        result = runner.run(script, magic_binary, timeout=60)

        if not result.reached:
            print(f"\n=== returncode: {result.returncode} ===")
            print("=== Script ===")
            print(result.script_text)
            print("=== Stdout (first 3000) ===")
            print(result.stdout[:3000])
            print("=== Stderr (first 2000) ===")
            print(result.stderr[:2000])

        assert result.reached, "binsec should reach the post-magic point with al != 0"

        # Look for the documented secret across all reach events. The
        # iteration is defensive: a single reach is the expected case
        # but Binsec can in principle emit more.
        recovered = [rp.values.get("arg<32>") for rp in result.reached]
        assert 0xC0DEDEAD in recovered, (
            f"expected arg<32> == 0xc0dedead in the recovered values, " f"got: {recovered}"
        )

    # NOTE: a Project / SimulationManager reproduction of this same
    # crackme requires ``simgr.explore(such_that=...)`` (or a
    # ``find_when=`` keyword) to express the ``reach return_address
    # such that al <> 0`` filter from the reference script. The current
    # API only exposes ``state.add_constraint(...)`` which is an
    # ``assume`` directive applied early, not a per-reach filter.
    # Tracked as a v0.4 API extension candidate.

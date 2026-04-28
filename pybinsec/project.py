"""Layer 3: idiomatic symbolic-execution API on top of the SSE runner.

The shape of this API is intentionally close to `angr <https://angr.io>`_'s
so that downstream code (e.g. a JNI analyser like Kharon) can swap the
backend with minimal surface change. Binsec is a *static* symbolic
execution engine driven by a declarative script, so a few angr concepts
do not translate directly:

- there is no ``step()`` or single-instruction interleaving,
- state is configured up front and explored in one batch,
- ``solver.eval`` reads from the textual results Binsec already
  produced, not from a live SMT context.

In return, ``simgr.explore(find=..., avoid=...)`` is one synchronous
call that compiles the accumulated state into an SSE script, runs
Binsec, and populates ``found`` / ``avoided``.

Example::

    from pybinsec import Project

    proj = Project("/path/to/check")
    state = proj.factory.entry_state(addr="main")
    state.regs.rsp = 0x7FFFFFFFD8E0

    arg0 = state.solver.BVS("arg0", 64)
    state.regs.rdi = arg0

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find="target", avoid=[0x401200])

    for found in simgr.found:
        print(f"path {found.path_id} -> {found.symbol or hex(found.addr)}")
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from pybinsec._binsec import Binsec
from pybinsec.sse.builder import ScriptBuilder
from pybinsec.sse.runner import CutPoint, ReachedPoint, SSEResult, SSERunner
from pybinsec.sse.script import AddressLike, ExprLike

# ---------------------------------------------------------------------------
# Symbolic values
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SymbolicValue:
    """A named symbolic variable with a fixed bit-width.

    Returned by :meth:`Solver.BVS`. Renders to the SSE form
    ``name<size>`` when interpolated into a script.
    """

    name: str
    size: int

    def to_sse(self) -> str:
        return f"{self.name}<{self.size}>"

    def __repr__(self) -> str:
        return f"<sym {self.name}<{self.size}>>"


# ---------------------------------------------------------------------------
# State views
# ---------------------------------------------------------------------------


def _render_value(value: Any) -> ExprLike:
    """Convert a Python-side value into something the SSE builder accepts.

    - ``SymbolicValue`` is rendered to its typed-variable form.
    - ``int`` and ``str`` are passed through (the builder hex-encodes
      ints and treats strings as raw SSE expressions).
    """
    if isinstance(value, SymbolicValue):
        return value.to_sse()
    if isinstance(value, int | str):
        return value
    raise TypeError(
        f"Cannot use {type(value).__name__} as a register/memory value. "
        "Pass an int, a SymbolicValue (from solver.BVS), or a raw SSE "
        "expression string."
    )


class _RegisterView:
    """Proxy that turns ``state.regs.rsp = 0x...`` into an SSE init.

    Attribute writes are intercepted; attribute reads are not supported
    (Binsec is batch-driven, there is no live register value to read).
    """

    def __init__(self, state: State) -> None:
        # Bypass our own __setattr__ to install the back-reference.
        object.__setattr__(self, "_state", state)

    def __setattr__(self, name: str, value: Any) -> None:
        # Allow internal attributes (only "_state" today).
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return
        state: State = object.__getattribute__(self, "_state")
        state._set_register(name, value)

    def __setitem__(self, name: str, value: Any) -> None:
        # Dictionary-style alias for callers who prefer it or whose
        # register names are dynamic.
        state: State = object.__getattribute__(self, "_state")
        state._set_register(name, value)


class _MemoryView:
    """Proxy for memory writes on a :class:`State`."""

    def __init__(self, state: State) -> None:
        self._state = state

    def store(self, address: ExprLike, value: Any, *, size: int = 1) -> None:
        """Initialize a memory cell: ``@[address, size] := value``."""
        self._state._set_memory(address, value, size)


class Solver:
    """Per-state solver: creates fresh symbolic variables.

    A real SMT solving step (``eval`` of arbitrary expressions) is only
    available *after* exploration, on a :class:`FoundState`. See
    :class:`FoundSolver`.
    """

    __slots__ = ("_state",)

    def __init__(self, state: State) -> None:
        self._state = state

    def BVS(self, name: str, size: int) -> SymbolicValue:
        """Declare a fresh symbolic bit-vector.

        Emits ``name<size> := nondet`` into the script and returns a
        :class:`SymbolicValue` so the caller can plug it into a register
        or memory location.
        """
        if size <= 0:
            raise ValueError(f"BVS size must be positive, got {size}")
        if not name or not name[0].isalpha():
            raise ValueError(
                f"BVS name must start with a letter, got {name!r}. "
                "SSE variable names follow the C identifier convention."
            )
        self._state._declare_symbolic(name, size)
        return SymbolicValue(name=name, size=size)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class State:
    """A symbolic state ready to be explored.

    Construction is done via :meth:`ProjectFactory.entry_state` or
    :meth:`ProjectFactory.blank_state`. Configuration is done by
    assigning to ``state.regs.<name>``, calling ``state.mem.store(...)``,
    declaring symbolic variables via ``state.solver.BVS(...)``, and
    optionally adding constraints via :meth:`add_constraint`.

    Internally, every action appends a directive to a private
    :class:`~pybinsec.sse.builder.ScriptBuilder`. The final script is
    assembled at :meth:`SimulationManager.explore` time, so the order
    in which the caller configures the state matches the order of
    directives in the generated SSE script.
    """

    def __init__(self, project: Project, entry: AddressLike | None = None) -> None:
        self._project = project
        self._entry = entry
        self._builder = ScriptBuilder()
        self._regs = _RegisterView(self)
        self._mem = _MemoryView(self)
        self._solver = Solver(self)

    @property
    def regs(self) -> _RegisterView:
        """Proxy for register initialization. ``state.regs.rsp = 0x...``."""
        return self._regs

    @property
    def mem(self) -> _MemoryView:
        """Memory accessor. ``state.mem.store(addr, value, size=...)``."""
        return self._mem

    @property
    def solver(self) -> Solver:
        """Per-state solver for declaring fresh symbolic variables."""
        return self._solver

    @property
    def entry(self) -> AddressLike | None:
        """The address (or symbol) this state starts execution at."""
        return self._entry

    def add_constraint(self, cond: ExprLike) -> None:
        """Add an ``assume`` directive over the symbolic state."""
        self._builder.assume(cond)

    # -- internals used by the views -------------------------------------

    def _set_register(self, name: str, value: Any) -> None:
        self._builder.init(name, _render_value(value))

    def _set_memory(self, addr: ExprLike, value: Any, size: int) -> None:
        self._builder.init_memory(addr, _render_value(value), size=size)

    def _declare_symbolic(self, name: str, size: int) -> None:
        self._builder.init(name, "nondet", size=size)


# ---------------------------------------------------------------------------
# Result-side classes (post-exploration)
# ---------------------------------------------------------------------------


class FoundSolver:
    """Solver attached to a :class:`FoundState`.

    Looks up concrete values that Binsec already printed for the state
    via ``reach(..., then=\"print ...\")``. There is no live SMT context
    in this version: an expression is evaluable iff Binsec printed it.
    """

    __slots__ = ("_fs",)

    def __init__(self, fs: FoundState) -> None:
        self._fs = fs

    def eval(self, expr: SymbolicValue | str) -> int:
        """Return the concrete value Binsec found for ``expr``.

        Raises :class:`KeyError` if no value was printed; the exception
        message lists the keys that *are* available.
        """
        key = self._key(expr)
        try:
            return self._fs._values[key]
        except KeyError as exc:
            available = sorted(self._fs._values)
            raise KeyError(
                f"No concrete value recorded for {key!r}. "
                "Did you ask Binsec to print it via reach(..., then='print ...')? "
                f"Available keys: {available}"
            ) from exc

    def has(self, expr: SymbolicValue | str) -> bool:
        """True if Binsec recorded a value for ``expr``."""
        return self._key(expr) in self._fs._values

    @staticmethod
    def _key(expr: SymbolicValue | str) -> str:
        if isinstance(expr, SymbolicValue):
            return expr.to_sse()
        return str(expr).strip()


class FoundState:
    """A reached point in the post-exploration result.

    Carries the path id, the resolved address, the optional symbol, and
    a :class:`FoundSolver` to look up printed values.
    """

    __slots__ = ("_parent", "_values", "addr", "path_id", "symbol")

    def __init__(self, rp: ReachedPoint, parent: State) -> None:
        self.addr: int = rp.address
        self.path_id: int = rp.path_id
        self.symbol: str | None = rp.symbol
        self._values: dict[str, int] = dict(rp.values)
        self._parent = parent

    @property
    def solver(self) -> FoundSolver:
        return FoundSolver(self)

    @property
    def values(self) -> dict[str, int]:
        """Read-only view of the values Binsec printed for this state."""
        return dict(self._values)

    def __repr__(self) -> str:
        sym = f" ({self.symbol})" if self.symbol else ""
        return f"<FoundState path={self.path_id} addr=0x{self.addr:x}{sym}>"


# ---------------------------------------------------------------------------
# SimulationManager
# ---------------------------------------------------------------------------


_TargetLike = AddressLike
_TargetsArg = _TargetLike | Sequence[_TargetLike] | None


class SimulationManager:
    """Drives Binsec on a configured :class:`State`.

    ``explore`` is the single entry point: it compiles the state into
    an SSE script, runs Binsec, and partitions the results into
    :attr:`found` and :attr:`avoided`. There is no incremental stepping
    in this version (Binsec does not expose one).
    """

    def __init__(self, project: Project, state: State) -> None:
        self._project = project
        self._state = state
        self.found: list[FoundState] = []
        self.avoided: list[CutPoint] = []
        self._last_result: SSEResult | None = None

    @property
    def last_result(self) -> SSEResult | None:
        """The raw :class:`SSEResult` from the most recent ``explore``."""
        return self._last_result

    def explore(
        self,
        *,
        find: _TargetsArg = None,
        avoid: _TargetsArg = None,
        timeout: float | None = None,
        extra_args: list[str] | None = None,
    ) -> SimulationManager:
        """Run Binsec on the state with one or more targets.

        Args:
            find: One target (address or symbol) or a sequence of targets
                to ``reach`` in the SSE script.
            avoid: One target or a sequence of targets to ``cut at``.
            timeout: Wall-clock timeout passed to the underlying runner.
            extra_args: Additional Binsec CLI flags (e.g.
                ``["-sse-timeout", "30"]``).

        Returns:
            ``self`` for chaining.

        Raises:
            ValueError: If neither ``find`` nor ``avoid`` is provided,
                or if the state has no entry point.
        """
        if find is None and avoid is None:
            raise ValueError("explore() needs at least one of find= or avoid=.")
        if self._state.entry is None:
            raise ValueError(
                "State has no entry point. Build it with "
                "project.factory.entry_state(addr=...) or .blank_state(addr=...)."
            )

        finds = self._normalize(find)
        avoids = self._normalize(avoid)

        script = self._compile_script(finds, avoids)
        runner = SSERunner(self._project._binsec)
        result = runner.run(
            script,
            self._project.binary,
            timeout=timeout,
            extra_args=extra_args,
        )
        self._last_result = result

        for rp in result.reached:
            if self._matches_any(rp, finds):
                self.found.append(FoundState(rp, self._state))

        self.avoided = list(result.cuts)
        return self

    # -- internals -------------------------------------------------------

    def _compile_script(
        self,
        finds: list[_TargetLike],
        avoids: list[_TargetLike],
    ) -> Any:  # Script, but importing here would be circular noise
        """Assemble: starting_from + state inits + reach(es) + cut(s)."""
        sb = ScriptBuilder()
        # 1. entry point first (mandatory in SSE syntax)
        assert self._state.entry is not None  # guarded above
        sb.starting_from(self._state.entry)
        # 2. replay every directive the state accumulated, in order
        for directive in self._state._builder.build().directives:
            sb._script.add(directive)
        # 3. reach / cut directives
        for f in finds:
            sb.reach(f)
        for a in avoids:
            sb.cut_at(a)
        return sb.build()

    @staticmethod
    def _normalize(arg: _TargetsArg) -> list[_TargetLike]:
        if arg is None:
            return []
        if isinstance(arg, list | tuple | set):
            return list(arg)
        # Past the isinstance checks above, ``arg`` is a single target
        # (int / str / Sym), but mypy can't fully narrow the union.
        return [cast("_TargetLike", arg)]

    @staticmethod
    def _matches_any(rp: ReachedPoint, finds: Sequence[_TargetLike]) -> bool:
        """Did this reached point hit one of the requested targets?

        Matching is intentionally permissive:
        - integer addresses match by exact address;
        - symbol strings match either by exact symbol (after stripping
          angle brackets) or, fallback, by string comparison on the
          address rendering.
        """
        for f in finds:
            if isinstance(f, int) and rp.address == f:
                return True
            if isinstance(f, str):
                stripped = f.strip("<>")
                rp_sym = (rp.symbol or "").strip("<>")
                if rp_sym and rp_sym == stripped:
                    return True
        return False


# ---------------------------------------------------------------------------
# Factory and Project
# ---------------------------------------------------------------------------


class ProjectFactory:
    """Produces :class:`State` and :class:`SimulationManager` instances."""

    def __init__(self, project: Project) -> None:
        self._project = project

    def entry_state(self, addr: AddressLike | None = None) -> State:
        """Create a state to start exploration from.

        Args:
            addr: Address or symbol to start from. Defaults to ``"main"``.
        """
        return State(self._project, entry=addr if addr is not None else "main")

    def blank_state(self, addr: AddressLike) -> State:
        """Create a state with no implicit defaults, anchored at ``addr``."""
        return State(self._project, entry=addr)

    def simulation_manager(self, state: State) -> SimulationManager:
        return SimulationManager(self._project, state)


class Project:
    """A target binary plus the Binsec instance that will analyse it.

    Mirrors angr's ``angr.Project`` in spirit, with the much narrower
    scope appropriate to a static symbolic execution backend.
    """

    def __init__(
        self,
        binary: str | os.PathLike[str],
        *,
        binsec: Binsec | None = None,
    ) -> None:
        self._binary = Path(binary)
        if not self._binary.is_file():
            raise FileNotFoundError(f"Binary not found: {self._binary}")
        self._binsec = binsec if binsec is not None else Binsec()
        self._factory = ProjectFactory(self)

    @property
    def factory(self) -> ProjectFactory:
        return self._factory

    @property
    def binary(self) -> Path:
        return self._binary

    @property
    def binsec(self) -> Binsec:
        return self._binsec

    def __repr__(self) -> str:
        return f"<Project binary={self._binary.name} binsec={self._binsec.path.name}>"

"""AST and text rendering for Binsec SSE scripts.

A Binsec SSE script is a sequence of directives in a domain-specific
language. This module models a useful subset as immutable dataclasses
and renders them back to text via ``to_sse()`` methods, so that scripts
can be built programmatically and fed to ``binsec -sse -sse-script``.

The directives supported in this version cover the common use cases
seen in the Binsec tutorial (``magic`` crackme) and in published CTF
write-ups: ``starting from``, variable/memory initialization,
``reach``, ``cut``, ``replace``, ``assume``, ``assert``, ``print``.

Expressions are deliberately kept loose: callers may use the helper
constructors (:class:`Const`, :class:`Var`, :class:`Mem`, :class:`Sym`,
:class:`BinOp`) for composition, or pass a raw string for any
expression that the AST does not model. ``to_sse()`` will render raw
strings verbatim. This keeps the surface area small while giving an
escape hatch for the long tail of DBA expressions.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Union

from pybinsec.exceptions import ScriptError

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

#: An address can be either an integer (rendered as 0x...) or a symbol
#: string (rendered as ``<name>``). Symbols are wrapped if they don't
#: already include the angle brackets.
AddressLike = Union[int, str, "Sym"]

#: An expression is either a typed AST node, an int (treated as a
#: constant of natural width), or a raw string passed through unchanged.
ExprLike = Union["Expr", int, str]


# ---------------------------------------------------------------------------
# Expression AST
# ---------------------------------------------------------------------------


class Expr:
    """Base class for SSE expressions.

    Subclasses implement :meth:`to_sse` to produce the textual form.
    """

    def to_sse(self) -> str:  # pragma: no cover - abstract
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class Const(Expr):
    """A typed constant. ``Const(0x401234, 64)`` renders as ``0x401234<64>``."""

    value: int
    size: int | None = None

    def to_sse(self) -> str:
        if self.size is None:
            return _hex(self.value)
        return f"{_hex(self.value)}<{self.size}>"


@dataclass(frozen=True, slots=True)
class Var(Expr):
    """A typed variable. ``Var("goal", 64)`` renders as ``goal<64>``."""

    name: str
    size: int | None = None

    def to_sse(self) -> str:
        if self.size is None:
            return self.name
        return f"{self.name}<{self.size}>"


@dataclass(frozen=True, slots=True)
class Reg(Expr):
    """A CPU register, rendered as its plain name (e.g. ``rsp``, ``eax``).

    Registers are untyped in SSE script syntax: their width is fixed by
    the ISA.
    """

    name: str

    def to_sse(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class Mem(Expr):
    """A memory access: ``Mem(addr, size)`` renders as ``@[addr, size]``.

    ``size`` is the access width in bytes. ``addr`` may be any
    expression-like value.
    """

    addr: ExprLike
    size: int = 1

    def to_sse(self) -> str:
        return f"@[{_render_expr(self.addr)}, {self.size}]"


@dataclass(frozen=True, slots=True)
class Sym(Expr):
    """A binary symbol: ``Sym("main")`` renders as ``<main>``."""

    name: str

    def to_sse(self) -> str:
        if self.name.startswith("<") and self.name.endswith(">"):
            return self.name
        return f"<{self.name}>"


@dataclass(frozen=True, slots=True)
class BinOp(Expr):
    """A binary operation: ``BinOp(a, "+", b)`` renders as ``(a + b)``.

    No precedence handling: parentheses are always added so that the
    result is unambiguous regardless of operator priority. Callers who
    want a flatter rendering can pass a raw string instead.
    """

    left: ExprLike
    op: str
    right: ExprLike

    def to_sse(self) -> str:
        return f"({_render_expr(self.left)} {self.op} {_render_expr(self.right)})"


@dataclass(frozen=True, slots=True)
class Nondet(Expr):
    """The ``nondet`` keyword: a fresh non-deterministic value."""

    def to_sse(self) -> str:
        return "nondet"


# Singleton-style helper.
NONDET = Nondet()


# ---------------------------------------------------------------------------
# Directives
# ---------------------------------------------------------------------------


class Directive:
    """Base class for top-level SSE script directives."""

    def to_sse(self) -> str:  # pragma: no cover - abstract
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class StartingFrom(Directive):
    """``starting from <addr>`` or ``starting from core``.

    Pass ``"core"`` (or any other non-int symbolic word) to use a
    pre-recorded core dump as the entry state.
    """

    address: AddressLike

    def to_sse(self) -> str:
        if isinstance(self.address, str) and self.address == "core":
            return "starting from core"
        return f"starting from {_render_address(self.address)}"


@dataclass(frozen=True, slots=True)
class Initialize(Directive):
    """A top-level assignment: ``<lhs> := <rhs>``.

    Used to fix the initial value of a register, memory cell, or a
    fresh declared variable. Examples:

    - ``Initialize(Reg("rsp"), 0x7fffffffd8e0)`` -> ``rsp := 0x7fffffffd8e0``
    - ``Initialize(Var("goal", 64), 0x401234)`` -> ``goal<64> := 0x401234``
    - ``Initialize(Mem(Reg("rdi"), 8), NONDET)`` -> ``@[rdi, 8] := nondet``
    """

    lhs: ExprLike
    rhs: ExprLike

    def to_sse(self) -> str:
        return f"{_render_expr(self.lhs)} := {_render_expr(self.rhs)}"


@dataclass(frozen=True, slots=True)
class Reach(Directive):
    """``reach <addr> [n times] [such that <cond>] [then <action>]``.

    Args:
        address: Address (or symbol) to reach.
        times: Number of times to reach it. ``None`` means once.
        such_that: Optional condition that must hold at the reach point.
        then: Optional action when reached, e.g. ``"print arg"``.
    """

    address: AddressLike
    times: int | None = None
    such_that: ExprLike | None = None
    then: str | None = None

    def to_sse(self) -> str:
        out = [f"reach {_render_address(self.address)}"]
        if self.times is not None:
            out.append(f"{self.times} times")
        if self.such_that is not None:
            out.append(f"such that {_render_expr(self.such_that)}")
        if self.then is not None:
            out.append(f"then {self.then}")
        return " ".join(out)


@dataclass(frozen=True, slots=True)
class Cut(Directive):
    """``cut at <addr> [if <cond>]``.

    Stops exploration of any path that reaches ``address``. The
    optional condition gates the cut.
    """

    address: AddressLike
    if_cond: ExprLike | None = None

    def to_sse(self) -> str:
        out = f"cut at {_render_address(self.address)}"
        if self.if_cond is not None:
            out += f" if {_render_expr(self.if_cond)}"
        return out


@dataclass(frozen=True, slots=True)
class Assume(Directive):
    """``assume <cond>``: constrain the symbolic state."""

    cond: ExprLike

    def to_sse(self) -> str:
        return f"assume {_render_expr(self.cond)}"


@dataclass(frozen=True, slots=True)
class Assert(Directive):
    """``assert <cond>``: report a failure if the condition can be false."""

    cond: ExprLike

    def to_sse(self) -> str:
        return f"assert {_render_expr(self.cond)}"


@dataclass(frozen=True, slots=True)
class Print(Directive):
    """``print <expr>``: dump a value at the current program point."""

    expr: ExprLike

    def to_sse(self) -> str:
        return f"print {_render_expr(self.expr)}"


@dataclass(frozen=True, slots=True)
class Replace(Directive):
    """``replace <sym1>[, <sym2>...] by <body> end``.

    Replaces the body of one or more symbols (typically library
    functions like ``puts`` or ``__isoc99_scanf``) with a custom
    sequence of statements, terminated by ``end``.

    The ``body`` argument is a sequence of strings or :class:`Initialize`
    directives. Each entry becomes one line inside the replace block.
    """

    symbols: Sequence[Sym | str]
    body: Sequence[Initialize | str]

    def to_sse(self) -> str:
        if not self.symbols:
            raise ScriptError("Replace requires at least one symbol")
        head = ", ".join(_render_address(s) for s in self.symbols)
        lines = [f"replace {head} by"]
        for stmt in self.body:
            rendered = stmt.to_sse() if isinstance(stmt, Initialize) else str(stmt)
            lines.append(f"    {rendered}")
        lines.append("end")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Top-level container
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Script:
    """A complete SSE script: a sequence of directives.

    Instances are mutable so that builders can append directives
    progressively. The conventional rendering puts one directive per
    line; multi-line directives like :class:`Replace` are kept intact.
    """

    directives: list[Directive] = field(default_factory=list)

    def add(self, directive: Directive) -> Script:
        """Append a directive in place and return self for chaining."""
        self.directives.append(directive)
        return self

    def extend(self, directives: Iterable[Directive]) -> Script:
        for d in directives:
            self.add(d)
        return self

    def to_sse(self) -> str:
        """Render the full script as a single text blob with a trailing newline."""
        lines = [d.to_sse() for d in self.directives]
        return "\n".join(lines) + ("\n" if lines else "")

    def __str__(self) -> str:
        return self.to_sse()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _hex(value: int) -> str:
    """Render an integer as 0x-prefixed lower-case hex, no padding."""
    return f"0x{value:x}" if value >= 0 else f"-0x{-value:x}"


def _render_expr(e: ExprLike) -> str:
    """Render an expression-like value to its SSE text form."""
    if isinstance(e, Expr):
        return e.to_sse()
    if isinstance(e, bool):
        # Catch this before int because bool is a subclass of int and we
        # want True/False to show up as the words, not 0x1/0x0.
        return "true" if e else "false"
    if isinstance(e, int):
        return _hex(e)
    if isinstance(e, str):
        return e
    raise ScriptError(f"Cannot render value of type {type(e).__name__}: {e!r}")


def _render_address(a: AddressLike) -> str:
    """Render an address-like value (int, symbol string, or Sym)."""
    if isinstance(a, Sym):
        return a.to_sse()
    if isinstance(a, int):
        return _hex(a)
    if isinstance(a, str):
        # Bare names get wrapped as symbols; pre-wrapped <names> are
        # passed through unchanged.
        if a.startswith("<") and a.endswith(">"):
            return a
        # Hex literals are accepted as-is so callers can pass "0x1234"
        # directly without converting.
        if a.startswith(("0x", "0X")):
            return a
        return f"<{a}>"
    raise ScriptError(f"Cannot render address of type {type(a).__name__}: {a!r}")

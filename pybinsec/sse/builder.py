"""Fluent builder API for SSE scripts.

This is a thin layer over :mod:`pybinsec.sse.script` that lets callers
chain method calls instead of constructing dataclass instances by hand.

Example:
    >>> from pybinsec.sse import ScriptBuilder
    >>> text = (
    ...     ScriptBuilder()
    ...     .starting_from(0x401234)
    ...     .init("rsp", 0x7fffffffd8e0)
    ...     .reach(0x401300, then="print eax")
    ...     .cut_at(0x401400)
    ...     .build()
    ...     .to_sse()
    ... )
"""

from __future__ import annotations

from collections.abc import Sequence

from pybinsec.sse.script import (
    AddressLike,
    Assert,
    Assume,
    Cut,
    ExprLike,
    Initialize,
    Print,
    Reach,
    Reg,
    Replace,
    Script,
    StartingFrom,
    Sym,
    Var,
)


class ScriptBuilder:
    """Fluent builder that produces a :class:`Script`.

    Every method returns ``self`` so that calls chain. Call
    :meth:`build` (or :meth:`to_sse`) when you are done.
    """

    def __init__(self) -> None:
        self._script = Script()

    # -- entry point ------------------------------------------------------

    def starting_from(self, address: AddressLike) -> ScriptBuilder:
        """Set the analysis entry point.

        Pass ``"core"`` to start from a recorded core dump.
        """
        self._script.add(StartingFrom(address))
        return self

    # -- initializers -----------------------------------------------------

    def init(
        self,
        target: str | Var | Reg,
        value: ExprLike,
        *,
        size: int | None = None,
    ) -> ScriptBuilder:
        """Initialize a variable or register.

        - If ``target`` is a string and ``size`` is given, a fresh typed
          variable is declared (e.g. ``init("goal", 0x401234, size=64)``
          becomes ``goal<64> := 0x401234``).
        - If ``target`` is a string and ``size`` is omitted, it's treated
          as an existing register (e.g. ``init("rsp", 0x7fff...)`` becomes
          ``rsp := 0x7fff...``).
        - If ``target`` is already a :class:`Var` or :class:`Reg`, it is
          used directly.
        """
        if isinstance(target, str):
            target_node: Var | Reg = Var(target, size) if size is not None else Reg(target)
        else:
            target_node = target
        self._script.add(Initialize(target_node, value))
        return self

    def init_memory(
        self,
        address: ExprLike,
        value: ExprLike,
        *,
        size: int = 1,
    ) -> ScriptBuilder:
        """Initialize a memory cell: ``@[address, size] := value``."""
        from pybinsec.sse.script import Mem

        self._script.add(Initialize(Mem(address, size), value))
        return self

    # -- exploration directives ------------------------------------------

    def reach(
        self,
        address: AddressLike,
        *,
        times: int | None = None,
        such_that: ExprLike | None = None,
        then: str | None = None,
    ) -> ScriptBuilder:
        """Add a ``reach`` directive."""
        self._script.add(Reach(address=address, times=times, such_that=such_that, then=then))
        return self

    def cut_at(
        self,
        address: AddressLike,
        *,
        if_cond: ExprLike | None = None,
    ) -> ScriptBuilder:
        """Add a ``cut at`` directive."""
        self._script.add(Cut(address=address, if_cond=if_cond))
        return self

    def assume(self, cond: ExprLike) -> ScriptBuilder:
        """Add an ``assume`` directive."""
        self._script.add(Assume(cond))
        return self

    def assert_(self, cond: ExprLike) -> ScriptBuilder:
        """Add an ``assert`` directive.

        Underscored to avoid shadowing the Python ``assert`` keyword.
        """
        self._script.add(Assert(cond))
        return self

    def print(self, expr: ExprLike) -> ScriptBuilder:
        """Add a ``print`` directive."""
        self._script.add(Print(expr))
        return self

    def replace(
        self,
        symbols: str | Sym | Sequence[str | Sym],
        body: Sequence[Initialize | str],
    ) -> ScriptBuilder:
        """Add a ``replace ... by ... end`` block.

        Args:
            symbols: One symbol name or a sequence of symbol names.
                Bare names (``"puts"``) are auto-wrapped in angle
                brackets.
            body: Sequence of statements (strings rendered verbatim,
                or :class:`Initialize` instances).
        """
        if isinstance(symbols, (str, Sym)):
            symbols_seq: Sequence[str | Sym] = [symbols]
        else:
            symbols_seq = list(symbols)
        self._script.add(Replace(symbols=symbols_seq, body=list(body)))
        return self

    # -- escape hatch ----------------------------------------------------

    def raw(self, line: str) -> ScriptBuilder:
        """Append a raw line of SSE script text.

        Useful for directives the builder does not model yet (e.g.
        ``for ... in ... do ... end`` loops). The line is rendered
        verbatim, so callers are responsible for its syntactic
        correctness.
        """
        from pybinsec.sse.script import Directive

        class _Raw(Directive):
            __slots__ = ("_text",)

            def __init__(self, text: str) -> None:
                self._text = text

            def to_sse(self) -> str:
                return self._text

        self._script.add(_Raw(line))
        return self

    # -- terminal --------------------------------------------------------

    def build(self) -> Script:
        """Return the assembled :class:`Script`.

        The same builder instance can keep being used after ``build()``
        is called; it returns the same underlying script.
        """
        return self._script

    def to_sse(self) -> str:
        """Convenience: ``builder.build().to_sse()``."""
        return self._script.to_sse()

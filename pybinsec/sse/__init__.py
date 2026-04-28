"""SSE (Static Symbolic Execution) script construction and execution.

Three groups of names are exposed:

- AST nodes for hand-rolled scripts (:class:`Script`, expressions like
  :class:`Const`, :class:`Var`, :class:`Mem`, and directives like
  :class:`Reach`, :class:`Cut`...).
- The fluent :class:`ScriptBuilder` for the common case.
- The :class:`SSERunner` that drives Binsec on a built script.
"""

from pybinsec.sse.builder import ScriptBuilder
from pybinsec.sse.runner import CutPoint, ReachedPoint, SSEResult, SSERunner
from pybinsec.sse.script import (
    NONDET,
    Assert,
    Assume,
    BinOp,
    Const,
    Cut,
    Directive,
    Expr,
    Initialize,
    Mem,
    Nondet,
    Print,
    Reach,
    Reg,
    Replace,
    Script,
    StartingFrom,
    Sym,
    Var,
)

__all__ = [
    "NONDET",
    "Assert",
    "Assume",
    "BinOp",
    "Const",
    "Cut",
    "CutPoint",
    "Directive",
    "Expr",
    "Initialize",
    "Mem",
    "Nondet",
    "Print",
    "Reach",
    "ReachedPoint",
    "Reg",
    "Replace",
    "SSEResult",
    "SSERunner",
    "Script",
    "ScriptBuilder",
    "StartingFrom",
    "Sym",
    "Var",
]

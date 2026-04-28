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
    Abort,
    Assert,
    Assume,
    BinOp,
    Const,
    Cut,
    Directive,
    Expr,
    Halt,
    Initialize,
    LoadFromFile,
    LoadSections,
    Mem,
    Nondet,
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

__all__ = [
    "NONDET",
    "Abort",
    "Assert",
    "Assume",
    "BinOp",
    "Const",
    "Cut",
    "CutPoint",
    "Directive",
    "Expr",
    "Halt",
    "Initialize",
    "LoadFromFile",
    "LoadSections",
    "Mem",
    "Nondet",
    "Print",
    "Reach",
    "ReachedPoint",
    "Reg",
    "Replace",
    "Return",
    "SSEResult",
    "SSERunner",
    "Script",
    "ScriptBuilder",
    "StartingFrom",
    "Sym",
    "Var",
]

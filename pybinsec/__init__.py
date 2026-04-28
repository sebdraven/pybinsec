"""pybinsec — Python bindings and high-level API for Binsec.

This is the public entry point. Three layers are exposed:

- Layer 1: low-level subprocess wrapper (:class:`Binsec`)
- Layer 2: SSE script builder and runner (:mod:`pybinsec.sse`)
- Layer 3: idiomatic symbolic-execution API (planned: ``Project``)
"""

from pybinsec._binsec import Binsec, BinsecInfo, find_binsec
from pybinsec.exceptions import (
    BinsecError,
    BinsecNotFoundError,
    BinsecRuntimeError,
    ParseError,
    PybinsecError,
    ScriptError,
)
from pybinsec.sse import (
    Script,
    ScriptBuilder,
    SSEResult,
    SSERunner,
)

__version__ = "0.2.0.dev0"

__all__ = [
    "Binsec",
    "BinsecError",
    "BinsecInfo",
    "BinsecNotFoundError",
    "BinsecRuntimeError",
    "ParseError",
    "PybinsecError",
    "SSEResult",
    "SSERunner",
    "Script",
    "ScriptBuilder",
    "ScriptError",
    "__version__",
    "find_binsec",
]

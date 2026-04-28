"""pybinsec — Python bindings and high-level API for Binsec.

This is the public entry point. Three layers are exposed:

- Layer 1: low-level subprocess wrapper (:class:`Binsec`)
- Layer 2: SSE script builder and runner (:mod:`pybinsec.sse`)
- Layer 3: angr-style API (:class:`Project`, :class:`SimulationManager`)
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
from pybinsec.project import (
    FoundState,
    Project,
    ProjectFactory,
    SimulationManager,
    State,
    SymbolicValue,
)
from pybinsec.sse import (
    Script,
    ScriptBuilder,
    SSEResult,
    SSERunner,
)

__version__ = "0.3.1.dev0"

__all__ = [
    "Binsec",
    "BinsecError",
    "BinsecInfo",
    "BinsecNotFoundError",
    "BinsecRuntimeError",
    "FoundState",
    "ParseError",
    "Project",
    "ProjectFactory",
    "PybinsecError",
    "SSEResult",
    "SSERunner",
    "Script",
    "ScriptBuilder",
    "ScriptError",
    "SimulationManager",
    "State",
    "SymbolicValue",
    "__version__",
    "find_binsec",
]

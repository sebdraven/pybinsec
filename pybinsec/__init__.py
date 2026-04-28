"""pybinsec — Python bindings and high-level API for Binsec.

This is the public entry point. Three layers are exposed:

- Layer 1: low-level subprocess wrapper (:class:`Binsec`)
- Layer 2: SSE script builder (:mod:`pybinsec.sse`)
- Layer 3: idiomatic symbolic-execution API (planned: ``Project``)
"""

from pybinsec._binsec import Binsec, BinsecInfo, find_binsec
from pybinsec.exceptions import (
    BinsecError,
    BinsecNotFoundError,
    BinsecRuntimeError,
    PybinsecError,
)

__version__ = "0.1.0.dev0"

__all__ = [
    "Binsec",
    "BinsecError",
    "BinsecInfo",
    "BinsecNotFoundError",
    "BinsecRuntimeError",
    "PybinsecError",
    "__version__",
    "find_binsec",
]

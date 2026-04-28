"""SSE (Static Symbolic Execution) script construction and execution.

This subpackage is the heart of the Layer 2 API: building Binsec SSE
scripts programmatically and running them via the :class:`~pybinsec.Binsec`
wrapper.

Modules will be filled in v0.2:

- :mod:`pybinsec.sse.script`: directive AST
- :mod:`pybinsec.sse.builder`: fluent builder API
- :mod:`pybinsec.sse.runner`: execution + output parsing
"""

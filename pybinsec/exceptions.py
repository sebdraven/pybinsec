"""Exception hierarchy for pybinsec."""

from __future__ import annotations


class PybinsecError(Exception):
    """Base class for every error raised by pybinsec."""


class BinsecError(PybinsecError):
    """Errors related to invoking the Binsec binary itself."""


class BinsecNotFoundError(BinsecError):
    """The Binsec binary could not be located.

    Raised when ``binsec`` is not on ``$PATH`` and no explicit path
    was provided through the ``PYBINSEC_BINARY`` environment variable
    or the :class:`~pybinsec.Binsec` constructor.
    """


class BinsecRuntimeError(BinsecError):
    """Binsec was invoked but exited with a non-zero status.

    Attributes:
        returncode: Exit code returned by the Binsec process.
        stderr: Captured standard error output, if any.
        cmd: The exact argv that was executed.
    """

    def __init__(
        self,
        message: str,
        *,
        returncode: int,
        stderr: str = "",
        cmd: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr
        self.cmd = list(cmd) if cmd is not None else []


class ScriptError(PybinsecError):
    """Invalid SSE script construction."""


class ParseError(PybinsecError):
    """Failed to parse Binsec output (logs, SMT models, traces)."""

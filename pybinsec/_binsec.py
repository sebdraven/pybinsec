"""Low-level interface to the ``binsec`` binary.

This module deliberately stays thin: it locates the binary, captures
its version, and runs it. Anything higher-level (script generation,
output parsing, idiomatic API) lives in sibling modules.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from pybinsec.exceptions import BinsecNotFoundError, BinsecRuntimeError

ENV_BINARY = "PYBINSEC_BINARY"

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


@dataclass(frozen=True, slots=True)
class BinsecInfo:
    """Information about a discovered Binsec installation."""

    path: Path
    version: str | None
    raw_version_output: str


def find_binsec(explicit: str | os.PathLike[str] | None = None) -> Path:
    """Locate the ``binsec`` binary.

    Resolution order:
      1. ``explicit`` argument, if provided.
      2. ``PYBINSEC_BINARY`` environment variable.
      3. ``binsec`` on ``$PATH``.

    Raises:
        BinsecNotFoundError: If no binary can be found.
    """
    if explicit is not None:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise BinsecNotFoundError(f"Binsec not found at explicit path: {path}")
        return path.resolve()

    env_path = os.environ.get(ENV_BINARY)
    if env_path:
        path = Path(env_path).expanduser()
        if not path.is_file():
            raise BinsecNotFoundError(f"{ENV_BINARY} points to a non-existent file: {env_path}")
        return path.resolve()

    found = shutil.which("binsec")
    if found is None:
        raise BinsecNotFoundError(
            "Binsec binary not found. Install it from https://github.com/binsec/binsec, "
            f"set ${ENV_BINARY}, or pass an explicit path."
        )
    return Path(found).resolve()


class Binsec:
    """Thin wrapper around the ``binsec`` executable.

    Example:
        >>> bs = Binsec()
        >>> bs.info.version  # doctest: +SKIP
        '0.10.1'
    """

    def __init__(
        self,
        binary: str | os.PathLike[str] | None = None,
        *,
        default_timeout: float | None = None,
    ) -> None:
        self._path = find_binsec(binary)
        self._default_timeout = default_timeout
        self._info: BinsecInfo | None = None

    @property
    def path(self) -> Path:
        """Absolute path to the Binsec binary."""
        return self._path

    @property
    def info(self) -> BinsecInfo:
        """Cached version information for this Binsec install."""
        if self._info is None:
            self._info = self._probe_version()
        return self._info

    def _probe_version(self) -> BinsecInfo:
        # Binsec uses a single dash for its top-level flags: ``-version``,
        # not ``--version``. Calling ``--version`` would print the entire
        # option list, which is much heavier and harder to parse.
        try:
            proc = subprocess.run(
                [str(self._path), "-version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except FileNotFoundError as exc:
            raise BinsecNotFoundError(str(exc)) from exc

        raw = (proc.stdout or proc.stderr or "").strip()
        match = _VERSION_RE.search(raw)
        return BinsecInfo(
            path=self._path,
            version=match.group(1) if match else None,
            raw_version_output=raw,
        )

    def run(
        self,
        args: list[str],
        *,
        cwd: str | os.PathLike[str] | None = None,
        timeout: float | None = None,
        check: bool = True,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run Binsec with the given arguments.

        Args:
            args: Arguments passed to the binary (without the binary path).
            cwd: Working directory.
            timeout: Override the instance's default timeout.
            check: Raise :class:`BinsecRuntimeError` on non-zero exit.
            extra_env: Additional environment variables.

        Returns:
            The completed process, with text stdout/stderr captured.
        """
        cmd = [str(self._path), *args]
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)

        effective_timeout = timeout if timeout is not None else self._default_timeout

        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
            env=env,
            check=False,
        )

        if check and proc.returncode != 0:
            raise BinsecRuntimeError(
                f"binsec exited with status {proc.returncode}",
                returncode=proc.returncode,
                stderr=proc.stderr,
                cmd=cmd,
            )
        return proc

    def __repr__(self) -> str:
        version = self._info.version if self._info else "?"
        return f"Binsec(path={self._path!s}, version={version})"

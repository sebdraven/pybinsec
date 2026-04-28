"""Tests for binary detection and the low-level wrapper."""

from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

from pybinsec import Binsec, BinsecNotFoundError, find_binsec
from pybinsec._binsec import ENV_BINARY


def _make_fake_binsec(tmp_path: Path, version: str = "0.10.1") -> Path:
    """Build a fake binsec executable that prints a plausible --version output.

    On POSIX we use a shell script. On Windows we use a Python script that
    we can call through the current interpreter.
    """
    if sys.platform == "win32":
        # Windows: shim through a .bat that calls python on a sibling .py.
        helper_py = tmp_path / "_fake_binsec.py"
        helper_py.write_text(
            "import sys\n"
            "if len(sys.argv) > 1 and sys.argv[1] == '--version':\n"
            f"    print('binsec {version}')\n"
            "    sys.exit(0)\n"
            "sys.exit(0)\n"
        )
        fake = tmp_path / "binsec.bat"
        fake.write_text(f'@echo off\r\n"{sys.executable}" "{helper_py}" %*\r\n')
        return fake

    fake = tmp_path / "binsec"
    fake.write_text(
        f"""#!/usr/bin/env bash
if [[ "$1" == "--version" ]]; then
  echo "binsec {version}"
  exit 0
fi
exit 0
"""
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return fake


class TestFindBinsec:
    def test_explicit_path_ok(self, tmp_path: Path) -> None:
        fake = _make_fake_binsec(tmp_path)
        assert find_binsec(fake) == fake.resolve()

    def test_explicit_path_missing(self, tmp_path: Path) -> None:
        with pytest.raises(BinsecNotFoundError):
            find_binsec(tmp_path / "nope")

    def test_env_var(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _make_fake_binsec(tmp_path)
        monkeypatch.setenv(ENV_BINARY, str(fake))
        # Strip PATH so we cannot fall through to a system binsec.
        monkeypatch.setenv("PATH", "")
        assert find_binsec() == fake.resolve()

    def test_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ENV_BINARY, raising=False)
        monkeypatch.setenv("PATH", "")
        with pytest.raises(BinsecNotFoundError):
            find_binsec()


class TestBinsecWrapper:
    def test_version_probe(self, tmp_path: Path) -> None:
        fake = _make_fake_binsec(tmp_path, version="0.9.0")
        bs = Binsec(fake)
        assert bs.info.version == "0.9.0"
        assert bs.path == fake.resolve()

    def test_repr_contains_path(self, tmp_path: Path) -> None:
        fake = _make_fake_binsec(tmp_path)
        bs = Binsec(fake)
        assert "Binsec(" in repr(bs)


@pytest.mark.requires_binsec
class TestRealBinsec:
    """Tests that require an actual binsec on PATH."""

    def test_real_version(self) -> None:
        if shutil.which("binsec") is None and not os.environ.get(ENV_BINARY):
            pytest.skip("real binsec not available")
        bs = Binsec()
        assert bs.info.version is not None

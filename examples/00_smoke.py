"""Smoke test: verify Binsec detection and print its version."""

from __future__ import annotations

from pybinsec import Binsec, BinsecNotFoundError


def main() -> int:
    try:
        bs = Binsec()
    except BinsecNotFoundError as exc:
        print(f"[!] {exc}")
        return 1

    print(f"[+] Binsec found  : {bs.path}")
    print(f"[+] Version       : {bs.info.version or 'unknown'}")
    print(f"[+] Raw output    : {bs.info.raw_version_output!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

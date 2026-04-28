# pybinsec

Python bindings and high-level API for [Binsec](https://binsec.github.io/) (CEA).

> ⚠️ **Pre-alpha.** The API will change between minor versions.

## Goals

`pybinsec` exposes Binsec through three API layers, from raw to idiomatic:

1. **Subprocess wrapper** (`pybinsec.Binsec`) — direct invocation of the binary.
2. **SSE script builder** (`pybinsec.sse`) — programmatic construction of
   static symbolic execution scripts.
3. **angr-style API** (`pybinsec.Project`, planned for v0.3) — to enable
   near-transparent DSE backend swapping in existing analysis tools.

## Installation

```bash
uv sync
# or, with extras
uv sync --extra smt --extra dev
```

After cloning, install the pre-commit hooks once so that ruff lint
and format run automatically on every `git commit`:

```bash
uv run pre-commit install
```

The CI runs the same hooks against the whole tree, so if anything
gets through, push will be rejected.

Binsec must be installed separately. `pybinsec` looks for it in this order:

1. Explicit argument passed to `Binsec(path=...)`.
2. `PYBINSEC_BINARY` environment variable.
3. `binsec` on `$PATH`.

## Quickstart

```python
from pybinsec import Binsec

bs = Binsec()
print(bs.info.version)
```

## Roadmap

- **v0.1** — low-level wrapper, binary detection, test infrastructure.
- **v0.2** — full SSE builder (`starting_from`, `reach`, `cut`, `replace`,
  `assume`, `assert`), log and SMT model parsing.
- **v0.3** — Layer 3 API (`Project` / `SimulationManager`).
- **v0.4** — clean `formula` module, `pysmt` integration.
- **v1.0** — Sphinx docs, CI, PyPI release.

## License

MIT — see [LICENSE.md](LICENSE.md).

Binsec itself has its own license; `pybinsec` only invokes it as an external
process and does not embed its source.

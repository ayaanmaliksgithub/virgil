"""Build a standalone `virgil` binary with PyInstaller.

Usage:
    python build.py            # builds dist/virgil (or dist/virgil.exe)
    python build.py --clean    # forwarded to PyInstaller

Run from `apps/cli/` so PyInstaller resolves `cli/main.py` correctly. The
resulting binary is self-contained: it bundles the Python interpreter and
every dependency, so end users don't need pipx or Python on PATH.

CI consumes this same path — see `.github/workflows/cli-binaries.yml`.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = HERE / "virgil.spec"


def main() -> int:
    if not SPEC.exists():
        print(f"error: spec file missing at {SPEC}", file=sys.stderr)
        return 2

    # Invoke PyInstaller as a module under the *current* interpreter — that
    # way `path/to/venv/bin/python build.py` works without needing the venv's
    # bin dir on PATH. CI uses the same code path.
    if importlib.util.find_spec("PyInstaller") is None:
        print(
            "error: PyInstaller not installed for this interpreter. Install the\n"
            "build extras into the venv you're using:\n"
            f"  {sys.executable} -m pip install -e '.[build]'",
            file=sys.stderr,
        )
        return 2

    cmd = [sys.executable, "-m", "PyInstaller", str(SPEC), "--noconfirm"]
    cmd += sys.argv[1:]
    print("$", " ".join(cmd))
    return subprocess.call(cmd, cwd=HERE)


if __name__ == "__main__":
    raise SystemExit(main())

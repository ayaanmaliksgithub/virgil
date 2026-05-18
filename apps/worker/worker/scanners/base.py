"""Scanner adapter protocol.

Adapters do three things:
  1. decide whether to run for a given repo (`applicable`),
  2. emit the argv to run inside the sandbox container (`command`),
  3. parse the scanner's output files into RawFinding objects (`parse`).

Adapters do NOT execute anything themselves. Execution is the sandbox runner's
job — single trust boundary.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from audit_core import RawFinding, RepoProfile


@runtime_checkable
class ScannerAdapter(Protocol):
    name: str
    version: str

    def applicable(self, profile: RepoProfile) -> bool: ...

    def command(self, repo_path: Path, out_dir: Path) -> list[str]:
        """argv to invoke inside the sandbox container.

        `repo_path` and `out_dir` are container-side paths (typically /repo, /out).
        """

    def parse(self, out_dir: Path) -> list[RawFinding]:
        """Read scanner output from the host out_dir and return RawFindings."""

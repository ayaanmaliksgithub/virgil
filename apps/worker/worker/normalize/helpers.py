"""Fix-the-helper hint generator.

A cluster of N findings spread across M files is usually one underlying
problem at a shared upstream module — a `sanitize_input` helper that
doesn't actually sanitize, a `make_query` builder that interpolates, a
`render_template` wrapper that misuses autoescape. Telling the user
"these N callsites all import `utils/db.py` — fix that one" is more
useful than "here are N rows to scroll through."

This module computes a small hint dict per cluster from two signals:

1. **shared_dir** — the deepest common directory of all callsites.
   `os.path.commonpath` style. Always cheap, always available.
2. **shared_modules** — internal imports that appear in ≥70% of the
   affected files. "Internal" means relative imports (Python `from
   .utils …`) or imports that resolve to files in the repo. External
   imports (`logging`, `react`) are filtered out — they're noise.

Computed at audit completion (we need the repo on disk) and stashed
on `audit.profile.cluster_hints` so the API can serve it without
re-walking the tree.
"""
from __future__ import annotations

import ast
import logging
import os
import re
from collections import Counter
from pathlib import Path

log = logging.getLogger(__name__)

MIN_SHARED_RATIO = 0.7   # an import must appear in ≥70% of files to count
MIN_FILES_FOR_HINT = 2   # below this, there's no "shared upstream" to find


def build_cluster_hint(affected_files: list[str], repo_path: Path) -> dict:
    """Return a hint dict for a cluster.

    `affected_files` is the de-duped list of files in the cluster.
    Empty / single-file clusters return `{"shared_dir": None,
    "shared_modules": []}` — nothing to share.
    """
    files = [f for f in affected_files if f]
    if len(files) < MIN_FILES_FOR_HINT:
        return {"shared_dir": None, "shared_modules": []}

    return {
        "shared_dir": _common_directory(files),
        "shared_modules": _shared_internal_imports(files, repo_path),
    }


def _common_directory(files: list[str]) -> str | None:
    """Deepest common parent directory across the files.

    Returns None if the only common ancestor is the repo root (no signal).
    """
    norm = [f.replace("\\", "/") for f in files]
    try:
        common = os.path.commonpath(norm)
    except ValueError:
        return None
    # commonpath('a/x.py', 'b/x.py') is '' → not useful
    if not common or common in ("/", "."):
        return None
    # If commonpath ends in a file (single-file cluster), strip to its dir.
    if "." in os.path.basename(common):
        common = os.path.dirname(common)
    return common or None


def _shared_internal_imports(files: list[str], repo_path: Path) -> list[str]:
    """Return imports that appear in ≥MIN_SHARED_RATIO of files AND resolve
    to source files within the repo.

    Order: by frequency desc, then alphabetical. Capped at 5 — past that
    we're listing dependencies, not pointing at a helper."""
    if not repo_path.is_dir():
        return []

    py_imports_per_file: list[set[str]] = []
    js_imports_per_file: list[set[str]] = []

    for rel in files:
        abs_path = (repo_path / rel.lstrip("/")).resolve()
        try:
            abs_path.relative_to(repo_path.resolve())
        except ValueError:
            continue
        if not abs_path.is_file():
            continue
        suffix = abs_path.suffix.lower()
        try:
            text = abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            if suffix == ".py":
                py_imports_per_file.append(_python_imports_with_relatives(text, rel))
            elif suffix in (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"):
                js_imports_per_file.append(_js_imports_with_relatives(text, rel))
        except Exception:
            continue

    candidates: Counter[str] = Counter()
    total = 0
    for s in py_imports_per_file + js_imports_per_file:
        total += 1
        candidates.update(s)

    if total < MIN_FILES_FOR_HINT:
        return []

    threshold = max(2, int(total * MIN_SHARED_RATIO))
    shared = [(name, count) for name, count in candidates.items() if count >= threshold]
    if not shared:
        return []

    # Keep only imports that resolve to source files in the repo (internal
    # helpers) — drop top-level package names that map to PyPI / npm.
    repo_files = {p.relative_to(repo_path).as_posix() for p in repo_path.rglob("*") if p.is_file()}
    internal = [
        (n, c) for n, c in shared
        if _looks_internal(n, repo_files, repo_path)
    ]
    internal.sort(key=lambda nc: (-nc[1], nc[0]))
    return [n for n, _ in internal[:5]]


# Python: collect both absolute and relative imports, resolving relatives
# against the importer's path so `from .utils import x` in `pkg/a.py` →
# `pkg/utils`.
def _python_imports_with_relatives(text: str, importer_rel: str) -> set[str]:
    out: set[str] = set()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return out
    importer_dir = os.path.dirname(importer_rel)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level > 0:
                # Resolve relative: walk up `level` dirs from importer, then add module.
                parts = importer_dir.split("/") if importer_dir else []
                up = max(0, len(parts) - (node.level - 1))
                base = "/".join(parts[:up]) if up else ""
                resolved = f"{base}/{module}".strip("/") if module else base
                if resolved:
                    out.add(resolved)
            elif module:
                out.add(module)
    return out


_JS_IMPORT_RE = re.compile(
    r"""(?:
        \bimport\s+(?:[^'"]*?\bfrom\s+)?['"]([^'"]+)['"] |
        \brequire\s*\(\s*['"]([^'"]+)['"]\s*\)         |
        \bimport\s*\(\s*['"]([^'"]+)['"]\s*\)
    )""",
    re.VERBOSE,
)


def _js_imports_with_relatives(text: str, importer_rel: str) -> set[str]:
    out: set[str] = set()
    importer_dir = os.path.dirname(importer_rel)
    for m in _JS_IMPORT_RE.finditer(text):
        spec = next(g for g in m.groups() if g)
        if spec.startswith(("./", "../")):
            resolved = os.path.normpath(os.path.join(importer_dir, spec))
            out.add(resolved.replace("\\", "/"))
        else:
            out.add(spec)
    return out


def _looks_internal(name: str, repo_files: set[str], repo_path: Path) -> bool:
    """Is this import a file inside the repo? Tries common extensions and
    `__init__.py` for Python packages."""
    # Python module form `pkg.sub.mod` -> path `pkg/sub/mod`
    candidates = [
        name,
        name.replace(".", "/"),
    ]
    suffixes = ["", ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
                "/__init__.py", "/index.ts", "/index.js"]
    for base in candidates:
        for suf in suffixes:
            candidate = f"{base}{suf}".lstrip("/")
            if candidate in repo_files:
                return True
    return False

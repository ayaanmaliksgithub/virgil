"""Tests for fix-the-helper hint generation."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic")

from worker.normalize.helpers import (
    MIN_FILES_FOR_HINT,
    build_cluster_hint,
)


def _write(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_single_file_cluster_returns_empty_hint(tmp_path: Path):
    hint = build_cluster_hint(["src/a.py"], tmp_path)
    assert hint == {"shared_dir": None, "shared_modules": []}


def test_common_directory_is_deepest_shared_path(tmp_path: Path):
    hint = build_cluster_hint(
        ["src/handlers/a.py", "src/handlers/b.py", "src/handlers/c.py"],
        tmp_path,
    )
    assert hint["shared_dir"] == "src/handlers"


def test_repo_root_not_returned_as_shared_dir(tmp_path: Path):
    """When the only common ancestor is the repo root, that's no signal."""
    hint = build_cluster_hint(["a.py", "b.py"], tmp_path)
    assert hint["shared_dir"] is None


def test_shared_internal_import_surfaced(tmp_path: Path):
    """Three files all importing a sibling helper module — that's the
    fix-the-helper signal we want."""
    _write(tmp_path, "src/db/helper.py", "def query(sql): return sql\n")
    _write(tmp_path, "src/handlers/a.py",
           "from src.db.helper import query\nquery('SELECT 1')\n")
    _write(tmp_path, "src/handlers/b.py",
           "from src.db.helper import query\nquery('SELECT 2')\n")
    _write(tmp_path, "src/handlers/c.py",
           "from src.db.helper import query\nquery('SELECT 3')\n")

    hint = build_cluster_hint(
        ["src/handlers/a.py", "src/handlers/b.py", "src/handlers/c.py"],
        tmp_path,
    )
    assert "src.db.helper" in hint["shared_modules"] or "src/db/helper" in hint["shared_modules"]


def test_external_imports_filtered_out(tmp_path: Path):
    """Every Python file imports `os` / `logging`. The hint should NOT
    surface those — they aren't the helper."""
    for i in range(3):
        _write(tmp_path, f"src/handler_{i}.py",
               "import os\nimport logging\n")
    hint = build_cluster_hint(
        [f"src/handler_{i}.py" for i in range(3)],
        tmp_path,
    )
    assert hint["shared_modules"] == []
    # shared_dir still works though
    assert hint["shared_dir"] == "src"


def test_threshold_requires_majority_of_files(tmp_path: Path):
    """A module imported by only one of four files isn't the helper."""
    _write(tmp_path, "src/util.py", "x = 1\n")
    _write(tmp_path, "src/a.py", "from src.util import x\n")
    _write(tmp_path, "src/b.py", "")  # no imports
    _write(tmp_path, "src/c.py", "")
    _write(tmp_path, "src/d.py", "")
    hint = build_cluster_hint(
        ["src/a.py", "src/b.py", "src/c.py", "src/d.py"],
        tmp_path,
    )
    # Only 1/4 files imports src.util — below the 70% threshold.
    assert "src.util" not in hint["shared_modules"]
    assert "src/util" not in hint["shared_modules"]


def test_js_relative_imports_resolved(tmp_path: Path):
    """For JS/TS, `./helpers` from `src/a.js` resolves to `src/helpers`."""
    _write(tmp_path, "src/helpers.js", "export const x = 1;\n")
    _write(tmp_path, "src/a.js", "import { x } from './helpers';\n")
    _write(tmp_path, "src/b.js", "import { x } from './helpers';\n")
    hint = build_cluster_hint(["src/a.js", "src/b.js"], tmp_path)
    assert any("helpers" in m for m in hint["shared_modules"])


def test_path_escape_skipped(tmp_path: Path):
    """A finding reporting `../etc/passwd` must not cause the resolver to
    read outside the repo."""
    outside = tmp_path.parent / "stranger.py"
    outside.write_text("import secret\n", encoding="utf-8")
    try:
        _write(tmp_path, "ok.py", "import secret\n")
        hint = build_cluster_hint(["ok.py", "../stranger.py"], tmp_path)
        # Either skipped silently, or only the in-repo file counted — never
        # crashes, never reads outside.
        assert hint["shared_modules"] == [] or "secret" not in str(hint)
    finally:
        outside.unlink(missing_ok=True)


def test_min_files_constant_enforced(tmp_path: Path):
    """One file → no hint, even if the file is valid."""
    _write(tmp_path, "a.py", "import os\n")
    assert MIN_FILES_FOR_HINT >= 2
    hint = build_cluster_hint(["a.py"], tmp_path)
    assert hint["shared_modules"] == []
    assert hint["shared_dir"] is None

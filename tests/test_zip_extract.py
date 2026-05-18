"""Zip extractor security tests."""
import io
import zipfile
from pathlib import Path

import pytest

from worker.sandbox.zip_extract import UnsafeArchive, safe_extract


def _write_zip(tmp: Path, members: list[tuple[str, bytes]]) -> Path:
    p = tmp / "in.zip"
    with zipfile.ZipFile(p, "w") as z:
        for name, data in members:
            z.writestr(name, data)
    return p


def test_rejects_path_traversal(tmp_path):
    z = _write_zip(tmp_path, [("../escape.txt", b"x")])
    with pytest.raises(UnsafeArchive):
        safe_extract(z, tmp_path / "out")


def test_rejects_absolute_path(tmp_path):
    z = _write_zip(tmp_path, [("/etc/passwd", b"x")])
    with pytest.raises(UnsafeArchive):
        safe_extract(z, tmp_path / "out")


def test_rejects_symlink(tmp_path):
    p = tmp_path / "sym.zip"
    with zipfile.ZipFile(p, "w") as z:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 & 0xFFFF) << 16
        z.writestr(info, b"target")
    with pytest.raises(UnsafeArchive):
        safe_extract(p, tmp_path / "out")


def test_accepts_normal_archive(tmp_path):
    z = _write_zip(tmp_path, [("a/b.txt", b"hello"), ("README.md", b"# x")])
    safe_extract(z, tmp_path / "out")
    assert (tmp_path / "out" / "a" / "b.txt").read_bytes() == b"hello"


def test_rejects_oversize(tmp_path):
    z = _write_zip(tmp_path, [("big.txt", b"x" * 1024)])
    with pytest.raises(UnsafeArchive):
        safe_extract(z, tmp_path / "out", max_total_bytes=100)

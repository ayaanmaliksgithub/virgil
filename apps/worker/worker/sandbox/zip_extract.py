"""Safe ZIP extraction.

Guards against:
  - path traversal (`..`, absolute paths)
  - symlinks pointing outside the workspace
  - oversized archives (zip-bomb mitigation)
  - excessive file counts
"""
from __future__ import annotations

import zipfile
from pathlib import Path


class UnsafeArchive(ValueError):
    pass


def safe_extract(
    zip_path: Path,
    dest: Path,
    *,
    max_total_bytes: int = 500 * 1024 * 1024,
    max_files: int = 50_000,
    max_compression_ratio: int = 100,
) -> None:
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path) as zf:
        members = zf.infolist()
        if len(members) > max_files:
            raise UnsafeArchive(f"Archive contains too many files ({len(members)} > {max_files})")

        total_uncompressed = 0
        total_compressed = 0
        for m in members:
            total_uncompressed += m.file_size
            total_compressed += m.compress_size
            if total_uncompressed > max_total_bytes:
                raise UnsafeArchive("Archive exceeds maximum uncompressed size")

        if total_compressed > 0 and total_uncompressed / max(total_compressed, 1) > max_compression_ratio:
            raise UnsafeArchive("Suspicious compression ratio (possible zip bomb)")

        for m in members:
            name = m.filename
            if not name or name.startswith("/") or ".." in Path(name).parts:
                raise UnsafeArchive(f"Disallowed path in archive: {name!r}")

            target = (dest / name).resolve()
            if dest not in target.parents and target != dest:
                raise UnsafeArchive(f"Path escapes destination: {name!r}")

            # Reject symlinks (mode high bits indicate symlink in zip)
            mode = (m.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise UnsafeArchive(f"Symlink not allowed in archive: {name!r}")

            if m.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(m) as src, target.open("wb") as dst:
                # Bounded copy to keep an extra safety net against lying headers.
                remaining = max_total_bytes
                while True:
                    chunk = src.read(64 * 1024)
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise UnsafeArchive("Per-file size exceeded budget during extraction")
                    dst.write(chunk)

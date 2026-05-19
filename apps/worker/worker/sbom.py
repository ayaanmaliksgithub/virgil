"""SBOM generation — CycloneDX + SPDX, produced via Trivy in the sandbox.

Phase 5 #15 / ROADMAP indie OSS item. After the main scan + report
artifacts land, we run two extra `trivy fs --format ...` invocations
against the same repo mount, capture the output files, and hand the
bytes back to the worker for upload to object storage.

We deliberately don't reuse the existing Trivy *scanner adapter* — that
one emits `RawFinding` rows and is meant for the vuln/misconfig path.
SBOM generation is a different output shape (a whole document, not
findings) and runs in a separate Trivy mode that doesn't need the vuln
database. Easier to keep them apart than to twist one adapter to do
both.

Failures here are non-fatal for the audit — if Trivy crashes on the
SBOM step or the container runtime is missing, we log and return an
empty map. The audit still completes; SBOM artifacts just won't appear
on the report download list.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from worker.sandbox import SandboxError, run_scanner

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Variant:
    name: str            # logical name we use as the `format` column ("cyclonedx" / "spdx")
    trivy_format: str    # the flag value Trivy expects
    out_filename: str    # filename inside /out that Trivy writes to


_VARIANTS = (
    _Variant(name="cyclonedx", trivy_format="cyclonedx",  out_filename="sbom-cyclonedx.json"),
    _Variant(name="spdx",      trivy_format="spdx-json",  out_filename="sbom-spdx.json"),
)


def generate_sboms(repo_dir: Path, out_dir: Path) -> dict[str, bytes]:
    """Produce CycloneDX + SPDX SBOMs for the cloned repo.

    Returns a dict keyed by variant name (`"cyclonedx"`, `"spdx"`). A
    variant is only included if Trivy ran successfully AND its output
    file is non-empty. Partial success is fine — the caller persists
    whatever came back.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, bytes] = {}

    for v in _VARIANTS:
        host_path = out_dir / v.out_filename
        # Container-side paths — the runner mounts repo at /repo, out at /out.
        argv = [
            "trivy", "fs",
            "--format", v.trivy_format,
            "--output", f"/out/{v.out_filename}",
            "--quiet",
            "--no-progress",
            "--timeout", "5m",
            "/repo",
        ]
        try:
            res = run_scanner(argv, repo_dir, out_dir)
        except SandboxError as e:
            log.warning("sbom %s: sandbox failed: %s", v.name, e)
            continue
        if res.returncode != 0:
            log.warning("sbom %s: trivy rc=%d stderr=%s",
                        v.name, res.returncode, (res.stderr or "")[:300])
            continue
        if not host_path.is_file():
            log.warning("sbom %s: output file missing at %s", v.name, host_path)
            continue
        try:
            body = host_path.read_bytes()
        except OSError as e:
            log.warning("sbom %s: read failed: %s", v.name, type(e).__name__)
            continue
        if not body:
            log.warning("sbom %s: output empty", v.name)
            continue
        results[v.name] = body

    return results


def variant_names() -> tuple[str, ...]:
    """Public accessor — what variants this module can produce."""
    return tuple(v.name for v in _VARIANTS)

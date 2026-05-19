"""Tests for the SBOM helper that produces CycloneDX + SPDX artifacts.

The sandbox shell-out is mocked at the `worker.sandbox.run_scanner`
import site so the test runs without Docker — the contract under test
is "for each variant, call Trivy with the right argv, read the output
file, return the bytes." Failure modes (non-zero rc, missing file,
empty body, sandbox unavailable) all degrade to "skip this variant,"
which the helper has to honor so a flaky Trivy step doesn't sink the
audit.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def _stub_run(repo, out, *, returncode=0, write_file=None, contents=b'{"sbom": "ok"}'):
    """Build a fake `run_scanner` that emulates the Trivy invocation:
    if `write_file` is set, it lays down `out/<write_file>` with `contents`
    before returning a CompletedProcess with the given returncode."""

    def fake_run_scanner(argv, repo_host_path, out_host_path, **_):
        # The argv carries `--output /out/<filename>` — we cross-check the
        # container-side filename against what the helper passed.
        out_idx = argv.index("--output") + 1 if "--output" in argv else None
        assert out_idx is not None, "trivy invocation missing --output"
        container_path = argv[out_idx]
        assert container_path.startswith("/out/"), f"unexpected --output {container_path!r}"
        if write_file is not None:
            out_host_path.mkdir(parents=True, exist_ok=True)
            (out_host_path / write_file).write_bytes(contents)
        return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout="", stderr="")

    return fake_run_scanner


def test_generate_sboms_returns_both_variants_on_success(monkeypatch, tmp_path: Path):
    from worker import sbom

    repo, out = tmp_path / "repo", tmp_path / "out"
    repo.mkdir()
    # Lay down the expected output files when Trivy "runs."
    def fake(argv, _repo, out_host_path, **_):
        out_host_path.mkdir(parents=True, exist_ok=True)
        for v in argv:
            if v.startswith("/out/"):
                filename = v[len("/out/"):]
                (out_host_path / filename).write_bytes(
                    b'{"format": "cyclonedx"}' if "cyclonedx" in filename else b'{"format": "spdx"}'
                )
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")
    monkeypatch.setattr(sbom, "run_scanner", fake)

    result = sbom.generate_sboms(repo, out)
    assert set(result.keys()) == {"cyclonedx", "spdx"}
    assert result["cyclonedx"] == b'{"format": "cyclonedx"}'
    assert result["spdx"] == b'{"format": "spdx"}'


def test_generate_sboms_skips_variant_on_non_zero_rc(monkeypatch, tmp_path: Path):
    from worker import sbom

    repo, out = tmp_path / "repo", tmp_path / "out"
    repo.mkdir()

    # First call (cyclonedx) succeeds; second (spdx) returns rc=1.
    calls = {"n": 0}
    def fake(argv, _repo, out_host_path, **_):
        out_host_path.mkdir(parents=True, exist_ok=True)
        calls["n"] += 1
        if calls["n"] == 1:
            container = next(v for v in argv if v.startswith("/out/"))
            (out_host_path / container[len("/out/"):]).write_bytes(b'{"format": "cyclonedx"}')
            return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")
        return subprocess.CompletedProcess(args=argv, returncode=1, stdout="", stderr="trivy: db unreachable")
    monkeypatch.setattr(sbom, "run_scanner", fake)

    result = sbom.generate_sboms(repo, out)
    assert "cyclonedx" in result
    assert "spdx" not in result


def test_generate_sboms_skips_when_output_missing(monkeypatch, tmp_path: Path):
    """Trivy can exit 0 yet not write the file in some failure modes —
    helper must not return a stale-empty entry for those."""
    from worker import sbom

    repo, out = tmp_path / "repo", tmp_path / "out"
    repo.mkdir()
    monkeypatch.setattr(
        sbom, "run_scanner",
        lambda argv, _r, _o, **_kw: subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr=""),
    )
    result = sbom.generate_sboms(repo, out)
    assert result == {}


def test_generate_sboms_skips_when_output_empty(monkeypatch, tmp_path: Path):
    from worker import sbom

    repo, out = tmp_path / "repo", tmp_path / "out"
    repo.mkdir()
    def fake(argv, _repo, out_host_path, **_):
        out_host_path.mkdir(parents=True, exist_ok=True)
        for v in argv:
            if v.startswith("/out/"):
                (out_host_path / v[len("/out/"):]).write_bytes(b"")
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")
    monkeypatch.setattr(sbom, "run_scanner", fake)

    assert sbom.generate_sboms(repo, out) == {}


def test_generate_sboms_swallows_sandbox_error(monkeypatch, tmp_path: Path):
    """`SandboxError` (e.g. docker missing on PATH) for one variant must not
    bring the whole pipeline down — the audit completes without SBOMs."""
    from worker import sbom
    from worker.sandbox import SandboxError

    repo, out = tmp_path / "repo", tmp_path / "out"
    repo.mkdir()
    monkeypatch.setattr(
        sbom, "run_scanner",
        lambda *a, **kw: (_ for _ in ()).throw(SandboxError("docker not found")),
    )
    assert sbom.generate_sboms(repo, out) == {}


def test_argv_uses_expected_trivy_flags(monkeypatch, tmp_path: Path):
    """Spot-check the Trivy invocation so a future flag rename surfaces
    here instead of silently producing wrong-shaped SBOMs in prod."""
    from worker import sbom

    repo, out = tmp_path / "repo", tmp_path / "out"
    repo.mkdir()
    seen: list[list[str]] = []
    def fake(argv, _repo, out_host_path, **_):
        seen.append(list(argv))
        out_host_path.mkdir(parents=True, exist_ok=True)
        container = next(v for v in argv if v.startswith("/out/"))
        (out_host_path / container[len("/out/"):]).write_bytes(b"{}")
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")
    monkeypatch.setattr(sbom, "run_scanner", fake)

    sbom.generate_sboms(repo, out)
    assert len(seen) == 2
    flat = [tuple(argv) for argv in seen]
    # both invocations are `trivy fs` against /repo
    for argv in flat:
        assert argv[0] == "trivy" and argv[1] == "fs"
        assert "/repo" in argv
        assert "--format" in argv
    formats = [argv[argv.index("--format") + 1] for argv in flat]
    assert sorted(formats) == ["cyclonedx", "spdx-json"]


def test_variant_names_exposes_public_list():
    from worker.sbom import variant_names
    assert set(variant_names()) == {"cyclonedx", "spdx"}

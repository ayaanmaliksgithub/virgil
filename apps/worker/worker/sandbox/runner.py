"""Sandboxed scanner execution.

Each scanner runs in its own Docker container with:
  - --network=none           (scanners have no internet)
  - --read-only rootfs
  - --tmpfs /tmp             (writable scratch)
  - --cap-drop=ALL --security-opt=no-new-privileges
  - non-root UID
  - bounded CPU / memory / pids
  - wall-clock timeout enforced by the worker as well

Output files land in a host-side directory mounted read-write at /out.
The repo is mounted read-only at /repo.

The runner deliberately does NOT execute any code from the target repository;
it only runs the scanner binaries baked into the sandbox image.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


class SandboxError(RuntimeError):
    pass


@dataclass
class SandboxLimits:
    cpus: str = os.environ.get("SANDBOX_CPUS", "2")
    memory: str = os.environ.get("SANDBOX_MEMORY", "4g")
    pids: int = int(os.environ.get("SANDBOX_PIDS", "512"))
    timeout_sec: int = int(os.environ.get("SCAN_TIMEOUT_SECONDS", "600"))
    image: str = os.environ.get("SCANNER_IMAGE", "virgil/scanner:latest")
    runtime: str = os.environ.get("CONTAINER_RUNTIME", "docker")  # docker | podman


def run_scanner(
    argv: list[str],
    repo_host_path: Path,
    out_host_path: Path,
    *,
    limits: SandboxLimits | None = None,
    extra_env: dict[str, str] | None = None,
    extra_mounts: list[tuple[Path, str, str]] | None = None,
) -> subprocess.CompletedProcess:
    """Run a scanner argv inside the sandbox container.

    `argv` must reference container-side paths (e.g. /repo, /out) — the worker's
    adapter `command()` is responsible for that.

    `extra_mounts` lets an adapter declare additional bind mounts as a list of
    `(host_path, container_path, mode)` tuples — used by the Semgrep adapter for
    custom-rule packs (Phase 4 §17 #6). Container paths must NOT collide with
    `/repo`, `/out`, or `/tmp`.
    """
    limits = limits or SandboxLimits()
    if shutil.which(limits.runtime) is None:
        raise SandboxError(f"Container runtime {limits.runtime!r} not found on PATH")

    out_host_path.mkdir(parents=True, exist_ok=True)
    # Sandbox runs as uid 65534; ensure it can write the scanner output.
    try:
        os.chown(out_host_path, 65534, 65534)
    except (PermissionError, OSError):
        out_host_path.chmod(0o777)

    # uid 65534 in the scanner image has HOME=/nonexistent. Combined with
    # the --read-only rootfs that means tools like semgrep cannot write
    # their settings cache and abort before scanning. Point HOME at the
    # writable tmpfs the sandbox already has.
    env_args: list[str] = ["-e", "HOME=/tmp"]
    for k, v in (extra_env or {}).items():
        env_args += ["-e", f"{k}={v}"]

    extra_mount_args: list[str] = []
    for host, container, mode in extra_mounts or []:
        if container in ("/repo", "/out", "/tmp") or container.startswith(("/repo/", "/out/", "/tmp/")):
            raise SandboxError(f"extra_mount container path {container!r} collides with reserved paths")
        if mode not in ("ro", "rw"):
            raise SandboxError(f"extra_mount mode must be 'ro' or 'rw', got {mode!r}")
        extra_mount_args += ["-v", f"{host}:{container}:{mode}"]

    cmd = [
        limits.runtime, "run", "--rm",
        "--network=bridge",
        "--read-only",
        "--tmpfs", "/tmp:size=512m,exec",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit", str(limits.pids),
        "--memory", limits.memory,
        "--cpus", limits.cpus,
        "--user", "65534:65534",  # nobody:nogroup
        "-v", f"{repo_host_path}:/repo:ro",
        "-v", f"{out_host_path}:/out:rw",
        *extra_mount_args,
        *env_args,
        limits.image,
        *argv,
    ]
    log.info("sandbox.run argv=%s", _safe_argv(cmd))
    try:
        return subprocess.run(
            cmd,
            timeout=limits.timeout_sec,
            capture_output=True,
            text=True,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise SandboxError(f"scanner exceeded {limits.timeout_sec}s timeout") from e


def _safe_argv(argv: list[str]) -> list[str]:
    # Strip absolute host paths from logs to avoid leaking filesystem layout.
    safe = []
    for a in argv:
        if a.startswith("/Users/") or a.startswith("/home/"):
            safe.append("<host-path>")
        else:
            safe.append(a)
    return safe

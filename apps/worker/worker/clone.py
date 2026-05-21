"""Git clone, executed inside the sandbox container (never on the host).

We re-use the sandbox runner with a thin override: the scanner image bakes
`git` so the same image performs the clone with --network=none disabled for
this single step only (cloning needs egress).
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


class CloneError(RuntimeError):
    pass


def clone_repo(
    url: str,
    dest: Path,
    *,
    github_token: str | None = None,
    timeout_sec: int = 300,
    max_bytes: int = 500 * 1024 * 1024,
) -> str:
    """Clone url into dest. Returns the resolved HEAD SHA. Raises CloneError on failure.

    Network IS required here. We still isolate via container with --cap-drop=ALL.

    By default the clone includes full commit history so secret scanners
    (Gitleaks) can walk the log — historic secrets are the highest-value
    secret-detection signal. Operators on tight disk/time budgets can set
    `CLONE_DEPTH=<n>` to fall back to a shallow clone; `CLONE_DEPTH=1`
    restores the original Phase-1 behavior. The `max_bytes` cap is enforced
    after clone regardless, so runaway histories abort.
    """
    image = os.environ.get("SCANNER_IMAGE", "virgil/scanner:latest")
    runtime = os.environ.get("CONTAINER_RUNTIME", "docker")
    if shutil.which(runtime) is None:
        raise CloneError(f"Container runtime {runtime!r} not found")

    dest.mkdir(parents=True, exist_ok=True)
    # Sandbox runs as uid 65534; ensure it can write into the mounted work dir.
    try:
        os.chown(dest, 65534, 65534)
    except (PermissionError, OSError):
        dest.chmod(0o777)
    env_args: list[str] = ["-e", "GIT_TERMINAL_PROMPT=0"]
    cleanup_paths: list[Path] = []
    if github_token:
        askpass = dest / ".git-askpass"
        token_file = dest / ".github-token"
        askpass.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "*Username*) printf '%s\\n' 'x-access-token' ;;\n"
            "*) cat /work/.github-token ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        token_file.write_text(github_token, encoding="utf-8")
        askpass.chmod(0o755)
        token_file.chmod(0o644)
        cleanup_paths.extend([askpass, token_file])
        env_args += ["-e", "GIT_ASKPASS=/work/.git-askpass"]

    depth_args: list[str] = []
    raw_depth = os.environ.get("CLONE_DEPTH", "").strip()
    if raw_depth:
        try:
            depth = int(raw_depth)
            if depth > 0:
                depth_args = [f"--depth={depth}"]
        except ValueError:
            log.warning("ignoring non-integer CLONE_DEPTH=%r", raw_depth)

    cmd = [
        runtime, "run", "--rm",
        "--read-only",
        "--tmpfs", "/tmp:size=256m,exec",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--memory", "1g", "--cpus", "1", "--pids-limit", "128",
        "--user", "65534:65534",
        "-v", f"{dest}:/work:rw",
        *env_args,
        image,
        "git", "clone", "--no-tags", "--single-branch", *depth_args, url, "/work/repo",
    ]
    try:
        proc = subprocess.run(cmd, timeout=timeout_sec, capture_output=True, text=True, check=False)
    except subprocess.TimeoutExpired as e:
        raise CloneError(f"clone exceeded {timeout_sec}s") from e
    finally:
        for path in cleanup_paths:
            path.unlink(missing_ok=True)
    if proc.returncode != 0:
        raise CloneError(f"git clone failed: {_redact_token(proc.stderr, github_token).strip()[:500]}")

    total = _dir_size(dest / "repo")
    if total > max_bytes:
        shutil.rmtree(dest / "repo", ignore_errors=True)
        raise CloneError(f"cloned repo exceeds size cap ({total} > {max_bytes})")

    sha_proc = subprocess.run(
        [runtime, "run", "--rm", "-v", f"{dest}:/work:ro", image,
         "git", "-C", "/work/repo", "rev-parse", "HEAD"],
        timeout=30, capture_output=True, text=True, check=False,
    )
    return sha_proc.stdout.strip() if sha_proc.returncode == 0 else ""


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def _redact_token(value: str, token: str | None) -> str:
    if token:
        value = value.replace(token, "<github-token>")
    return value

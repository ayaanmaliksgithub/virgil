"""Virgil CLI entrypoint.

Subcommands:
  scan PATH | --url URL    Submit a scan and stream progress.
  status AUDIT_ID          Print the current audit state.
  findings AUDIT_ID        Pretty-print findings table.
  report AUDIT_ID          Fetch the report in json/md/sarif/pdf.
  open AUDIT_ID            Print the audit's web URL.

Environment:
  VIRGIL_API   API base URL (default: http://localhost:8000)

Exit codes:
  0   success / no Critical (or whatever the --fail-on threshold allows)
  1   the audit completed but findings exceed the configured threshold
  2   the audit itself failed
  3   could not reach the API (suggest `docker compose up`)
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import click
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.text import Text

from cli import __version__
from cli.client import (
    ApiError,
    ApiUnreachable,
    get_audit,
    get_clusters,
    get_report,
    list_findings,
    poll_until_terminal,
    stream_events,
    submit_url,
    submit_zip,
)
from cli.render import (
    SEVERITY_ORDER,
    console,
    findings_table,
    header,
    priority_panel,
    summary_counts,
)


# Files / directories the bundler always skips. These can balloon the upload
# without contributing to scanner signal.
_BUNDLE_SKIP = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".next", "dist", "build", "target",
    ".tox", ".idea", ".vscode", "coverage",
}


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="virgil")
def cli() -> None:
    """virgil — terminal client for the Virgil security audit platform."""


# ---- scan -----------------------------------------------------------------


@cli.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path), required=False)
@click.option("--url", "repo_url", help="GitHub URL to scan instead of a local path.")
@click.option(
    "--fail-on",
    type=click.Choice(["never", "critical", "high", "medium", "low"], case_sensitive=False),
    default="critical",
    show_default=True,
    help="Exit non-zero when findings at this severity (or higher) are present.",
)
@click.option("--wait/--no-wait", default=True, help="Wait for the audit to finish before returning.")
@click.option("--base-sha", help="PR-mode base SHA (use with --head-sha).")
@click.option("--head-sha", help="PR-mode head SHA (use with --base-sha).")
def scan(
    path: Path | None,
    repo_url: str | None,
    fail_on: str,
    wait: bool,
    base_sha: str | None,
    head_sha: str | None,
) -> None:
    """Run a scan on PATH (default: current dir) or --url.

    Exits non-zero when findings of `--fail-on` severity or higher exist —
    suitable for CI gating. Use `--fail-on never` to always exit 0.
    """
    if repo_url and path:
        raise click.UsageError("Pass either PATH or --url, not both.")
    if (base_sha is None) != (head_sha is None):
        raise click.UsageError("--base-sha and --head-sha must be set together.")

    try:
        if repo_url:
            console.print(f"[dim]submit URL → {repo_url}[/dim]")
            audit = submit_url(repo_url, base_sha=base_sha, head_sha=head_sha)
        else:
            target = (path or Path(".")).resolve()
            console.print(f"[dim]bundle {target} → zip → submit[/dim]")
            with tempfile.TemporaryDirectory() as tmp:
                zip_path = _bundle_dir(target, Path(tmp))
                audit = submit_zip(zip_path)
    except ApiUnreachable as e:
        console.print(
            "[red]error[/red]: could not reach the API at "
            f"[bold]{os.environ.get('VIRGIL_API', 'http://localhost:8000')}[/bold]\n"
            "  → try [bold]docker compose up -d[/bold] from the project root,\n"
            "  → or set [bold]VIRGIL_API[/bold] to a reachable instance.\n"
            f"  cause: {e}",
            style="red",
        )
        sys.exit(3)
    except ApiError as e:
        console.print(f"[red]submission rejected[/red]: {e}", style="red")
        sys.exit(2)

    audit_id = audit["id"]
    console.print(header(audit))

    if not wait:
        console.print(f"[dim]submitted; not waiting. status:[/dim] virgil status {audit_id}")
        return

    _stream_progress(audit_id)

    try:
        final = get_audit(audit_id)
    except ApiError as e:
        console.print(f"[red]could not fetch final audit:[/red] {e}")
        sys.exit(2)

    if final["state"] == "failed":
        console.print(Panel(
            Text(final.get("error") or "audit failed without a recorded reason",
                 style="red"),
            title="[ audit failed ]",
            border_style="red",
        ))
        sys.exit(2)

    findings = list_findings(audit_id)
    clusters = get_clusters(audit_id)

    console.print()
    console.print(summary_counts(findings))
    panel = priority_panel(final, clusters)
    if panel:
        console.print()
        console.print(panel)
    console.print()
    console.print(findings_table(findings))

    threshold_breached = _breaches_threshold(findings, fail_on)
    if threshold_breached and fail_on != "never":
        worst = _worst_severity(findings)
        console.print(
            f"\n[bold red]✗ findings at {worst} ≥ --fail-on={fail_on} — exiting 1[/bold red]"
        )
        sys.exit(1)
    console.print("\n[green]✓ scan complete — threshold satisfied[/green]")


def _stream_progress(audit_id: str) -> None:
    """Render a live spinner with the latest phase message until the stream
    closes. Falls back to polling if SSE isn't available.
    """
    spinner = Spinner("dots", text=Text("queued", style="dim"))
    last_msg = "queued"
    last_phase = "queued"
    try:
        with Live(spinner, console=console, refresh_per_second=10):
            for event in stream_events(audit_id):
                data = event.get("data", "")
                if event.get("event") == "done":
                    spinner.update(text=Text(f"done · {last_phase}", style="green"))
                    break
                # The server emits `phase | message` style frames; we don't
                # parse a fixed format — just show the latest line.
                last_msg = data
                if " · " in data:
                    last_phase = data.split(" · ", 1)[0]
                spinner.update(text=Text(f"{last_phase} · {last_msg[:80]}", style="yellow"))
    except ApiUnreachable:
        console.print("[dim]stream unavailable; polling…[/dim]")
        try:
            poll_until_terminal(audit_id)
        except TimeoutError:
            console.print("[red]timed out waiting for audit[/red]")
            sys.exit(2)


# ---- status ---------------------------------------------------------------


@cli.command()
@click.argument("audit_id")
def status(audit_id: str) -> None:
    """Print the audit's current state + phase."""
    try:
        audit = get_audit(audit_id)
    except (ApiUnreachable, ApiError) as e:
        _exit_on(e)
        return
    console.print(header(audit))


# ---- findings -------------------------------------------------------------


@cli.command()
@click.argument("audit_id")
@click.option("--include-suppressed", is_flag=True, default=False)
def findings(audit_id: str, include_suppressed: bool) -> None:
    """Pretty-print the findings table for AUDIT_ID."""
    try:
        items = list_findings(audit_id, include_suppressed=include_suppressed)
    except (ApiUnreachable, ApiError) as e:
        _exit_on(e)
        return
    console.print(summary_counts(items))
    console.print()
    console.print(findings_table(items))


# ---- report ---------------------------------------------------------------


@cli.command()
@click.argument("audit_id")
@click.option("--view", type=click.Choice(["executive", "technical"]), default="technical", show_default=True)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "md", "sarif", "pdf"]),
    default="md",
    show_default=True,
)
@click.option("-o", "--output", type=click.Path(path_type=Path),
              help="Write to FILE; otherwise print to stdout (md/json/sarif) or save as report.pdf (pdf).")
def report(audit_id: str, view: str, fmt: str, output: Path | None) -> None:
    """Fetch the audit report in the requested format."""
    try:
        body = get_report(audit_id, view=view, format=fmt)
    except (ApiUnreachable, ApiError) as e:
        _exit_on(e)
        return

    if output is None and fmt == "pdf":
        output = Path(f"audit-{audit_id}-{view}.pdf")
    if output:
        output.write_bytes(body)
        console.print(f"[green]wrote[/green] {output}  ({len(body)} bytes)")
    else:
        click.echo(body.decode("utf-8", errors="replace"))


# ---- helpers --------------------------------------------------------------


def _exit_on(e: Exception) -> None:
    if isinstance(e, ApiUnreachable):
        console.print(f"[red]API unreachable[/red]: {e}")
        sys.exit(3)
    console.print(f"[red]error[/red]: {e}")
    sys.exit(2)


def _bundle_dir(target: Path, tmp: Path) -> Path:
    """ZIP `target` to a temp path, skipping vendored dirs."""
    zip_path = tmp / "scan.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in target.rglob("*"):
            if path.is_dir():
                continue
            if any(part in _BUNDLE_SKIP for part in path.parts):
                continue
            # Skip very large files (>50MB) so we don't spend the whole upload
            # budget on a single binary asset.
            try:
                if path.stat().st_size > 50 * 1024 * 1024:
                    continue
            except OSError:
                continue
            arcname = path.relative_to(target).as_posix()
            zf.write(path, arcname=arcname)
    return zip_path


def _worst_severity(findings: list[dict]) -> str | None:
    """Return the most severe severity present, or None."""
    present = {f.get("severity") for f in findings if not f.get("suppressed")}
    for s in SEVERITY_ORDER:
        if s in present:
            return s
    return None


def _breaches_threshold(findings: list[dict], fail_on: str) -> bool:
    if fail_on == "never":
        return False
    threshold_idx = SEVERITY_ORDER.index(fail_on.capitalize())
    worst = _worst_severity(findings)
    if worst is None:
        return False
    return SEVERITY_ORDER.index(worst) <= threshold_idx


if __name__ == "__main__":
    cli()

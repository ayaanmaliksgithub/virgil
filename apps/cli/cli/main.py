"""Virgil CLI entrypoint.

Subcommands:
  scan PATH | --url URL          Submit a scan and stream progress.
                                 Land on `--show {triage|report|surface|ask_virgil}`.
  status   AUDIT_ID              Print the current audit state.
  clusters AUDIT_ID              List every cluster (sorted by severity).
  cluster  AUDIT_ID CLUSTER_KEY  Drill into one cluster.
  findings AUDIT_ID              Raw findings table.
  finding  FINDING_ID            Single-finding drill + why-flagged trace.
  chat     AUDIT_ID              Interactive Q&A grounded in this audit.
  report   AUDIT_ID              Fetch the report (json/md/sarif/pdf).
  open     AUDIT_ID              Open the audit in the web app.
  config                         Read/write ~/.config/virgil/config.json.

Global flags:
  --json                         Emit machine-readable JSON to stdout
                                 (progress UI is routed to stderr).

Environment overrides:
  VIRGIL_API         API base URL              (default: https://virgilhq.app/api)
  VIRGIL_WEB         Web app base URL          (default: https://virgilhq.app)
  VIRGIL_FAIL_ON     Default --fail-on         (default: critical)
  VIRGIL_SHOW        Default --show surface    (default: triage)
  VIRGIL_CONFIG_DIR  Override config dir       (default: ~/.config/virgil)

Exit codes:
  0   success / no findings at or above --fail-on threshold
  1   the audit completed but findings exceed the configured threshold
  2   the audit itself failed, or an API error occurred
  3   could not reach the API (suggest `docker compose up`)
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
import webbrowser
import zipfile
from pathlib import Path

import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.text import Text

from cli import __version__, config
from cli.client import (
    ApiError,
    ApiUnreachable,
    get_audit,
    get_chat_session,
    get_clusters,
    get_finding,
    get_report,
    get_suggested_questions,
    list_findings,
    poll_until_terminal,
    post_chat,
    post_chat_stream,
    stream_events,
    submit_url,
    submit_zip,
)
from cli.render import (
    SEVERITY_ORDER,
    chat_turn,
    cluster_detail_panel,
    clusters_table,
    console,
    executive_narrative_panel,
    finding_detail,
    findings_table,
    header,
    next_steps,
    priority_panel,
    summary_counts,
    surface_panel,
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
@click.option("--json", "json_out", is_flag=True, default=False,
              help="Emit machine-readable JSON instead of formatted output. "
                   "Honored by: scan (final state), status, clusters, cluster, "
                   "findings, finding. Chat and report keep their own formats.")
@click.pass_context
def cli(ctx: click.Context, json_out: bool) -> None:
    """virgil — terminal client for the Virgil security audit platform."""
    ctx.ensure_object(dict)
    ctx.obj["json"] = json_out


def _is_json(ctx: click.Context) -> bool:
    root = ctx.find_root()
    return bool(root.obj and root.obj.get("json"))


def _emit_json(payload: object) -> None:
    click.echo(json.dumps(payload, indent=2, default=str))


# A dedicated stderr console used in --json mode so progress UI doesn't
# corrupt the structured JSON we write to stdout.
_stderr_console = Console(stderr=True)


def _ui(ctx: click.Context) -> Console:
    """Pick the right Rich console: stdout by default, stderr when --json."""
    return _stderr_console if _is_json(ctx) else console


# Recognized hosted Git providers. Bare `host/owner/repo` (no scheme) gets
# https:// prepended automatically.
_KNOWN_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")
_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$")


def _resolve_scan_target(target_arg: str | None, url_flag: str | None) -> tuple[str, str]:
    """Figure out whether the user meant a local directory or a remote repo.

    Returns `("local", absolute-path)` or `("remote", https-url)`.

    Detection (in order):
      1. `--url FOO` (explicit, back-compat) → remote.
      2. No positional arg → local cwd.
      3. Looks like a URL (`http(s)://…`, `git@…`) → remote.
      4. Starts with a known host (`github.com/x/y`) → remote, prepend `https://`.
      5. Looks like a shorthand (`x/y`) AND no local path with that name exists
         → remote on github.com.
      6. Otherwise: must resolve as an existing local directory.
    """
    if url_flag and target_arg:
        raise click.UsageError("Pass either TARGET or --url, not both.")
    if url_flag:
        return ("remote", url_flag)
    if not target_arg:
        return ("local", str(Path(".").resolve()))

    s = target_arg.strip()

    # Explicit URLs / SSH coordinates.
    if s.startswith(("http://", "https://", "git@")):
        return ("remote", s)

    # `github.com/owner/repo` (no scheme).
    for host in _KNOWN_HOSTS:
        if s.startswith(host + "/"):
            return ("remote", "https://" + s)

    # `owner/repo` shorthand — but only if no local dir of that name exists.
    # This lets `virgil scan myorg/myrepo` Do The Right Thing without
    # accidentally hijacking a literal relative path the user has on disk.
    if _SHORTHAND_RE.match(s) and not Path(s).exists():
        return ("remote", f"https://github.com/{s.rstrip('/')}")

    # Fall through: treat as a local path. Must exist and be a directory.
    p = Path(s)
    if not p.exists():
        raise click.BadParameter(
            f"no such path: {s!r}. "
            "If you meant a remote repo, use `github.com/owner/repo` or `owner/repo`."
        )
    if not p.is_dir():
        raise click.BadParameter(f"{s!r} is a file, not a directory")
    return ("local", str(p.resolve()))


# ---- scan -----------------------------------------------------------------


@cli.command()
@click.argument("target", required=False)
@click.option("--url", "repo_url",
              help="Explicit remote URL. Usually unnecessary — `virgil scan github.com/x/y` "
                   "or `virgil scan x/y` is auto-detected as remote.")
@click.option(
    "--fail-on",
    type=click.Choice(["never", "critical", "high", "medium", "low"], case_sensitive=False),
    default=None,
    help="Exit non-zero when findings at this severity (or higher) are present. "
         "Defaults to the value in config / $VIRGIL_FAIL_ON / 'critical'.",
)
@click.option("--wait/--no-wait", default=True, help="Wait for the audit to finish before returning.")
@click.option("--base-sha", help="PR-mode base SHA (use with --head-sha).")
@click.option("--head-sha", help="PR-mode head SHA (use with --base-sha).")
@click.option(
    "--show",
    "show",
    type=click.Choice(["triage", "report", "surface", "ask_virgil"], case_sensitive=False),
    default=None,
    help="Which surface to land on once the scan finishes. "
         "Defaults to the value in config / $VIRGIL_SHOW / 'triage'.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    target: str | None,
    repo_url: str | None,
    fail_on: str | None,
    wait: bool,
    base_sha: str | None,
    head_sha: str | None,
    show: str | None,
) -> None:
    """Scan a local directory or a remote repo.

    TARGET can be:
      .                          (or any local path)
      https://github.com/x/y     full URL
      github.com/x/y             bare host, scheme inferred
      x/y                        GitHub shorthand (must not match a local dir)

    Default with no TARGET is the current directory. Exits non-zero when
    findings of `--fail-on` severity or higher exist — suitable for CI
    gating. Use `--fail-on never` to always exit 0.
    """
    if (base_sha is None) != (head_sha is None):
        raise click.UsageError("--base-sha and --head-sha must be set together.")

    kind, value = _resolve_scan_target(target, repo_url)

    effective_fail_on = (fail_on or config.default_fail_on()).lower()
    effective_show = (show or config.default_post_scan_view()).lower()
    ui = _ui(ctx)

    try:
        if kind == "remote":
            ui.print(f"[dim]submit URL → {value}[/dim]")
            audit = submit_url(value, base_sha=base_sha, head_sha=head_sha)
        else:
            ui.print(f"[dim]bundle {value} → zip → submit[/dim]")
            with tempfile.TemporaryDirectory() as tmp:
                zip_path = _bundle_dir(Path(value), Path(tmp))
                audit = submit_zip(zip_path)
    except ApiUnreachable as e:
        ui.print(
            "[red]error[/red]: could not reach the API at "
            f"[bold]{config.api_url()}[/bold]\n"
            "  → try [bold]docker compose up -d[/bold] from the project root,\n"
            "  → or set [bold]VIRGIL_API[/bold] / `virgil config set api_url=…`.\n"
            f"  cause: {e}",
            style="red",
        )
        sys.exit(3)
    except ApiError as e:
        ui.print(f"[red]submission rejected[/red]: {e}", style="red")
        sys.exit(2)

    audit_id = audit["id"]
    ui.print(header(audit))

    if not wait:
        if _is_json(ctx):
            _emit_json({"audit": audit, "submitted": True, "waited": False})
        else:
            ui.print(f"[dim]submitted; not waiting. status:[/dim] virgil status {audit_id}")
        return

    _stream_progress(audit_id, ui)

    try:
        final = get_audit(audit_id)
    except ApiError as e:
        ui.print(f"[red]could not fetch final audit:[/red] {e}")
        sys.exit(2)

    if final["state"] == "failed":
        if _is_json(ctx):
            _emit_json({"audit": final, "ok": False, "error": final.get("error")})
        else:
            ui.print(Panel(
                Text(final.get("error") or "audit failed without a recorded reason",
                     style="red"),
                title="[ audit failed ]",
                border_style="red",
            ))
        sys.exit(2)

    findings = list_findings(audit_id)
    clusters = get_clusters(audit_id)
    threshold_breached = _breaches_threshold(findings, effective_fail_on)
    worst = _worst_severity(findings)

    if _is_json(ctx):
        _emit_json({
            "audit": final,
            "counts": _severity_counts(findings),
            "findings_count": len(findings),
            "clusters": clusters.get("items", []),
            "total_clusters": clusters.get("total_clusters", len(clusters.get("items", []))),
            "priority_list": (final.get("profile") or {}).get("priority_list") or [],
            "fail_on": effective_fail_on,
            "threshold_breached": threshold_breached,
            "worst_severity": worst,
            "web_url": _web_audit_url(audit_id),
        })
        if threshold_breached and effective_fail_on != "never":
            sys.exit(1)
        return

    # Counts always render — they are the headline regardless of --show.
    ui.print()
    ui.print(summary_counts(findings))

    if effective_show == "triage":
        panel = priority_panel(final, clusters)
        if panel:
            ui.print(); ui.print(panel)
        elif findings:
            ui.print(); ui.print(clusters_table(clusters.get("items", []), max_rows=10))
        ui.print()
        ui.print(next_steps(audit_id, has_findings=bool(findings), web_url=_web_audit_url(audit_id)))
    elif effective_show == "surface":
        ui.print(); ui.print(surface_panel(final))
        ui.print()
        ui.print(next_steps(audit_id, has_findings=bool(findings), web_url=_web_audit_url(audit_id)))
    elif effective_show == "report":
        narrative_panel = executive_narrative_panel(final)
        if narrative_panel:
            ui.print(); ui.print(narrative_panel)
        else:
            ui.print("\n[dim]// no executive narrative on file (no LLM provider configured)[/dim]")
        ui.print()
        ui.print(next_steps(audit_id, has_findings=bool(findings), web_url=_web_audit_url(audit_id)))
    elif effective_show == "ask_virgil":
        # Pre-flight the threshold + worst severity output BEFORE handing off to
        # the REPL, since the REPL takes over the terminal and we may exit 1
        # from there.
        if threshold_breached and effective_fail_on != "never":
            ui.print(
                f"\n[bold red]✗ findings at {worst} ≥ --fail-on={effective_fail_on}[/bold red]"
                f"  [dim](will exit 1 after chat)[/dim]"
            )
        ui.print()
        ui.print(Panel(
            Text.from_markup(
                "[dim]// dropping into ask_virgil — grounded in this audit's findings.[/dim]\n"
                "[dim]// Ctrl-D or :q to quit.[/dim]"
            ),
            title="[ ask_virgil ]", title_align="left", border_style="yellow",
        ))
        # Reuse the REPL by invoking the chat command in-process.
        ctx.invoke(chat, audit_id=audit_id, message=None, session_id=None)
        if threshold_breached and effective_fail_on != "never":
            sys.exit(1)
        return

    if threshold_breached and effective_fail_on != "never":
        ui.print(
            f"\n[bold red]✗ findings at {worst} ≥ --fail-on={effective_fail_on} — exiting 1[/bold red]"
        )
        sys.exit(1)
    ui.print("\n[green]✓ scan complete — threshold satisfied[/green]")


def _stream_progress(audit_id: str, ui: Console) -> None:
    """Render a live spinner with the latest phase message until the stream
    closes. Falls back to polling if SSE isn't available. `ui` lets the
    caller route the spinner to stderr (e.g. in --json mode).
    """
    spinner = Spinner("dots", text=Text("queued", style="dim"))
    last_msg = "queued"
    last_phase = "queued"
    try:
        with Live(spinner, console=ui, refresh_per_second=10):
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
        ui.print("[dim]stream unavailable; polling…[/dim]")
        try:
            poll_until_terminal(audit_id)
        except TimeoutError:
            ui.print("[red]timed out waiting for audit[/red]")
            sys.exit(2)


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        s = f.get("severity")
        if s in counts:
            counts[s] += 1
    counts["kev"] = sum(1 for f in findings if f.get("kev"))
    counts["unreachable"] = sum(1 for f in findings if f.get("reachable") is False)
    return counts


# ---- status ---------------------------------------------------------------


@cli.command()
@click.argument("audit_id")
@click.pass_context
def status(ctx: click.Context, audit_id: str) -> None:
    """Print the audit's current state + phase."""
    try:
        audit = get_audit(audit_id)
    except (ApiUnreachable, ApiError) as e:
        _exit_on(e)
        return
    if _is_json(ctx):
        _emit_json(audit); return
    console.print(header(audit))


# ---- findings -------------------------------------------------------------


@cli.command()
@click.argument("audit_id")
@click.option("--include-suppressed", is_flag=True, default=False)
@click.pass_context
def findings(ctx: click.Context, audit_id: str, include_suppressed: bool) -> None:
    """Pretty-print the findings table for AUDIT_ID."""
    try:
        items = list_findings(audit_id, include_suppressed=include_suppressed)
    except (ApiUnreachable, ApiError) as e:
        _exit_on(e)
        return
    if _is_json(ctx):
        _emit_json({"items": items, "count": len(items)}); return
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


# ---- clusters -------------------------------------------------------------


@cli.command()
@click.argument("audit_id")
@click.option("--sev", type=click.Choice(["critical", "high", "medium", "low", "informational"], case_sensitive=False),
              help="Only show clusters at this severity.")
@click.option("--include-unreachable", is_flag=True, default=False,
              help="Include clusters whose every instance is unreachable.")
@click.option("-n", "--limit", type=int, default=None, help="Show at most N clusters.")
@click.pass_context
def clusters(ctx: click.Context, audit_id: str, sev: str | None, include_unreachable: bool, limit: int | None) -> None:
    """List every cluster for AUDIT_ID, sorted by severity."""
    try:
        data = get_clusters(audit_id, include_unreachable=include_unreachable)
    except (ApiUnreachable, ApiError) as e:
        _exit_on(e); return

    items = data.get("items", [])
    if sev:
        sev_cap = sev.capitalize()
        items = [c for c in items if c.get("severity") == sev_cap]

    if _is_json(ctx):
        _emit_json({**data, "items": items, "filtered": bool(sev)}); return

    if not items:
        console.print("[dim]no clusters match.[/dim]")
        return

    console.print(clusters_table(items, max_rows=limit))
    console.print()
    console.print(
        Text.from_markup(
            f"[dim]// drill in:[/dim] [bold]virgil cluster[/bold] [dim]{audit_id} <key>[/dim]"
        )
    )


# ---- cluster (singular drill-down) ----------------------------------------


@cli.command()
@click.argument("audit_id")
@click.argument("cluster_key")
@click.pass_context
def cluster(ctx: click.Context, audit_id: str, cluster_key: str) -> None:
    """Show a single cluster in detail.

    CLUSTER_KEY is the `key` column from `virgil clusters AUDIT_ID`.
    Prefix matches are accepted as long as they identify exactly one cluster.
    """
    try:
        data = get_clusters(audit_id, include_unreachable=True)
    except (ApiUnreachable, ApiError) as e:
        _exit_on(e); return

    items = data.get("items", [])
    matches = [c for c in items if c.get("key") == cluster_key]
    if not matches:
        matches = [c for c in items if (c.get("key") or "").startswith(cluster_key)]

    if not matches:
        if _is_json(ctx):
            _emit_json({"error": "no cluster matches", "query": cluster_key})
        else:
            console.print(f"[red]no cluster matches[/red] {cluster_key!r}")
        sys.exit(2)
    if len(matches) > 1:
        if _is_json(ctx):
            _emit_json({"error": "ambiguous prefix", "query": cluster_key,
                        "matches": [{"key": c.get("key"), "title": c.get("title")} for c in matches]})
        else:
            console.print(f"[red]ambiguous prefix[/red] {cluster_key!r} matches {len(matches)} clusters:")
            for c in matches[:5]:
                console.print(f"  [dim]{c.get('key')}[/dim]  {c.get('title')}")
        sys.exit(2)

    if _is_json(ctx):
        _emit_json(matches[0]); return
    console.print(cluster_detail_panel(matches[0]))


# ---- finding (singular drill-down) ----------------------------------------


@cli.command()
@click.argument("finding_id")
@click.pass_context
def finding(ctx: click.Context, finding_id: str) -> None:
    """Show a single finding in detail, including the why-flagged trace."""
    try:
        f = get_finding(finding_id)
    except (ApiUnreachable, ApiError) as e:
        _exit_on(e); return
    if _is_json(ctx):
        _emit_json(f); return
    console.print(finding_detail(f))


# ---- chat -----------------------------------------------------------------


@cli.command()
@click.argument("audit_id")
@click.option("-m", "--message", help="One-shot: send this and print the reply, then exit.")
@click.option("--session", "session_id", help="Resume an existing chat session.")
def chat(audit_id: str, message: str | None, session_id: str | None) -> None:
    """Interactive Q&A grounded in this audit's findings.

    With `-m TEXT`, run as a one-shot (useful in pipes / CI).
    Otherwise opens a REPL: Ctrl-D or `:q` to quit.
    """
    # Verify the audit exists and surface suggested seed prompts up front so
    # the user doesn't stare at a blank line wondering what to ask.
    try:
        get_audit(audit_id)
    except (ApiUnreachable, ApiError) as e:
        _exit_on(e); return

    if session_id:
        try:
            prior = get_chat_session(audit_id, session_id)
            for turn in prior.get("history", []):
                console.print(chat_turn(turn["role"], turn["content"],
                                        citations=turn.get("citations") or []))
        except ApiError as e:
            console.print(f"[red]could not load session[/red]: {e}")
            sys.exit(2)

    # ---- one-shot path
    if message is not None:
        try:
            resp = post_chat(audit_id, message, session_id=session_id)
        except (ApiUnreachable, ApiError) as e:
            _exit_on(e); return
        msg = resp.get("message") or {}
        console.print(chat_turn("assistant", msg.get("content", ""),
                                citations=msg.get("citations") or []))
        return

    # ---- REPL path
    if not session_id:
        try:
            suggestions = get_suggested_questions(audit_id)
        except (ApiUnreachable, ApiError):
            suggestions = []
        body = Text()
        body.append("// chat is grounded in this audit's findings.\n", style="dim")
        body.append("// Ctrl-D or :q to quit.\n", style="dim")
        if suggestions:
            body.append("\ntry one of:\n", style="dim")
            for s in suggestions[:3]:
                body.append("  • ", style="dim")
                body.append(s + "\n")
        console.print(Panel(body, title="[ chat ]", title_align="left", border_style="dim"))

    current_session = session_id
    while True:
        try:
            user_msg = click.prompt(click.style("you", fg="cyan"), prompt_suffix=" › ", default="", show_default=False)
        except (EOFError, click.exceptions.Abort):
            console.print("\n[dim]bye[/dim]")
            return
        user_msg = (user_msg or "").strip()
        if not user_msg:
            continue
        if user_msg in (":q", ":quit", ":exit"):
            console.print("[dim]bye[/dim]")
            return

        # Streaming render: a Rich Live panel that grows as tokens arrive.
        # On `done` we replace the streamed text with the canonical final
        # message — the safety validator runs at end-of-stream and can swap
        # in refusal text different from what tokens already showed.
        accumulated = ""
        final_msg: dict | None = None
        stream_failed: str | None = None

        try:
            with Live(chat_turn("assistant", "…", citations=None),
                      console=console, refresh_per_second=12) as live:
                for ev in post_chat_stream(audit_id, user_msg, session_id=current_session):
                    name = ev.get("event")
                    data = ev.get("data") or {}
                    if name == "session":
                        current_session = data.get("session_id") or current_session
                    elif name == "token":
                        accumulated += data.get("text", "")
                        live.update(chat_turn("assistant", accumulated, citations=None))
                    elif name == "done":
                        final_msg = data.get("message") or {}
                        # Use the safety-validated content verbatim; refusals
                        # may differ from streamed tokens.
                        live.update(chat_turn(
                            "assistant",
                            final_msg.get("content", accumulated),
                            citations=final_msg.get("citations") or [],
                        ))
                        break
                    elif name == "error":
                        stream_failed = data.get("detail") or "stream error"
                        break
        except ApiUnreachable as e:
            console.print(f"[red]API unreachable[/red]: {e}")
            continue
        except ApiError as e:
            console.print(f"[red]chat failed[/red]: {e}")
            continue

        if stream_failed:
            console.print(f"[red]chat failed[/red]: {stream_failed}")
            continue


# ---- open -----------------------------------------------------------------


@cli.command(name="open")
@click.argument("audit_id")
@click.option("--page", type=click.Choice(["triage", "chat", "findings", "report", "attack-surface"]),
              default="triage", show_default=True, help="Which tab to land on.")
@click.option("--print", "print_only", is_flag=True, default=False,
              help="Print the URL instead of launching a browser.")
def open_cmd(audit_id: str, page: str, print_only: bool) -> None:
    """Open the audit in the web app (default tab: triage)."""
    url = f"{_web_audit_url(audit_id)}/{page}"
    if print_only:
        click.echo(url)
        return
    console.print(f"[dim]opening[/dim] {url}")
    try:
        webbrowser.open(url)
    except Exception as e:
        console.print(f"[dim]could not launch a browser:[/dim] {e}")
        click.echo(url)


# ---- config ---------------------------------------------------------------


@cli.group(name="config")
def config_cmd() -> None:
    """Read/write the persisted CLI config (~/.config/virgil/config.json)."""


@config_cmd.command("path")
def config_path_cmd() -> None:
    """Print the path to the config file."""
    click.echo(str(config.CONFIG_PATH))


@config_cmd.command("show")
def config_show_cmd() -> None:
    """Print the resolved config (env > file > default)."""
    console.print("[dim]// effective values (env > file > default)[/dim]")
    console.print(f"  api_url                 {config.api_url()}")
    console.print(f"  web_url                 {config.web_url()}")
    console.print(f"  default_fail_on         {config.default_fail_on()}")
    console.print(f"  default_post_scan_view  {config.default_post_scan_view()}")
    raw = config.load()
    if raw:
        console.print("\n[dim]// on disk[/dim]")
        for k, v in sorted(raw.items()):
            console.print(f"  {k:22s}  {v}")


@config_cmd.command("get")
@click.argument("key")
def config_get_cmd(key: str) -> None:
    """Print a single value (resolved through env > file > default)."""
    resolver = {
        "api_url": config.api_url,
        "web_url": config.web_url,
        "default_fail_on": config.default_fail_on,
        "default_post_scan_view": config.default_post_scan_view,
    }.get(key)
    if resolver is None:
        raise click.UsageError(f"unknown key: {key}. known: {sorted(config.KNOWN_KEYS)}")
    click.echo(resolver())


_VALID_VALUES: dict[str, set[str]] = {
    "default_fail_on": {"never", "critical", "high", "medium", "low"},
    "default_post_scan_view": {"triage", "report", "surface", "ask_virgil"},
}


@config_cmd.command("set")
@click.argument("assignment")
def config_set_cmd(assignment: str) -> None:
    """Set a value, e.g. `virgil config set api_url=https://virgil.example/api`."""
    if "=" not in assignment:
        raise click.UsageError("expected KEY=VALUE")
    key, _, value = assignment.partition("=")
    key = key.strip()
    value = value.strip()
    if key not in config.KNOWN_KEYS:
        raise click.UsageError(f"unknown key: {key}. known: {sorted(config.KNOWN_KEYS)}")
    allowed = _VALID_VALUES.get(key)
    if allowed and value.lower() not in allowed:
        raise click.UsageError(f"invalid value for {key}: {value!r}. allowed: {sorted(allowed)}")
    if allowed:
        value = value.lower()
    config.set_(key, value)
    console.print(f"[green]set[/green] {key}={value}  →  {config.CONFIG_PATH}")


@config_cmd.command("unset")
@click.argument("key")
def config_unset_cmd(key: str) -> None:
    """Remove a key from the config file."""
    if config.unset(key):
        console.print(f"[green]unset[/green] {key}")
    else:
        console.print(f"[dim]{key} was not set[/dim]")


# ---- helpers --------------------------------------------------------------


def _web_audit_url(audit_id: str) -> str:
    return f"{config.web_url().rstrip('/')}/audits/{audit_id}"


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

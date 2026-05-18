"""Terminal rendering — keeps the disassembler aesthetic, fits 80–120 columns.

We use `rich` for table layout + color, but the styles are deliberately
restrained: warm phosphor accent (yellow), severity reds/ambers/greens,
muted gutters in `dim`. No emoji.
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


# Severity ordering shared with the rest of the codebase.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

_SEVERITY_STYLE = {
    "Critical": "bold red",
    "High": "yellow",
    "Medium": "bright_yellow",
    "Low": "green",
    "Informational": "dim white",
}


console = Console()


def severity_text(severity: str) -> Text:
    style = _SEVERITY_STYLE.get(severity, "white")
    label = severity[:4].upper().ljust(4)
    return Text(f"[ {label} ]", style=style)


def header(audit: dict) -> Panel:
    """Top-of-output banner with audit id + source + state."""
    state = audit.get("state", "?")
    phase = audit.get("phase", "?")
    state_style = {
        "succeeded": "bold green",
        "failed": "bold red",
        "running": "yellow",
        "pending": "dim yellow",
    }.get(state, "white")

    body = Text()
    body.append("audit_id  ", style="dim")
    body.append(str(audit.get("id", "?")) + "\n", style="bold")
    body.append("source    ", style="dim")
    body.append(str(audit.get("source_ref", "?")) + "\n")
    body.append("state     ", style="dim")
    body.append(state, style=state_style)
    body.append("  phase=", style="dim")
    body.append(phase)
    return Panel(body, title="[ virgil ]", title_align="left", border_style="dim")


def findings_table(findings: list[dict], *, max_rows: int = 50) -> Table:
    table = Table(
        show_header=True,
        header_style="dim",
        border_style="dim",
        expand=True,
    )
    table.add_column("sev", width=10, no_wrap=True)
    table.add_column("title", overflow="fold")
    table.add_column("category", style="dim", no_wrap=True)
    table.add_column("file", style="dim", overflow="ellipsis", no_wrap=True)
    table.add_column("flags", justify="right", style="dim", no_wrap=True)

    sorted_findings = sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.index(f.get("severity", "Informational"))
            if f.get("severity") in SEVERITY_ORDER
            else 999,
        ),
    )

    for f in sorted_findings[:max_rows]:
        flags = []
        if f.get("kev"):
            flags.append(Text("KEV", style="bold red"))
        if f.get("reachable") is False:
            flags.append(Text("unreach", style="dim"))
        if f.get("lifecycle") == "new":
            flags.append(Text("NEW", style="cyan"))
        if f.get("suppressed"):
            flags.append(Text("supp", style="dim italic"))
        flag_text = Text(" ")
        for i, t in enumerate(flags):
            if i:
                flag_text.append(" ")
            flag_text.append(t)

        files = f.get("affected_files") or []
        file = files[0] if files else ""
        line = (f.get("affected_lines") or [{}])[0].get("start")
        if file and line:
            file = f"{file}:L{line}"

        table.add_row(
            severity_text(f.get("severity", "?")),
            f.get("title", ""),
            f.get("category", ""),
            file,
            flag_text,
        )

    if len(sorted_findings) > max_rows:
        table.caption = f"showing top {max_rows} of {len(sorted_findings)}"

    return table


def summary_counts(findings: list[dict]) -> Table:
    """A one-row severity-count table — used for the post-scan summary."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        s = f.get("severity")
        if s in counts:
            counts[s] += 1
    kev = sum(1 for f in findings if f.get("kev"))
    unreach = sum(1 for f in findings if f.get("reachable") is False)

    table = Table(show_header=True, header_style="dim", border_style="dim", expand=False)
    for s in SEVERITY_ORDER:
        table.add_column(s[:4].upper(), justify="right", no_wrap=True)
    table.add_column("KEV", justify="right")
    table.add_column("unreach", justify="right")
    row = [
        Text(str(counts[s]), style=_SEVERITY_STYLE[s] if counts[s] else "dim")
        for s in SEVERITY_ORDER
    ]
    row.append(Text(str(kev), style="bold red" if kev else "dim"))
    row.append(Text(str(unreach), style="dim"))
    table.add_row(*row)
    return table


def priority_panel(audit: dict, clusters: dict) -> Panel | None:
    """Render the LLM-ranked top-K priority list, if present."""
    profile = audit.get("profile") or {}
    plist = profile.get("priority_list") or []
    if not plist:
        return None

    by_key = {c["key"]: c for c in clusters.get("items", [])}

    body = Text()
    body.append("// these are the clusters the auditor ranked for this week\n\n", style="dim")
    for i, p in enumerate(plist, start=1):
        c = by_key.get(p.get("cluster_key"))
        if not c:
            continue
        body.append(f"#{i:02d} ", style="bold yellow")
        body.append(severity_text(c["severity"]))
        body.append(f"  {c['title']}", style="bold")
        if c.get("instances", 1) > 1:
            body.append(f"  ×{c['instances']}", style="dim")
        body.append("\n     ")
        body.append(p["reason"], style="dim")
        body.append("\n\n")
    return Panel(body, title="[ fix.this_week() · ranked ]", title_align="left", border_style="yellow")

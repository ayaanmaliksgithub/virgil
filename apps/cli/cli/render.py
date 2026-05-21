"""Terminal rendering — keeps the disassembler aesthetic, fits 80–120 columns.

We use `rich` for table layout + color, but the styles are deliberately
restrained: warm phosphor accent (yellow), severity reds/ambers/greens,
muted gutters in `dim`. No emoji.
"""
from __future__ import annotations

from rich.console import Console, Group
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


def clusters_table(items: list[dict], *, max_rows: int | None = None) -> Group:
    """List view for `virgil clusters AUDIT_ID`.

    Renders one tight, color-coded table per severity bucket, with a section
    header announcing the count. Empty severities are skipped. The point is
    visual triage: CRITICAL/HIGH dominate; LOW/INFO are quietly listed below.
    """
    by_sev: dict[str, list[dict]] = {s: [] for s in SEVERITY_ORDER}
    for c in items:
        s = c.get("severity")
        if s in by_sev:
            by_sev[s].append(c)
        else:
            by_sev.setdefault("Informational", []).append(c)

    # Sort within each bucket by instance count (loudest first), then title.
    for s in by_sev:
        by_sev[s].sort(key=lambda c: (-int(c.get("instances") or 0), c.get("title", "")))

    blocks: list = []
    shown = 0
    truncated = False
    overall_index = 0
    for sev in SEVERITY_ORDER:
        bucket = by_sev.get(sev) or []
        if not bucket:
            continue
        if max_rows is not None and shown >= max_rows:
            truncated = True
            break

        # Section header
        header_text = Text()
        header_text.append(sev.upper(), style=_SEVERITY_STYLE.get(sev, "white"))
        header_text.append(f"  · {len(bucket)} cluster{'s' if len(bucket) != 1 else ''}", style="dim")
        blocks.append(Text(""))  # blank line before each section
        blocks.append(header_text)

        # Tight per-section table — no severity column (it's the header), and
        # title gets the lion's share of the width.
        t = Table(
            show_header=True,
            header_style="dim",
            border_style="dim",
            box=None,             # no heavy box; the section header carries the visual weight
            pad_edge=False,
            expand=True,
        )
        t.add_column("#", width=4, no_wrap=True, justify="right", style="dim")
        t.add_column("title", ratio=5, overflow="ellipsis", no_wrap=True,
                     style=_SEVERITY_STYLE.get(sev, "white"))
        t.add_column("category", ratio=2, style="dim", no_wrap=True, overflow="ellipsis")
        t.add_column("×", width=4, justify="right", no_wrap=True, style="dim")
        t.add_column("flags", width=10, justify="left", style="dim", no_wrap=True)
        t.add_column("key", style="dim", no_wrap=True, width=16)

        for c in bucket:
            if max_rows is not None and shown >= max_rows:
                truncated = True
                break
            overall_index += 1
            shown += 1
            flag_text = Text("")
            if c.get("kev"):
                flag_text.append("KEV", style="bold red")
            if c.get("all_unreachable"):
                if len(flag_text):
                    flag_text.append(" ")
                flag_text.append("unreach", style="dim")
            t.add_row(
                str(overall_index),
                c.get("title", "") or "",
                c.get("category", "") or "",
                f"×{c.get('instances') or 1}",
                flag_text,
                c.get("key", "") or "",
            )
        blocks.append(t)

    if truncated:
        total = sum(len(v) for v in by_sev.values())
        blocks.append(Text(f"  … showing {shown} of {total} clusters (use -n / --limit)", style="dim"))

    return Group(*blocks)


def cluster_detail_panel(cluster: dict) -> Panel:
    """Drill view for `virgil cluster AUDIT_ID CLUSTER_KEY`."""
    body = Text()
    body.append("title       ", style="dim"); body.append(str(cluster.get("title", "")) + "\n", style="bold")
    body.append("severity    ", style="dim"); body.append(str(cluster.get("severity", "?")) + "\n")
    body.append("confidence  ", style="dim"); body.append(str(cluster.get("confidence", "?")) + "\n")
    body.append("category    ", style="dim"); body.append(str(cluster.get("category") or "—") + "\n")
    body.append("cwe         ", style="dim"); body.append(str(cluster.get("cwe") or "—") + "\n")
    body.append("instances   ", style="dim"); body.append(str(cluster.get("instances") or 1) + "\n")
    body.append("key         ", style="dim"); body.append(str(cluster.get("key") or "—") + "\n")
    if cluster.get("kev"):
        body.append("kev         ", style="dim"); body.append("yes\n", style="bold red")
    if cluster.get("all_unreachable"):
        body.append("reachable   ", style="dim"); body.append("none (all unreachable)\n", style="dim")
    elif cluster.get("any_unreachable"):
        body.append("reachable   ", style="dim"); body.append("partial\n", style="dim")
    cves = cluster.get("cves") or []
    if cves:
        body.append("cves        ", style="dim"); body.append(", ".join(cves) + "\n")
    if cluster.get("hint"):
        body.append("\n")
        body.append("// fix the helper, not the callsites:\n", style="dim")
        body.append(str(cluster["hint"]) + "\n", style="yellow")
    files = cluster.get("files") or []
    if files:
        body.append("\n")
        body.append(f"files ({len(files)}):\n", style="dim")
        for f in files[:20]:
            body.append("  " + str(f) + "\n")
        if len(files) > 20:
            body.append(f"  … and {len(files) - 20} more\n", style="dim")
    return Panel(body, title=f"[ cluster · {cluster.get('title', '')[:60]} ]",
                 title_align="left", border_style="yellow")


def finding_detail(f: dict) -> Panel:
    """Single-finding drill: severity/confidence header + the why-flagged trace
    block (scanner+rule, file:line, evidence, cwe/cve refs) + prose blocks."""
    files = f.get("affected_files") or []
    lines = f.get("affected_lines") or []
    first_line = lines[0] if lines else {}
    raw_ref = f.get("raw_reference") or {}
    rule_id = raw_ref.get("check_id") or raw_ref.get("rule_id") or raw_ref.get("pkg") or raw_ref.get("id")

    body = Text()
    body.append("severity    ", style="dim"); body.append(str(f.get("severity", "?")) + "\n")
    body.append("confidence  ", style="dim"); body.append(str(f.get("confidence", "?")) + "\n")
    body.append("category    ", style="dim"); body.append(str(f.get("category") or "—") + "\n")
    if f.get("kev"):
        body.append("kev         ", style="dim"); body.append("yes\n", style="bold red")
    if f.get("reachable") is False:
        body.append("reachable   ", style="dim"); body.append("no\n", style="dim")
    if f.get("suppressed"):
        body.append("suppressed  ", style="dim")
        body.append(f"yes — {f.get('suppression_reason') or 'no reason given'}\n", style="dim italic")

    body.append("\n// why_we_flagged_this()\n", style="dim")
    body.append("  scanner   ", style="dim")
    body.append(", ".join(f.get("source_tool") or []) or "—")
    if rule_id:
        body.append("  rule=", style="dim"); body.append(str(rule_id))
    body.append("\n")
    if first_line:
        body.append("  file      ", style="dim")
        body.append(str(first_line.get("file") or files[0] if files else "—"))
        if first_line.get("start"):
            body.append(":L", style="dim"); body.append(str(first_line["start"]))
            if first_line.get("end") and first_line.get("end") != first_line.get("start"):
                body.append(f"–{first_line['end']}", style="dim")
        body.append("\n")
    elif files:
        body.append("  file      ", style="dim"); body.append(str(files[0]) + "\n")
    if f.get("evidence"):
        body.append("  evidence  ", style="dim"); body.append(str(f["evidence"])[:200] + "\n", style="dim")
    if f.get("cwe"):
        body.append("  cwe       ", style="dim"); body.append(str(f["cwe"]) + "\n")
    if f.get("cve"):
        body.append("  cve       ", style="dim"); body.append(str(f["cve"]) + "\n")

    for label, key in [("explanation", "explanation"),
                       ("exploitability", "exploitability_summary"),
                       ("business impact", "business_impact"),
                       ("guidance", "safe_guidance")]:
        val = f.get(key)
        if val:
            body.append(f"\n// {label}\n", style="dim")
            body.append(str(val) + "\n")

    if f.get("code_context"):
        body.append("\n// code.context() — the slice the model saw\n", style="dim")
        snippet = str(f["code_context"])
        # Cap to keep the panel readable. The full slice is in the JSON output.
        for line in snippet.splitlines()[:20]:
            body.append("  " + line + "\n", style="dim")
        if len(snippet.splitlines()) > 20:
            body.append(f"  … and {len(snippet.splitlines()) - 20} more lines\n", style="dim")

    title = f"[ finding · {(f.get('title') or '')[:60]} ]"
    return Panel(body, title=title, title_align="left", border_style="yellow")


def chat_turn(role: str, content: str, *, citations: list[str] | None = None) -> Panel:
    """Render a single chat turn. `role` is "user" or "assistant"."""
    if role == "user":
        title = "[ you ]"
        style = "cyan"
    else:
        title = "[ auditor ]"
        style = "yellow"
    body = Text(content)
    if citations:
        body.append("\n\n")
        body.append("// citations\n", style="dim")
        for c in citations:
            body.append("  " + c + "\n", style="dim")
    return Panel(body, title=title, title_align="left", border_style=style)


def surface_panel(audit: dict) -> Panel:
    """Attack-surface readout: languages / frameworks / pkg managers / IaC."""
    p = audit.get("profile") or {}
    langs = p.get("languages") or {}
    body = Text()
    body.append("languages    ", style="dim")
    if isinstance(langs, dict) and langs:
        top = sorted(langs.items(), key=lambda kv: -int(kv[1] or 0))[:8]
        body.append("  ".join(f"{k} {v}" for k, v in top))
    else:
        body.append("—", style="dim")
    body.append("\n")
    for label, key in [("frameworks  ", "frameworks"),
                       ("pkg.mgrs    ", "package_managers"),
                       ("iac         ", "iac")]:
        body.append(label, style="dim")
        vals = p.get(key) or []
        body.append(", ".join(vals) if vals else "—", style=("white" if vals else "dim"))
        body.append("\n")
    body.append("files       ", style="dim"); body.append(str(p.get("file_count") or "—") + "\n")
    body.append("loc         ", style="dim")
    loc = p.get("loc")
    body.append(f"{loc:,}" if isinstance(loc, int) else "—")
    return Panel(body, title="[ attack.surface ]", title_align="left", border_style="dim")


def executive_narrative_panel(audit: dict) -> Panel | None:
    """The auditor's prose summary, if the LLM enrichment ran."""
    p = audit.get("profile") or {}
    narrative = p.get("narrative")
    if not narrative:
        return None
    body = Text()
    body.append("// auditor.narrative\n", style="dim")
    body.append(str(narrative))
    return Panel(body, title="[ executive ]", title_align="left", border_style="dim")


def next_steps(audit_id: str, *, has_findings: bool, web_url: str | None = None) -> Panel:
    """Tight `// what now` hint footer for the end of `virgil scan`."""
    body = Text()
    body.append("// what now\n", style="dim")
    if has_findings:
        body.append("  virgil clusters ", style="bold")
        body.append(f"{audit_id}\n", style="dim")
        body.append("  virgil chat     ", style="bold")
        body.append(f"{audit_id}\n", style="dim")
        body.append("  virgil findings ", style="bold")
        body.append(f"{audit_id}  ", style="dim")
        body.append("# raw table\n", style="dim italic")
        body.append("  virgil report   ", style="bold")
        body.append(f"{audit_id} --format md\n", style="dim")
    if web_url:
        body.append("  virgil open     ", style="bold")
        body.append(f"{audit_id}  ", style="dim")
        body.append(f"# {web_url}\n", style="dim italic")
    return Panel(body, title="[ next ]", title_align="left", border_style="dim")


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

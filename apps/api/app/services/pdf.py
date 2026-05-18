"""PDF rendering via WeasyPrint.

The PDF is print-grade — it preserves the platform's evidence-first stance
without any of the live-screen affordances (no SSE, no hover states). We
generate an HTML document and let WeasyPrint do the layout.

WeasyPrint requires system libraries (cairo, pango, gdk-pixbuf). The API
Dockerfile installs them; on bare metal you'll need to install them yourself
before this endpoint will work.
"""
from __future__ import annotations

import html
import logging
from datetime import datetime
from typing import Any

log = logging.getLogger(__name__)

_SEVERITY_COLOR = {
    "Critical":      "#A52B14",
    "High":          "#A1741F",
    "Medium":        "#7C7141",
    "Low":           "#4E5F5B",
    "Informational": "#3F4E5F",
}
_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def render_pdf(payload: dict[str, Any], view: str) -> bytes:
    """Render report payload to a PDF byte string.

    Raises `RuntimeError` if WeasyPrint is not available so callers can
    degrade to MD/JSON rather than crashing.
    """
    try:
        from weasyprint import HTML, CSS  # type: ignore
    except Exception as e:
        raise RuntimeError("weasyprint not installed") from e

    html_doc = _render_html(payload, view)
    return HTML(string=html_doc).write_pdf(stylesheets=[CSS(string=_CSS)])


# --- HTML --------------------------------------------------------------------


def _render_html(payload: dict[str, Any], view: str) -> str:
    audit_id = payload.get("audit_id", "")
    src = payload.get("source", {})
    generated = payload.get("generated_at") or datetime.utcnow().isoformat()
    title = "Executive Audit Report" if view == "executive" else "Technical Audit Report"
    summary = payload.get("summary", {}) or {}
    sev = summary.get("severity_breakdown", {}) or {}
    owasp = summary.get("owasp_breakdown", {}) or {}

    body_parts = [
        _masthead(title, audit_id, src, generated),
        _severity_block(sev),
    ]

    if view == "executive":
        if payload.get("narrative"):
            body_parts.append(_section("Narrative", _para(payload["narrative"])))
        body_parts.append(_owasp_table(owasp))
        body_parts.append(_top_findings(payload.get("top_findings") or []))
    else:
        body_parts.append(_owasp_table(owasp))
        body_parts.append(_findings_register(payload.get("findings") or []))

    body_parts.append(_disclaimer())

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{html.escape(title)} — Cipher Audit</title>
</head>
<body>
  {"".join(body_parts)}
</body>
</html>"""


def _masthead(title: str, audit_id: str, src: dict, generated: str) -> str:
    return f"""
    <header class="masthead">
      <div class="masthead-eyebrow">CIPHER AUDIT · {html.escape(title.upper())}</div>
      <h1>{html.escape(title)}</h1>
      <table class="meta">
        <tr><th>Case ID</th><td class="mono">{html.escape(audit_id)}</td></tr>
        <tr><th>Source</th><td class="mono">{html.escape(str(src.get('kind') or '—'))} · {html.escape(str(src.get('ref') or '—'))}</td></tr>
        {f"<tr><th>Commit</th><td class='mono'>{html.escape(str(src.get('sha')))}</td></tr>" if src.get("sha") else ""}
        <tr><th>Generated</th><td>{html.escape(generated)}</td></tr>
      </table>
    </header>
    """


def _severity_block(sev: dict) -> str:
    total = sum(int(sev.get(k, 0) or 0) for k in _SEV_ORDER) or 1
    cells = []
    for k in _SEV_ORDER:
        n = int(sev.get(k, 0) or 0)
        cells.append(
            f"<div class='sev-cell'>"
            f"  <div class='sev-bar' style='background:{_SEVERITY_COLOR[k]};width:{(n/total)*100:.1f}%'></div>"
            f"  <div class='sev-label'><span class='sev-dot' style='background:{_SEVERITY_COLOR[k]}'></span>{html.escape(k)}</div>"
            f"  <div class='sev-count'>{n}</div>"
            f"</div>"
        )
    return _section("Severity distribution", f"<div class='sev-grid'>{''.join(cells)}</div>")


def _owasp_table(owasp: dict) -> str:
    entries = sorted(owasp.items(), key=lambda kv: kv[1], reverse=True)
    if not entries:
        return ""
    rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td class='right mono'>{v}</td></tr>"
        for k, v in entries
    )
    table = f"<table class='register'><thead><tr><th>OWASP category</th><th class='right'>Count</th></tr></thead><tbody>{rows}</tbody></table>"
    return _section("OWASP distribution", table)


def _top_findings(items: list[dict]) -> str:
    if not items:
        return ""
    lis = "".join(
        f"<li>"
        f"<div class='entry-head'><span class='sev-pill' style='border-color:{_SEVERITY_COLOR.get(f.get('severity','Medium'), '#888')};color:{_SEVERITY_COLOR.get(f.get('severity','Medium'), '#888')}'>[ {html.escape(str(f.get('severity','')).upper())} ]</span>"
        f"<h3>{html.escape(str(f.get('title','')))}</h3></div>"
        f"<div class='entry-meta mono'>{html.escape(str(f.get('category','')))}"
        + (f" · {html.escape(str(f.get('owasp_category')))}" if f.get("owasp_category") else "")
        + "</div>"
        + (f"<p class='entry-body'><strong>Impact —</strong> {html.escape(str(f.get('business_impact')))}</p>" if f.get("business_impact") else "")
        + "</li>"
        for f in items
    )
    return _section("Top findings", f"<ol class='top-findings'>{lis}</ol>")


def _findings_register(items: list[dict]) -> str:
    if not items:
        return ""
    lis = []
    for i, f in enumerate(items, start=1):
        sev = str(f.get("severity", "Medium"))
        affected = "".join(
            f"<li><span class='mono'>{html.escape(str(al.get('file','')))}</span>"
            f" <span class='mono dim'>L{int(al.get('start', 1))}"
            + (f"–{int(al['end'])}" if al.get("end") and al['end'] != al['start'] else "")
            + "</span></li>"
            for al in (f.get("affected_lines") or [])
        )
        lis.append(
            f"<li class='entry'>"
            f"<div class='entry-head'>"
            f"  <span class='entry-no mono'>0x{((i-1)*0x10):06x}</span>"
            f"  <span class='sev-pill' style='border-color:{_SEVERITY_COLOR.get(sev,'#888')};color:{_SEVERITY_COLOR.get(sev,'#888')}'>[ {html.escape(sev.upper())} ]</span>"
            f"  <h3>{html.escape(str(f.get('title','')))}</h3>"
            f"</div>"
            f"<div class='entry-meta mono'>"
            f"  {html.escape(str(f.get('category','')))}"
            + (f" · {html.escape(str(f.get('owasp_category')))}" if f.get("owasp_category") else "")
            + (f" · {html.escape(str(f.get('cwe')))}" if f.get("cwe") else "")
            + (f" · <span class='cve'>{html.escape(str(f.get('cve')))}</span>" if f.get("cve") else "")
            + f" · sources: {html.escape(', '.join(f.get('source_tool') or []))}"
            + "</div>"
            + (f"<p class='entry-body'>{html.escape(str(f.get('explanation','')))}</p>" if f.get("explanation") else "")
            + (f"<p class='entry-body'><strong>Impact —</strong> {html.escape(str(f.get('business_impact')))}</p>" if f.get("business_impact") else "")
            + (f"<p class='entry-body'><strong>Defensive guidance —</strong> {html.escape(str(f.get('safe_guidance')))}</p>" if f.get("safe_guidance") else "")
            + (f"<ul class='affected'>{affected}</ul>" if affected else "")
            + (f"<pre class='evidence'>{html.escape(str(f.get('evidence','')))}</pre>" if f.get("evidence") else "")
            + "</li>"
        )
    return _section("Findings register", f"<ol class='register-list'>{''.join(lis)}</ol>")


def _disclaimer() -> str:
    return (
        "<section class='disclaimer'>"
        "<div class='term-label'>Scope</div>"
        "<p>Cipher Audit is an audit and risk-analysis platform. This report "
        "describes risks identified by deterministic scanners and summarized "
        "by an audit reasoning layer. It does not include exploit payloads, "
        "step-by-step reproduction, exact code patches, or operational "
        "remediation runbooks.</p>"
        "</section>"
    )


def _section(title: str, inner: str) -> str:
    return (
        f"<section class='section'>"
        f"<div class='term-label'>// {html.escape(title)}</div>"
        f"<h2>{html.escape(title)}</h2>"
        f"{inner}"
        f"</section>"
    )


def _para(text: str) -> str:
    return f"<p class='lede'>{html.escape(text)}</p>"


# --- CSS ---------------------------------------------------------------------

_CSS = """
@page {
  size: A4;
  margin: 22mm 18mm 22mm 18mm;
  @bottom-right {
    content: "page " counter(page) " / " counter(pages);
    font-family: "DejaVu Sans Mono", monospace;
    font-size: 9pt;
    color: #888;
  }
  @bottom-left {
    content: "Cipher Audit · evidence-first · not an exploit toolkit";
    font-family: "DejaVu Sans Mono", monospace;
    font-size: 9pt;
    color: #888;
  }
}

* { box-sizing: border-box; }
body {
  font-family: "DejaVu Sans Mono", "Menlo", monospace;
  font-size: 10.5pt;
  line-height: 1.55;
  color: #181410;
  background: #FDFBF4;
}

.mono { font-family: "DejaVu Sans Mono", monospace; }
.right { text-align: right; }
.dim { color: #777; }

.masthead { border-bottom: 1px solid #181410; padding-bottom: 12mm; margin-bottom: 10mm; }
.masthead-eyebrow {
  font-size: 8pt;
  letter-spacing: 0.18em;
  color: #555;
  text-transform: uppercase;
}
.masthead h1 {
  font-family: "DejaVu Sans Mono", monospace;
  font-size: 28pt;
  font-weight: 700;
  margin: 6mm 0 8mm;
  letter-spacing: -0.01em;
}
.meta { width: 100%; border-collapse: collapse; font-size: 9.5pt; }
.meta th {
  text-align: left;
  width: 90px;
  color: #666;
  font-weight: 500;
  font-size: 8.5pt;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  padding: 1mm 0;
}
.meta td { padding: 1mm 0; }

.section { margin-top: 10mm; page-break-inside: avoid; }
.term-label {
  font-size: 8pt;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: #888;
  margin-bottom: 1.5mm;
}
.section h2 {
  font-family: "DejaVu Sans Mono", monospace;
  font-size: 16pt;
  letter-spacing: -0.005em;
  margin: 0 0 3mm 0;
  border-bottom: 0.5pt solid #cfc7b0;
  padding-bottom: 2mm;
}

.lede { font-size: 11pt; line-height: 1.65; }

.sev-grid { display: flex; gap: 4mm; }
.sev-cell {
  flex: 1; border: 0.5pt solid #cfc7b0; padding: 3mm; background: #FAF6E8;
}
.sev-bar { height: 4px; margin-bottom: 3mm; }
.sev-label {
  font-size: 8pt; letter-spacing: 0.16em; text-transform: uppercase; color: #444;
  display: flex; align-items: center; gap: 1.5mm;
}
.sev-dot { display: inline-block; width: 8px; height: 8px; }
.sev-count {
  font-family: "DejaVu Sans Mono", monospace;
  font-size: 22pt; font-weight: 700; margin-top: 1.5mm;
}

table.register { width: 100%; border-collapse: collapse; font-size: 10pt; }
table.register th, table.register td {
  text-align: left; padding: 1.5mm 2mm; border-bottom: 0.4pt solid #d6cdb2;
}
table.register th {
  text-transform: uppercase; letter-spacing: 0.16em; font-size: 8pt; color: #666; font-weight: 500;
}

ol.top-findings, ol.register-list { list-style: none; padding: 0; margin: 0; }
ol.top-findings li, ol.register-list li.entry {
  border-top: 0.5pt solid #d6cdb2;
  padding: 4mm 0;
  page-break-inside: avoid;
}
.entry-head { display: flex; align-items: baseline; gap: 3mm; flex-wrap: wrap; }
.entry-no { font-size: 8.5pt; color: #aaa; }
.sev-pill {
  border: 0.6pt solid currentColor;
  padding: 0.6mm 2mm;
  font-size: 8pt;
  letter-spacing: 0.16em;
}
.entry-head h3 {
  font-family: "DejaVu Sans Mono", monospace;
  font-size: 12pt;
  font-weight: 600;
  margin: 0;
}
.entry-meta { font-size: 9pt; color: #555; margin-top: 1mm; }
.entry-meta .cve { color: #A1741F; }
.entry-body { margin: 2mm 0; font-size: 10pt; line-height: 1.65; }
ul.affected { list-style: none; padding: 0; margin: 2mm 0; font-size: 9pt; }
ul.affected li { display: flex; justify-content: space-between; border-top: 0.3pt dotted #c8c0a8; padding: 0.8mm 0; }
pre.evidence {
  font-family: "DejaVu Sans Mono", monospace;
  font-size: 9pt;
  white-space: pre-wrap;
  background: #F0EBD9;
  border: 0.5pt solid #d6cdb2;
  padding: 2mm 3mm;
  margin: 2mm 0 0;
  color: #2a241a;
}

.disclaimer {
  margin-top: 16mm;
  padding-top: 4mm;
  border-top: 0.5pt solid #cfc7b0;
  font-size: 9pt;
  color: #555;
  page-break-inside: avoid;
}
"""

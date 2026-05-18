/**
 * Inline code-context view for the finding detail page.
 *
 * Renders the redacted ~30-line slice that the worker captured at audit
 * time. The offending line is highlighted with a left rail + warm-phosphor
 * tint so the eye lands on it immediately. Redaction markers from the
 * upstream scrubber (`<host-path>`, `<jwt-redacted>`, …) keep their text
 * but pick up a muted style so it reads as "intentionally masked," not as
 * a typo.
 *
 * The input format is what `worker/normalize/code_context.py` emits:
 *   "  40  ctx = build()\n  41  q = make_query(user)\n  42  db.execute(q)"
 * — a 1-indexed line number, two spaces, the (redacted) line. A trailing
 * "… (truncated)" marker is preserved as-is.
 */
const LINE_RE = /^(\s*\d+)\s\s(.*)$/;
const REDACTION_RE = /(<[^>]+?-redacted>|<host-path>|<internal-ip>|<jwt-redacted>|<google-api-key-redacted>|<slack-token-redacted>|<private-key-redacted>|AKIA\*+|ghp_<redacted>)/g;

export function CodeContext({
  codeContext,
  highlightLine,
  fileLabel,
}: {
  codeContext: string;
  highlightLine?: number | null;
  fileLabel?: string;
}) {
  const lines = codeContext.split("\n");
  const parsed = lines.map((raw) => {
    const m = LINE_RE.exec(raw);
    if (!m) return { lineNo: null as number | null, text: raw };
    return { lineNo: parseInt(m[1].trim(), 10), text: m[2] };
  });

  return (
    <div className="panel pt-4">
      <span className="panel-title">code.context() · redacted on read</span>
      <div className="border-b border-ink-300 px-4 py-2 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
        {fileLabel ? <>file ⟶ <span className="text-bone-dim">{fileLabel}</span></> : "code slice"}
        {highlightLine ? (
          <span className="ml-3">
            offending ⟶ <span className="text-signal-live tabular">L{highlightLine}</span>
          </span>
        ) : null}
      </div>
      <pre className="overflow-x-auto px-0 py-2 font-mono text-[12px] leading-[1.6]">
        {parsed.map((p, i) => {
          const isHit = p.lineNo !== null && p.lineNo === highlightLine;
          return (
            <div
              key={i}
              className={
                isHit
                  ? "grid grid-cols-[60px_4px_1fr] gap-0 border-l-2 border-signal-live bg-ink-100"
                  : "grid grid-cols-[60px_4px_1fr] gap-0 border-l-2 border-transparent"
              }
            >
              <span
                className={
                  isHit
                    ? "select-none px-3 text-right font-mono text-[11px] text-signal-live tabular"
                    : "select-none px-3 text-right font-mono text-[11px] text-ink-400 tabular"
                }
              >
                {p.lineNo ?? ""}
              </span>
              <span aria-hidden />
              <span
                className={
                  isHit
                    ? "whitespace-pre pl-2 pr-4 text-bone"
                    : "whitespace-pre pl-2 pr-4 text-bone-dim"
                }
              >
                {renderWithRedaction(p.text)}
              </span>
            </div>
          );
        })}
      </pre>
      <div className="border-t border-ink-300 px-4 py-2 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
        <span className="text-ink-400">{"//"}</span> redactor: aws keys · gh
        tokens · jwts · slack/google keys · private keys · rfc1918 · host paths
      </div>
    </div>
  );
}

function renderWithRedaction(text: string) {
  // Split the line so each redaction span gets a distinct style; surrounding
  // text stays in the default code color. The split keeps delimiters via
  // capture groups in the regex.
  const parts = text.split(REDACTION_RE);
  return (
    <>
      {parts.map((seg, i) => {
        if (!seg) return null;
        if (REDACTION_RE.test(seg)) {
          // reset lastIndex after a regex test on a global pattern
          REDACTION_RE.lastIndex = 0;
          return (
            <span key={i} className="bg-ink-300 px-1 text-ink-400">
              ▒{seg}▒
            </span>
          );
        }
        return <span key={i}>{seg}</span>;
      })}
    </>
  );
}

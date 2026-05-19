/**
 * "Why did you flag this?" — the structured trace from LLM-surfaced prose
 * back to the deterministic artifacts that grounded it.
 *
 * Implements Virgil's first product principle (ARCHITECTURE.md §1): every
 * AI-surfaced finding traces back to scanner output, repository file,
 * dependency manifest, or IaC/config file. The LLM is a reasoning +
 * summarization layer, never a source of vulnerabilities.
 *
 * Surfaced on the finding detail page in place of the old prose
 * "provenance" block. Each `ProvenanceTag` elsewhere on the page links
 * here via anchor (`#provenance-{finding_id}`) so the user can click "from
 * scanner X" on any prose block and land on the receipts.
 */
import type { Finding } from "@/lib/types";

export function GroundingTrace({ finding }: { finding: Finding }) {
  // Heuristic LLM-presence detection — we don't track per-field provenance
  // server-side, but `business_impact` and `exploitability_summary` are
  // LLM-only fields (no scanner fallback), so their presence is a strong
  // signal the enrichment step ran.
  const llmRan = !!(finding.business_impact || finding.exploitability_summary);

  const cweNum = finding.cwe?.match(/CWE-(\d+)/)?.[1] ?? null;
  const cweUrl = cweNum
    ? `https://cwe.mitre.org/data/definitions/${cweNum}.html`
    : null;
  const cveUrl = finding.cve
    ? `https://nvd.nist.gov/vuln/detail/${finding.cve}`
    : null;

  const ruleId =
    (finding as Finding & { raw_reference?: Record<string, string> }).raw_reference
      ?.check_id ??
    (finding as Finding & { raw_reference?: Record<string, string> }).raw_reference
      ?.rule_id ??
    (finding as Finding & { raw_reference?: Record<string, string> }).raw_reference
      ?.pkg ??
    (finding as Finding & { raw_reference?: Record<string, string> }).raw_reference
      ?.id ??
    null;

  const firstLine = finding.affected_lines?.[0];

  return (
    <div id={`provenance-${finding.id}`}>
      <div className="term-label mb-2">why_we_flagged_this() · grounding trace</div>
      <div className="panel pt-4">
        <span className="panel-title">deterministic_artifacts</span>

        <Row addr="0x00" label="scanner">
          {finding.source_tool.map((t, i) => (
            <span key={t}>
              {i ? <span className="text-ink-400"> · </span> : null}
              <span className="text-bone">{t}</span>
            </span>
          ))}
          {ruleId && (
            <>
              <span className="text-bone-ghost"> rule=</span>
              <span className="text-bone-dim">{ruleId}</span>
            </>
          )}
        </Row>

        <Row addr="0x10" label="file">
          {firstLine ? (
            <>
              <span className="text-bone">{firstLine.file}</span>
              <span className="text-bone-ghost">:</span>
              <span className="text-bone-mute tabular">
                L{firstLine.start}
                {firstLine.end && firstLine.end !== firstLine.start
                  ? `–${firstLine.end}`
                  : ""}
              </span>
            </>
          ) : finding.affected_files?.[0] ? (
            <span className="text-bone">{finding.affected_files[0]}</span>
          ) : (
            <span className="text-bone-ghost">—</span>
          )}
        </Row>

        <Row addr="0x20" label="evidence">
          <code className="break-all text-bone-dim">{finding.evidence || "—"}</code>
        </Row>

        {finding.cwe && (
          <Row addr="0x30" label="cwe">
            {cweUrl ? (
              <a
                href={cweUrl}
                target="_blank"
                rel="noreferrer"
                className="text-bone hover:text-signal-live"
              >
                {finding.cwe}
              </a>
            ) : (
              <span className="text-bone">{finding.cwe}</span>
            )}
            <span className="text-bone-ghost"> · mitre.org</span>
          </Row>
        )}

        {finding.cve && (
          <Row addr="0x40" label="cve">
            {cveUrl ? (
              <a
                href={cveUrl}
                target="_blank"
                rel="noreferrer"
                className="text-signal-high hover:text-bone"
              >
                {finding.cve}
              </a>
            ) : (
              <span className="text-signal-high">{finding.cve}</span>
            )}
            <span className="text-bone-ghost"> · nvd.nist.gov</span>
            {finding.kev && (
              <span
                title="CISA Known Exploited Vulnerability"
                className="ml-2 text-signal-critical"
              >
                [KEV]
              </span>
            )}
            {typeof finding.epss_score === "number" && (
              <span className="ml-2 text-bone-mute">
                EPSS={finding.epss_score.toFixed(2)}
              </span>
            )}
          </Row>
        )}

        {finding.owasp_category && (
          <Row addr="0x50" label="owasp">
            <span className="text-bone-dim">{finding.owasp_category}</span>
          </Row>
        )}

        <Row addr="0x60" label="code.ctx" last={!finding.code_context}>
          {finding.code_context ? (
            <>
              <span className="text-bone-ghost">window above ⟶ </span>
              <a href="#code-context" className="text-bone hover:text-signal-live">
                code.context()
              </a>
              <span className="text-bone-ghost"> · same slice the model saw</span>
            </>
          ) : (
            <span className="text-bone-ghost">no slice captured (no source on disk)</span>
          )}
        </Row>

        {/* Footer — make the LLM-vs-scanner provenance unambiguous. */}
        <div className="border-t border-ink-300 px-4 py-3 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
          {llmRan ? (
            <>
              <span className="text-signal-live">●</span> scanners detected; llm described.
              every prose block above is grounded in the artifacts shown.
              outputs passed the safety validator before storage.
            </>
          ) : (
            <>
              <span className="text-bone-mute">●</span> scanner output only · no llm
              ran for this audit (no provider configured). prose fields are
              scanner-derived where present, blank where not.
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function Row({
  addr,
  label,
  children,
  last,
}: {
  addr: string;
  label: string;
  children: React.ReactNode;
  last?: boolean;
}) {
  return (
    <div
      className={
        last
          ? "grid grid-cols-[60px_90px_1fr] items-baseline gap-3 px-4 py-2 font-mono text-[12px]"
          : "grid grid-cols-[60px_90px_1fr] items-baseline gap-3 border-b border-ink-300 px-4 py-2 font-mono text-[12px]"
      }
    >
      <span className="text-ink-400 tabular text-[10px] uppercase tracking-widest2">
        {addr}
      </span>
      <span className="text-bone-ghost text-[10px] uppercase tracking-widest2">
        {label}
      </span>
      <span className="break-words text-bone-mute">{children}</span>
    </div>
  );
}

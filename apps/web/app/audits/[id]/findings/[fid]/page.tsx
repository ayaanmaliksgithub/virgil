import Link from "next/link";
import { CodeContext } from "@/components/code-context";
import { ConfidenceChip } from "@/components/confidence-chip";
import { GroundingTrace } from "@/components/grounding-trace";
import { OwaspBadge } from "@/components/owasp-badge";
import { ProvenanceTag } from "@/components/provenance-tag";
import { SeverityChip } from "@/components/severity-chip";
import { SuppressAction } from "@/components/suppress-action";
import { loadAudit, loadFinding } from "@/lib/server";
import { tabs } from "../../../tabs";

export default async function FindingDetailPage({ params }: { params: { id: string; fid: string } }) {
  const [audit, finding] = await Promise.all([loadAudit(params.id), loadFinding(params.id, params.fid)]);

  return (
    <article>
      <div className="mb-6 flex items-center justify-between">
        <Link
          href={`/audits/${params.id}/findings`}
          className="group inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-widest2 text-bone-mute hover:text-bone"
        >
          <span aria-hidden className="transition-transform group-hover:-translate-x-1 text-ink-400">←</span>
          $ cd ../ledger
        </Link>
        <div className="hidden gap-6 md:flex">
          {tabs(params.id, "findings").map((t, i) => (
            <Link
              key={t.href}
              href={t.href}
              className="inline-flex items-baseline gap-2 font-mono text-[11px] uppercase tracking-widest2 text-bone-mute hover:text-bone"
            >
              <span className="text-ink-400 tabular">0x{i.toString(16).padStart(2, "0")}</span>
              {t.label}
            </Link>
          ))}
        </div>
      </div>

      {/* TITLE PANEL */}
      <header className="panel pt-4">
        <span className="panel-title">finding_t</span>
        <div className="grid grid-cols-12 gap-x-6 gap-y-3 px-5 py-5">
          <div className="col-span-12 lg:col-span-8">
            <div className="flex items-baseline gap-3 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
              <span className="text-ink-400 tabular">0x{params.fid.padStart(8, "0").toUpperCase()}</span>
              <span>finding_id</span>
            </div>
            <h1 className="mt-2 font-display text-[clamp(28px,4vw,52px)] leading-[1.02] tracking-tight text-bone">
              {finding.title}
            </h1>
            <div className="mt-5 flex flex-wrap items-center gap-x-3 gap-y-2">
              <SeverityChip severity={finding.severity} />
              <ConfidenceChip confidence={finding.confidence} />
              {finding.owasp_category && <OwaspBadge category={finding.owasp_category} />}
              {finding.cwe && (
                <span className="tag text-bone-mute">{finding.cwe}</span>
              )}
              {finding.cve && (
                <span className="tag text-signal-high">{finding.cve}</span>
              )}
              {finding.kev && (
                <span title="CISA Known Exploited Vulnerability" className="tag text-signal-critical">
                  [ KEV ]
                </span>
              )}
              {typeof finding.epss_score === "number" && (
                <span
                  title={`EPSS percentile ${finding.epss_percentile?.toFixed(2) ?? "?"}`}
                  className="tag text-signal-high"
                >
                  EPSS={finding.epss_score.toFixed(2)}
                </span>
              )}
              {finding.lifecycle && (
                <span className="tag text-bone-mute">[{finding.lifecycle.toUpperCase()}]</span>
              )}
              {finding.reachable === false && (
                <span
                  title="dependency is not imported anywhere in source — severity demoted"
                  className="tag text-bone-ghost"
                >
                  [ unreachable ]
                </span>
              )}
              {finding.reachable === true && (
                <span title="dependency is imported in source" className="tag text-bone-mute">
                  [ reachable ]
                </span>
              )}
            </div>
            <div className="mt-4">
              <SuppressAction
                auditId={params.id}
                dedupeKey={finding.dedupe_key}
                suppressed={!!finding.suppressed}
                suppressionId={finding.suppression_id}
                suppressionReason={finding.suppression_reason}
              />
            </div>
          </div>

          <dl className="col-span-12 grid grid-cols-[110px_1fr] items-baseline gap-x-4 gap-y-1 self-end font-mono text-[11px] lg:col-span-4">
            <dt className="text-bone-ghost uppercase tracking-widest2">source ⟶</dt>
            <dd className="text-bone-dim">{finding.source_tool.join(" · ")}</dd>
            <dt className="text-bone-ghost uppercase tracking-widest2">category ⟶</dt>
            <dd className="text-bone-dim">{finding.category}</dd>
            <dt className="text-bone-ghost uppercase tracking-widest2">status ⟶</dt>
            <dd className="text-bone-dim">{finding.status}</dd>
            <dt className="text-bone-ghost uppercase tracking-widest2">filed ⟶</dt>
            <dd className="text-bone-dim">{finding.created_at}</dd>
          </dl>
        </div>
      </header>

      {/* BODY */}
      <section className="mt-10 grid grid-cols-12 gap-x-8 gap-y-10">
        <div className="col-span-12 lg:col-span-7 space-y-8">
          {finding.code_context && (
            <div id="code-context">
              <Block label="code.context() · the actual code">
                <CodeContext
                  codeContext={finding.code_context}
                  highlightLine={finding.affected_lines?.[0]?.start ?? null}
                  fileLabel={finding.affected_lines?.[0]?.file ?? finding.affected_files?.[0]}
                />
                <p className="mt-3 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
                  <span className="text-ink-400">{"//"}</span> {finding.affected_lines?.[0]?.start
                    ? `${finding.affected_lines[0].start} is highlighted · `
                    : ""}redactor scrubs secrets before we ever store, render, or send to the model.
                </p>
              </Block>
            </div>
          )}
          <Block label="explanation()">
            <p className="font-mono text-[14px] leading-[1.7] text-bone-dim">
              <span className="text-bone-ghost">{"//"} </span>{finding.explanation}
            </p>
            <ProvenanceTag finding={finding} />
          </Block>

          {finding.exploitability_summary && (
            <Block label="exploitability_summary() · high-level only">
              <p className="font-mono text-[13px] leading-[1.7] text-bone-dim">
                {finding.exploitability_summary}
              </p>
              <p className="mt-3 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
                <span className="text-ink-400">{"//"}</span> no payloads, no reproduction steps.
              </p>
              <ProvenanceTag finding={finding} />
            </Block>
          )}

          {finding.business_impact && (
            <Block label="business_impact()">
              <p className="font-mono text-[13px] leading-[1.7] text-bone-dim">
                {finding.business_impact}
              </p>
              <ProvenanceTag finding={finding} />
            </Block>
          )}

          {finding.compliance && Object.keys(finding.compliance).length > 0 && (
            <Block label="compliance.controls()">
              <ul className="border border-ink-300 bg-ink-50">
                {Object.entries(finding.compliance).map(([framework, controls]) => (
                  <li
                    key={framework}
                    className="grid grid-cols-[120px_1fr] gap-3 border-b border-ink-300 px-4 py-2 last:border-b-0 font-mono text-[12px]"
                  >
                    <span className="text-bone-ghost uppercase tracking-widest2">{framework}</span>
                    <span className="text-bone-dim">{controls.join(", ")}</span>
                  </li>
                ))}
              </ul>
            </Block>
          )}

          {finding.safe_guidance && (
            <Block label="safe_guidance() · defensive only">
              <div className="border-l-2 border-signal-live bg-ink-50 px-4 py-3">
                <p className="font-mono text-[13px] leading-[1.7] text-bone">
                  {finding.safe_guidance}
                </p>
                <p className="mt-3 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
                  <span className="text-ink-400">{"//"}</span> safety validator: ok · payload/diff/step-by-step rejected
                </p>
              </div>
              <ProvenanceTag finding={finding} />
            </Block>
          )}
        </div>

        <aside className="col-span-12 lg:col-span-5 space-y-8">
          <HexDump text={finding.evidence} />

          <div>
            <div className="term-label mb-2">memory.map · affected locations</div>
            <ul className="panel pt-4">
              <span className="panel-title">offsets</span>
              {finding.affected_lines.map((al, i) => (
                <li
                  key={i}
                  className="grid grid-cols-[80px_1fr_80px] items-center gap-3 border-b border-ink-300 px-4 py-2 last:border-b-0 font-mono text-[12px]"
                >
                  <span className="text-ink-400 tabular text-[11px]">
                    0x{(i * 0x10).toString(16).padStart(6, "0")}
                  </span>
                  <span className="truncate text-bone-dim">{al.file}</span>
                  <span className="text-right text-bone-mute tabular">
                    L{al.start}{al.end && al.end !== al.start ? `–${al.end}` : ""}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <GroundingTrace finding={finding} />
        </aside>
      </section>
    </article>
  );
}

function Block({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <section>
      <div className="term-label mb-2">{label}</div>
      {children}
    </section>
  );
}

/**
 * Render the evidence as a 16-column hex dump. Each cell is either a hex byte
 * of the literal ascii content, or a redacted block when the redactor masked
 * the token. ASCII column on the right rounds out the disassembler vibe.
 */
function HexDump({ text }: { text: string }) {
  const bytes = Array.from(new TextEncoder().encode(text));
  const REDACTED_RE = /<[^>]+?-redacted>|AKIA\*+|ghp_<redacted>|<jwt-redacted>|<host-path>|<internal-ip>/g;
  const redactedRanges: [number, number][] = [];
  for (const m of text.matchAll(REDACTED_RE)) {
    if (m.index === undefined) continue;
    const startByte = new TextEncoder().encode(text.slice(0, m.index)).length;
    const endByte = startByte + new TextEncoder().encode(m[0]).length;
    redactedRanges.push([startByte, endByte]);
  }
  const isRedacted = (i: number) => redactedRanges.some(([s, e]) => i >= s && i < e);

  const rows: number[][] = [];
  for (let i = 0; i < bytes.length; i += 16) rows.push(bytes.slice(i, i + 16));

  return (
    <div>
      <div className="term-label mb-2">evidence.hex · redacted on read</div>
      <div className="panel pt-4">
        <span className="panel-title">hexdump -C</span>
        <pre className="overflow-x-auto px-4 py-3 font-mono text-[11px] leading-[18px] text-bone-mute">
          {rows.map((row, r) => {
            const offset = (r * 16).toString(16).padStart(8, "0");
            return (
              <div key={r} className="grid grid-cols-[90px_1fr_140px] gap-3">
                <span className="text-ink-400">{offset}</span>
                <span className="tabular">
                  {row.map((b, ci) => {
                    const idx = r * 16 + ci;
                    const hex = b.toString(16).padStart(2, "0");
                    return (
                      <span
                        key={ci}
                        className={
                          isRedacted(idx) ? "bg-ink-300 text-ink-400" : "text-bone-dim"
                        }
                      >
                        {hex}{ci === 15 ? "" : " "}
                      </span>
                    );
                  })}
                  {Array.from({ length: 16 - row.length }).map((_, k) => (
                    <span key={`pad-${k}`} className="text-ink-400">   </span>
                  ))}
                </span>
                <span className="text-bone-ghost">
                  │
                  {row.map((b, ci) => {
                    const idx = r * 16 + ci;
                    const c = b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
                    return (
                      <span
                        key={ci}
                        className={isRedacted(idx) ? "bg-ink-300 text-ink-400" : "text-bone-mute"}
                      >
                        {isRedacted(idx) ? "▒" : c}
                      </span>
                    );
                  })}
                  │
                </span>
              </div>
            );
          })}
          <div className="text-ink-400">
            {bytes.length.toString(16).padStart(8, "0")}
          </div>
        </pre>
      </div>
    </div>
  );
}

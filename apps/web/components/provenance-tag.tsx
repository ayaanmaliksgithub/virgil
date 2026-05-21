/**
 * A small, always-visible footer on each LLM-generated prose block that
 * names the deterministic artifact the LLM was grounded in, and anchors
 * to the full `GroundingTrace` panel for the receipts.
 *
 * Rendered like:
 *   ┌─ from static analysis:javascript.express.nosql-injection-mongodb · src/x.py:L42 ¶ trace
 *
 * The trailing `¶ trace` is a link that scrolls to `#provenance-{fid}`. The
 * tag itself is intentionally low-volume — we don't want it to overpower
 * the prose, just to make the lineage visible at a glance.
 */
import type { Finding } from "@/lib/types";
import { friendlyToolName } from "@/lib/tool-labels";

export function ProvenanceTag({ finding }: { finding: Finding }) {
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

  const scanner = friendlyToolName(finding.source_tool[0]);
  const firstLine = finding.affected_lines?.[0];
  const fileLabel = firstLine
    ? `${firstLine.file}:L${firstLine.start}`
    : finding.affected_files?.[0] ?? null;

  return (
    <div className="mt-2 flex flex-wrap items-baseline gap-x-3 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
      <span className="text-ink-400">└─</span>
      <span>
        from{" "}
        <span className="text-bone-mute">{scanner}</span>
        {ruleId && (
          <>
            <span className="text-ink-400">:</span>
            <span className="text-bone-mute normal-case tracking-normal">
              {ruleId}
            </span>
          </>
        )}
      </span>
      {fileLabel && (
        <>
          <span className="text-ink-400">·</span>
          <span className="text-bone-mute normal-case tracking-normal">
            {fileLabel}
          </span>
        </>
      )}
      <a
        href={`#provenance-${finding.id}`}
        className="ml-auto text-bone-mute transition-colors hover:text-signal-live"
        title="open the full grounding trace below"
      >
        ¶ trace
      </a>
    </div>
  );
}

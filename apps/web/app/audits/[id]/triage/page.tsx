import Link from "next/link";
import { CaseHeader } from "@/components/case-header";
import { ApiError, listClusters, type Cluster } from "@/lib/api";
import { SeverityChip } from "@/components/severity-chip";
import { loadAudit } from "@/lib/server";
import { notFound } from "next/navigation";
import { tabs } from "../../tabs";

/**
 * Triage view. The product's answer to "where do I spend my next hour."
 *
 * Renders findings collapsed into clusters by `(category, cwe, rule_signature)`
 * so a single underlying pattern (one helper that needs a fix) shows once with
 * an instance count, instead of N rows. Sorted by severity, then instance
 * count — the loud Critical wins over the quiet High no matter how many
 * callsites the High touches.
 *
 * The LLM "fix this week" priority list lands here next.
 */
export default async function TriagePage({
  params,
  searchParams,
}: {
  params: { id: string };
  searchParams?: { include_unreachable?: string };
}) {
  const includeUnreachable = searchParams?.include_unreachable === "true";
  const audit = await loadAudit(params.id);
  let data;
  try {
    data = await listClusters(params.id, { includeUnreachable });
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }

  const priorityList = audit.profile?.priority_list ?? [];
  const clusterByKey = new Map(data.items.map((c) => [c.key, c]));
  const priorityClusters = priorityList
    .map((p) => ({ p, c: clusterByKey.get(p.cluster_key) }))
    .filter((x): x is { p: { cluster_key: string; reason: string }; c: Cluster } => !!x.c);

  return (
    <>
      <CaseHeader
        caseNo={audit.id.toUpperCase().slice(0, 12)}
        source={audit.source_ref}
        generatedAt={audit.finished_at ?? "—"}
        tabs={tabs(params.id, "triage")}
      />

      {priorityClusters.length > 0 && (
        <section className="mb-10">
          <div className="mb-2 flex items-baseline justify-between">
            <span className="term-label">fix.this_week() · ranked</span>
            <span className="font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
              top {priorityClusters.length}
            </span>
          </div>
          <p className="mb-3 font-mono text-[11px] text-bone-mute leading-[1.6]">
            <span className="text-bone-ghost">{"//"} </span>
            ranked by the auditor combining severity, kev status, instance count, and category
            spread. spend your hour here first.
          </p>
          <ol className="panel pt-4">
            <span className="panel-title">priority_queue</span>
            {priorityClusters.map((item, i) => (
              <li
                key={item.p.cluster_key}
                className="grid grid-cols-[60px_1fr_100px] items-start gap-3 border-b border-ink-300 px-4 py-3 last:border-b-0"
              >
                <span className="pt-1 font-mono text-[13px] text-signal-live tabular">
                  #{(i + 1).toString().padStart(2, "0")}
                </span>
                <div className="min-w-0">
                  <Link
                    href={`/audits/${params.id}/findings/${item.c.representative_id}`}
                    className="group block"
                  >
                    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                      <SeverityChip severity={item.c.severity} size="sm" />
                      <span className="font-mono text-[14px] text-bone group-hover:text-signal-live">
                        {item.c.title}
                      </span>
                      {item.c.kev && (
                        <span className="font-mono text-[9px] uppercase tracking-widest2 text-signal-critical">
                          [ KEV ]
                        </span>
                      )}
                      {item.c.instances > 1 && (
                        <span className="font-mono text-[10px] text-bone-mute">
                          ×{item.c.instances} callsites
                        </span>
                      )}
                    </div>
                    <p className="mt-2 font-mono text-[12px] leading-[1.6] text-bone-dim">
                      <span className="text-bone-ghost">{"//"} </span>
                      {item.p.reason}
                    </p>
                  </Link>
                </div>
                <div className="pt-1 text-right font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
                  {item.c.category}
                </div>
              </li>
            ))}
          </ol>
        </section>
      )}

      <section className="mb-6">
        <div className="mb-2 flex items-baseline justify-between">
          <span className="term-label">cluster.ledger</span>
          <span className="font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
            {data.total_clusters} clusters · {data.total_findings} findings
          </span>
        </div>
        <p className="font-mono text-[11px] text-bone-mute leading-[1.6]">
          <span className="text-bone-ghost">{"//"} </span>
          findings collapsed by <span className="text-bone">(category, cwe, rule)</span> — one row
          per <em className="not-italic text-bone">underlying pattern</em>, not per callsite.
          fix the cluster, the instances follow.
        </p>
      </section>

      <div className="border border-ink-300 bg-ink-50">
        <div className="grid grid-cols-[100px_1fr_80px_120px_120px] gap-3 border-b border-ink-300 px-4 py-2 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
          <span>offset</span>
          <span>cluster</span>
          <span className="text-right">×N</span>
          <span className="text-right">scope</span>
          <span className="text-right">flags</span>
        </div>

        {data.items.map((c, i) => (
          <ClusterRow key={c.key} cluster={c} index={i} auditId={params.id} />
        ))}

        {data.items.length === 0 && (
          <div className="px-4 py-8 text-center font-mono text-[12px] text-bone-mute">
            <span className="text-bone-ghost">{"//"}</span> no clusters to triage. either the audit
            found nothing, or every finding was filtered as unreachable. try{" "}
            <Link
              href={`/audits/${params.id}/triage?include_unreachable=true`}
              className="text-bone hover:text-signal-live"
            >
              $ include unreachable
            </Link>
            .
          </div>
        )}
      </div>

      <div className="mt-6 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
        {includeUnreachable ? (
          <Link href={`/audits/${params.id}/triage`} className="text-bone-mute hover:text-bone">
            $ hide unreachable
          </Link>
        ) : (
          <Link
            href={`/audits/${params.id}/triage?include_unreachable=true`}
            className="text-bone-mute hover:text-bone"
          >
            $ include unreachable clusters
          </Link>
        )}
      </div>
    </>
  );
}

function ClusterRow({
  cluster,
  index,
  auditId,
}: {
  cluster: Cluster;
  index: number;
  auditId: string;
}) {
  return (
    <Link
      href={`/audits/${auditId}/findings/${cluster.representative_id}`}
      className="group grid grid-cols-[100px_1fr_80px_120px_120px] items-start gap-3 border-b border-ink-300 px-4 py-3 last:border-b-0 hover:bg-ink-100"
    >
      <span className="pt-1 font-mono text-[11px] text-ink-400 tabular">
        0x{(index * 0x40).toString(16).padStart(8, "0")}
      </span>

      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <SeverityChip severity={cluster.severity} size="sm" />
          <h3 className="font-mono text-[14px] text-bone group-hover:text-signal-live">
            {cluster.title}
          </h3>
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-bone-mute">
          <span className="text-bone-ghost uppercase tracking-widest2">{cluster.category}</span>
          {cluster.cwe && <span>· {cluster.cwe}</span>}
          {cluster.cves.length > 0 && (
            <span className="text-signal-high">· {cluster.cves.slice(0, 3).join(", ")}</span>
          )}
          {cluster.cves.length > 3 && (
            <span className="text-ink-400">+{cluster.cves.length - 3}</span>
          )}
        </div>
        <div className="mt-1 font-mono text-[11px] text-bone-ghost">
          {cluster.files.slice(0, 3).map((f, i) => (
            <span key={i}>
              {i ? <span className="text-ink-400"> · </span> : null}
              {f}
            </span>
          ))}
          {cluster.files.length > 3 && (
            <span className="text-ink-400"> · +{cluster.files.length - 3} more</span>
          )}
        </div>
        {cluster.hint && (cluster.hint.shared_dir || cluster.hint.shared_modules.length > 0) && (
          <div className="mt-2 border-l-2 border-signal-live bg-ink-50 px-3 py-1.5 font-mono text-[11px] text-bone-mute">
            <span className="text-signal-live">fix_the_helper:</span>{" "}
            {cluster.hint.shared_modules.length > 0 && (
              <>
                shared import{cluster.hint.shared_modules.length === 1 ? "" : "s"}{" "}
                {cluster.hint.shared_modules.slice(0, 3).map((m, i) => (
                  <span key={i}>
                    {i ? ", " : ""}
                    <span className="text-bone">{m}</span>
                  </span>
                ))}
                {cluster.hint.shared_dir && <span className="text-bone-ghost"> · </span>}
              </>
            )}
            {cluster.hint.shared_dir && (
              <>
                common dir <span className="text-bone">{cluster.hint.shared_dir}</span>
              </>
            )}
          </div>
        )}
      </div>

      <div className="pt-1 text-right font-mono text-[14px] text-bone tabular">
        ×{cluster.instances}
      </div>

      <div className="pt-1 text-right font-mono text-[11px] text-bone-mute">
        {cluster.files.length} file{cluster.files.length === 1 ? "" : "s"}
      </div>

      <div className="flex flex-wrap justify-end gap-x-2 gap-y-1 pt-1 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
        {cluster.kev && <span className="text-signal-critical">[KEV]</span>}
        {cluster.all_unreachable && <span>[unreach]</span>}
        {cluster.any_unreachable && !cluster.all_unreachable && (
          <span title="some instances unreachable" className="text-bone-mute">[partial]</span>
        )}
      </div>
    </Link>
  );
}

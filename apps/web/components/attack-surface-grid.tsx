import Link from "next/link";
import clsx from "clsx";
import type { Finding, Severity } from "@/lib/types";

type Pillar = {
  key: string;
  label: string;
  addr: string;
  match: (f: Finding) => boolean;
};

const PILLARS: Pillar[] = [
  { key: "secrets",   label: "exposed_secrets",          addr: "0x0010", match: (f) => f.category === "Secret Exposure" },
  { key: "auth",      label: "auth_session",             addr: "0x0020", match: (f) => /Authentication|JWT|Session|Cryptography/i.test(f.category) },
  { key: "api",       label: "injection_api",            addr: "0x0030", match: (f) => /Injection|Cross-Site|SSRF|Path Traversal|Open Redirect|CSRF/i.test(f.category) },
  { key: "deps",      label: "dependency_exposure",      addr: "0x0040", match: (f) => /Vulnerable Dependency/i.test(f.category) },
  { key: "infra",     label: "infra_iac",                addr: "0x0050", match: (f) => /Infrastructure|IaC|Misconfiguration/i.test(f.category) },
  { key: "logging",   label: "logging_monitoring",       addr: "0x0060", match: (f) => /Logging|Monitoring|Smell/i.test(f.category) },
];

const SEV_ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Informational"];

export function AttackSurfaceGrid({ findings, auditId }: { findings: Finding[]; auditId: string }) {
  const groups = PILLARS.map((p) => {
    const items = findings.filter(p.match);
    const top = items.slice().sort(
      (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
    )[0];
    return { p, items, top };
  });
  const max = Math.max(1, ...groups.map(({ items }) => items.length));

  return (
    <ol className="grid grid-cols-1 border border-ink-300 md:grid-cols-2 lg:grid-cols-3">
      {groups.map(({ p, items, top }, i) => {
        const bar = Math.round((items.length / max) * 24);
        return (
          <li
            key={p.key}
            className={clsx(
              "relative border-b border-r border-ink-300 px-5 py-5",
              "lg:[&:nth-child(3n)]:border-r-0",
              "md:[&:nth-child(2n)]:border-r-0 lg:[&:nth-child(2n)]:border-r",
              items.length === 0 && "opacity-60"
            )}
          >
            <div className="flex items-baseline justify-between font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
              <span>
                <span className="text-ink-400">{p.addr}</span>{" "}
                {p.label}
              </span>
              <span className="text-ink-400 tabular">i={String(i).padStart(2, "0")}</span>
            </div>

            <div className="mt-4 flex items-baseline justify-between">
              <span className="font-display text-[44px] leading-[0.95] tabular text-bone">
                {String(items.length).padStart(2, "0")}
              </span>
              <span className="font-mono text-[12px] tabular text-signal-live">
                [{"█".repeat(bar)}{"·".repeat(Math.max(0, 24 - bar))}]
              </span>
            </div>

            {top ? (
              <Link
                href={`/audits/${auditId}/findings/${top.id}`}
                className="mt-5 block border-t border-ink-300 pt-3 font-mono text-[12px] hover:bg-ink-100"
              >
                <div className="text-[10px] uppercase tracking-widest2 text-bone-ghost">top entry ⟶</div>
                <div className="mt-1 text-bone group-hover:underline">{top.title}</div>
                <div className="mt-1 text-[10px] uppercase tracking-widest2 text-bone-mute">
                  {top.severity} · {top.source_tool.join(" · ")}
                </div>
              </Link>
            ) : (
              <p className="mt-5 border-t border-ink-300 pt-3 font-mono text-[12px] text-bone-mute">
                <span className="text-bone-ghost">{"//"}</span> no findings in this pillar
              </p>
            )}

            {items.length > 1 && (
              <ul className="mt-3 space-y-1 font-mono text-[11px] text-bone-ghost">
                {items.slice(1, 4).map((f) => (
                  <li key={f.id}>
                    <Link href={`/audits/${auditId}/findings/${f.id}`} className="hover:text-bone-dim">
                      <span className="text-ink-400">→ </span>{f.title}
                    </Link>
                  </li>
                ))}
                {items.length > 4 && (
                  <li className="text-ink-400">+ {items.length - 4} more</li>
                )}
              </ul>
            )}
          </li>
        );
      })}
    </ol>
  );
}

import Link from "next/link";
import { SubmissionForm } from "@/components/submission-form";
import { TrySample } from "@/components/try-sample";
import { DEMO_SCAN_URL } from "@/lib/server";

/* Hand-cut banner — renders the platform mark in a chunky figlet style. */
const BANNER = `\
   ▄████████  ▄█     ▄███████▄    ▄█    █▄       ▄████████    ▄████████
  ███    ███ ███    ███    ███   ███    ███     ███    ███   ███    ███
  ███        ███▌   ███    ███   ███    ███     ███    █▀    ███    ███
  ███        ███▌   ███    ███  ▄███▄▄▄▄███▄▄  ▄███▄▄▄      ▄███▄▄▄▄██▀
  ███        ███▌ ▀█████████▀  ▀▀███▀▀▀▀███▀  ▀▀███▀▀▀     ▀▀███▀▀▀▀▀
  ███    █▄  ███    ███          ███    ███     ███    █▄  ▀███████████
  ███    ███ ███    ███          ███    ███     ███    ███   ███    ███
  ████████▀  █▀    ▄████▀        ███    █▀      ██████████   ███    ███
                                                             ███    ███`;

export default function Landing() {
  return (
    <div className="relative">
      <pre aria-hidden className="ascii-rule mb-4">{"─".repeat(220)}</pre>
      <div className="grid grid-cols-12 items-end gap-x-6 gap-y-2 pb-6">
        <div className="col-span-12 md:col-span-6">
          <div className="term-label">offset 0x00000000 · masthead</div>
        </div>
        <div className="col-span-12 flex flex-wrap items-baseline gap-x-6 gap-y-1 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost md:col-span-6 md:justify-end">
          <span>build 2026.05.15</span>
          <span className="text-ink-400">·</span>
          <span>rev <span className="text-bone-mute">9f3c1d8</span></span>
          <span className="text-ink-400">·</span>
          <span>sig <span className="text-signal-live">ok</span></span>
        </div>
      </div>

      <section className="overflow-hidden border-y border-ink-300 py-8">
        <pre aria-hidden className="text-[clamp(8px,1vw,11px)] leading-[1.05] text-bone-dim">
{BANNER}
        </pre>
        <div className="mt-6 grid grid-cols-12 gap-x-6 gap-y-3">
          <h1 className="col-span-12 font-display text-[clamp(34px,5vw,68px)] leading-[1.02] tracking-tight md:col-span-9">
            <span className="text-bone">audit the surface,</span>{" "}
            <span className="italic text-signal-live">never the keys</span>
            <span className="ml-1 align-top font-mono text-[12px] tracking-widest2 text-ink-400">¹</span>
          </h1>
          <aside className="col-span-12 self-end md:col-span-3 md:text-right">
            <p className="font-mono text-[11px] leading-snug text-bone-mute">
              <span className="text-bone-ghost">{"//"}</span> evidence-first static analysis.<br />
              redactions on read, sanity-check on write.
            </p>
          </aside>
        </div>
      </section>

      <section className="grid grid-cols-12 gap-x-8 pt-12">
        <div className="col-span-12 md:col-span-5">
          <div className="term-label">§0x01 ─ intake</div>
          <h2 className="mt-3 font-display text-[36px] leading-[1.05] tracking-tight">
            <span className="text-bone">open a</span>{" "}
            <span className="text-signal-live">case_t</span>
            <span className="text-bone-ghost">{"{}"}</span>
          </h2>
          <p className="mt-5 max-w-[42ch] font-mono text-[13px] leading-snug text-bone-dim">
            <span className="text-bone-ghost">{"//"}</span> submit a public github repo or upload a zip.
            the worker provisions a per-job sandbox and runs semgrep · trivy · gitleaks, then
            correlates output into a normalized ledger of findings.
          </p>

          <pre className="mt-8 overflow-x-auto border border-ink-300 bg-ink-50 px-4 py-3 text-[11px] leading-[20px] text-bone-mute">
{`struct sandbox_t {
    net      = none;
    rootfs   = read_only;
    caps     = drop_all;
    uid      = nobody;
    pids     = 512;
    ttl      = 600s;
};`}
          </pre>
        </div>

        <div className="col-span-12 mt-10 md:col-span-7 md:mt-0">
          <SubmissionForm />
          <div className="mt-4">
            <TrySample url={DEMO_SCAN_URL} />
          </div>
          <div className="mt-3 flex items-center justify-end">
            <Link
              href="/audits/demo"
              className="group inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-widest2 text-bone-mute transition-colors hover:text-signal-live"
            >
              <span aria-hidden className="text-ink-400">→</span>
              inspect_design_fixture()
            </Link>
          </div>
        </div>
      </section>

      <section className="mt-20 border-y border-ink-300 py-12">
        <div className="grid grid-cols-12 gap-x-8 gap-y-6">
          <div className="col-span-12 md:col-span-4">
            <div className="term-label">§0x02 ─ pipeline</div>
            <h2 className="mt-3 font-display text-[32px] italic leading-[1.05] tracking-tight">
              determinism,<br />
              <span className="not-italic text-bone-mute">then</span> reasoning.
            </h2>
            <p className="mt-5 max-w-[40ch] font-mono text-[12px] leading-snug text-bone-mute">
              <span className="text-bone-ghost">{"//"}</span> the llm describes findings the
              scanners already identified. it does not invent. every output passes a safety
              validator before persistence.
            </p>
          </div>
          <ol className="col-span-12 grid grid-cols-1 gap-0 md:col-span-8 md:grid-cols-2">
            {METHOD.map((m, i) => (
              <li key={m.title} className="border-l border-t border-ink-300 px-5 py-5 md:[&:nth-child(odd)]:border-r">
                <div className="flex items-baseline gap-3 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost tabular">
                  <span className="text-ink-400">{m.addr}</span>
                  <span>step {String(i + 1).padStart(2, "0")}</span>
                </div>
                <div className="mt-2 font-display text-[18px] leading-tight text-bone">{m.title}</div>
                <p className="mt-2 font-mono text-[12px] leading-snug text-bone-mute">{m.body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="mt-16 grid grid-cols-12 gap-x-8">
        <div className="col-span-12 md:col-span-4">
          <div className="term-label">§0x03 ─ constraints</div>
          <h2 className="mt-3 font-display text-[30px] leading-[1.05] tracking-tight">
            <span className="text-bone">what it will</span>{" "}
            <span className="italic text-signal-critical">not</span>{" "}
            <span className="text-bone">do.</span>
          </h2>
          <p className="mt-5 max-w-[36ch] font-mono text-[12px] leading-snug text-bone-mute">
            <span className="text-bone-ghost">{"//"}</span> hard rules. enforced by the system
            prompt, by an output validator, and by the schema itself.
          </p>
        </div>
        <ul className="col-span-12 mt-8 grid grid-cols-1 md:col-span-8 md:mt-2 md:grid-cols-2 md:gap-x-10">
          {NEVER.map((line, i) => (
            <li key={line} className="flex items-baseline gap-3 border-t border-ink-300 py-3 font-mono text-[13px] leading-snug text-bone-dim">
              <span aria-hidden className="text-signal-critical">✕</span>
              <span className="text-ink-400 tabular">0x{(0x10 + i * 0x10).toString(16).padStart(4, "0")}</span>
              <span>{line}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

const METHOD = [
  { addr: "0x10", title: "sandboxed scan",      body: "per-job container · net off during scan · read-only rootfs · dropped caps · non-root uid · bounded cpu/mem/pids" },
  { addr: "0x20", title: "normalize & redact",  body: "three scanners, one schema. secrets are masked before storage and before any prompt reaches the llm." },
  { addr: "0x30", title: "reason & cite",       body: "findings are enriched with explanation, business impact, and high-level defensive guidance — grounded in scanner evidence only." },
  { addr: "0x40", title: "validate output",     body: "every llm string is filtered. payloads, diffs, and step-by-step reproduction are rejected before they reach the report." },
];

const NEVER = [
  "generate exploit payloads or proof-of-concept code.",
  "produce step-by-step attack reproduction.",
  "emit exact code patches or auto-fix pull requests.",
  "provide operational remediation playbooks.",
  "invent vulnerabilities absent from scanner evidence.",
  "send raw secrets to the language model.",
];

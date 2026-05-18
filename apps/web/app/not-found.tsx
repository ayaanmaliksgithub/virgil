import Link from "next/link";

export default function NotFound() {
  return (
    <div className="grid min-h-[60vh] place-content-center text-center">
      <div className="term-label">EXIT 0x194 · case not on file</div>
      <pre aria-hidden className="mt-6 text-[10px] leading-tight text-ink-400">
{`┌─────────────────────────────┐
│  SIGSEGV: segment not found │
└─────────────────────────────┘`}
      </pre>
      <h1 className="mt-4 font-display text-[clamp(60px,10vw,140px)] leading-[0.9] tracking-tight">
        <span className="text-bone">404</span>{" "}
        <span className="italic text-signal-critical">not_found</span>
      </h1>
      <p className="mt-5 font-mono text-[13px] text-bone-mute">
        <span className="text-bone-ghost">{"//"}</span> the reference you followed does not match any open audit case.
      </p>
      <Link
        href="/"
        className="mt-8 inline-flex items-center justify-center gap-3 border border-signal-live px-6 py-3 font-mono text-[11px] uppercase tracking-widest2 text-signal-live hover:bg-signal-live hover:text-ink"
      >
        $ cd /
      </Link>
    </div>
  );
}

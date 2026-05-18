import Link from "next/link";

/**
 * Top-level chrome. Header is a terminal status bar: PID-style identifier,
 * mode flags, route segments rendered as a path. Footer keeps the platform's
 * non-exploit positioning permanently in view.
 */
export function SiteFrame({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative z-10 mx-auto flex min-h-dvh max-w-[1440px] flex-col px-6 lg:px-10">
      <Header />
      <main className="relative flex-1 pb-24 pt-6">{children}</main>
      <Footer />
    </div>
  );
}

function Header() {
  return (
    <header className="relative border-b border-ink-300">
      <div className="flex h-[28px] items-center justify-between gap-6 border-b border-ink-300 px-1 text-bone-ghost">
        <div className="flex items-center gap-3 font-mono text-[10px] uppercase tracking-widest2">
          <span className="text-signal-live">●</span>
          <span>tty/0</span>
          <span className="text-ink-400">·</span>
          <span>pid 0x{Math.floor(Math.random() * 0xffff).toString(16).padStart(4, "0")}</span>
          <span className="text-ink-400">·</span>
          <span>uid=audit gid=audit</span>
        </div>
        <div className="hidden items-center gap-3 font-mono text-[10px] uppercase tracking-widest2 md:flex">
          <Flag label="mode" value="audit-only" />
          <Flag label="exec" value="off" />
          <Flag label="net.scan" value="none" />
          <Flag label="exfil" value="blocked" />
        </div>
      </div>

      <div className="flex flex-wrap items-end justify-between gap-6 px-1 py-5">
        <Link href="/" className="group block">
          <pre aria-hidden className="text-[10px] leading-[12px] text-ink-400 select-none">
{`┌───────────────────────────────────────────┐`}
          </pre>
          <div className="font-display text-[28px] leading-none tracking-tight">
            <span className="text-bone-mute">$</span>{" "}
            <span className="text-bone">cipher_audit</span>
            <span className="text-bone-ghost">::v0.1</span>
            <span className="ml-1 text-signal-live term-cursor" />
          </div>
          <pre aria-hidden className="text-[10px] leading-[12px] text-ink-400 select-none">
{`└─ static analysis · risk register · no exploit output ─┘`}
          </pre>
        </Link>
        <nav className="flex flex-wrap items-center gap-x-5 gap-y-2">
          <NavLink href="/" code="0x00">submit</NavLink>
          <NavLink href="/audits/demo" code="0x01">console</NavLink>
          <NavLink href="/audits/demo/findings" code="0x02">findings</NavLink>
          <NavLink href="/audits/demo/attack-surface" code="0x03">surface</NavLink>
          <NavLink href="/audits/demo/report" code="0x04">report</NavLink>
        </nav>
      </div>
    </header>
  );
}

function Flag({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex items-baseline gap-[6px]">
      <span className="text-bone-ghost">{label}=</span>
      <span className="text-bone-dim">{value}</span>
    </span>
  );
}

function NavLink({ href, code, children }: { href: string; code: string; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      className="group inline-flex items-baseline gap-2 font-mono text-[11px] uppercase tracking-widest2 text-bone-mute transition-colors hover:text-bone"
    >
      <span className="text-ink-400 group-hover:text-signal-live tabular">{code}</span>
      <span>{children}</span>
    </Link>
  );
}

function Footer() {
  return (
    <footer className="mt-10 border-t border-ink-300 py-6">
      <pre aria-hidden className="ascii-rule">
        {"━".repeat(220)}
      </pre>
      <div className="mt-4 grid grid-cols-1 gap-6 md:grid-cols-3">
        <div>
          <div className="term-label">scope</div>
          <p className="mt-2 font-mono text-[12px] leading-snug text-bone-dim">
            cipher_audit identifies risk in source you control.{" "}
            <span className="text-signal-critical">not an exploit toolkit</span>. no payloads, no PoCs, no step-by-step reproduction, no exact patches.
          </p>
        </div>
        <div>
          <div className="term-label">method</div>
          <p className="mt-2 font-mono text-[12px] leading-snug text-bone-dim">
            deterministic scanners (semgrep · trivy · gitleaks) run sandboxed.
            llm reasoning operates over normalized,{" "}
            <span className="text-bone">redacted</span> findings only — never invents vulnerabilities.
          </p>
        </div>
        <div className="md:text-right">
          <div className="term-label">refs</div>
          <p className="mt-2 font-mono text-[11px] leading-snug text-bone-mute">
            OWASP_TOP_10/2021<br />
            MITRE_CWE/4.14<br />
            NVD_CVE
          </p>
        </div>
      </div>
      <div className="mt-6 flex items-center justify-between font-mono text-[10px] uppercase tracking-widest2 text-bone-fog">
        <span>© cipher_audit · internal review build</span>
        <span>built for analysts · not attackers</span>
      </div>
    </footer>
  );
}

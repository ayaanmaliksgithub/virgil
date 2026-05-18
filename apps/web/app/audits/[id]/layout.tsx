/**
 * Layout wrapping every page under /audits/[id]. Renders a clearly-labeled
 * banner when the id is the `demo` design fixture, so a visitor never
 * mistakes the baked TS-fixture data for a real scan.
 *
 * The fixture exists for design review without a backend; the real demo
 * experience is the homepage's "run sample scan" button against OWASP
 * NodeGoat, which submits through the live pipeline.
 */
import Link from "next/link";

export default function AuditLayout({
  params,
  children,
}: {
  params: { id: string };
  children: React.ReactNode;
}) {
  const isDesignFixture = params.id === "demo";

  return (
    <>
      {isDesignFixture && (
        <div className="mb-6 border-2 border-signal-high bg-ink-50 px-4 py-3 font-mono text-[11px] leading-[1.6]">
          <div className="text-[10px] uppercase tracking-widest2 text-signal-high">
            ⚠ static design fixture — not a real scan
          </div>
          <p className="mt-1 text-bone-mute">
            <span className="text-bone-ghost">{"//"} </span>
            You're viewing baked sample data so the design renders without a backend.
            Numbers and findings are illustrative.{" "}
            <Link href="/" className="text-bone hover:text-signal-live">
              ← run a real scan from the homepage
            </Link>{" "}
            to see actual scanner output.
          </p>
        </div>
      )}
      {children}
    </>
  );
}

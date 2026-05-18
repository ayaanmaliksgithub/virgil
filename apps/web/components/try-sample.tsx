"use client";

/**
 * One-click "try a real scan" CTA on the landing page.
 *
 * Submits the configured demo target (default: OWASP NodeGoat) through the
 * same `/v1/audits/json` route a user submission goes through. Routes to
 * the live audit page so the user watches their own actual scan complete.
 *
 * Deliberately NOT a pre-baked seed: every finding the user ends up looking
 * at is real scanner output produced by the same pipeline their own repo
 * would run through.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import clsx from "clsx";
import { submitUrl } from "@/lib/api";

export function TrySample({ url }: { url: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Pretty label: trim the scheme so the button is readable.
  const display = url.replace(/^https?:\/\//, "");

  async function start() {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const audit = await submitUrl(url);
      router.push(`/audits/${audit.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "submission failed");
      setBusy(false);
    }
  }

  return (
    <div className="border border-ink-300 bg-ink-50">
      <div className="border-b border-ink-300 px-5 py-2 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
        try_a_real_scan() · canonical example
      </div>
      <div className="grid grid-cols-1 items-center gap-4 px-5 py-4 md:grid-cols-[1fr_auto]">
        <div className="min-w-0">
          <div className="font-mono text-[13px] text-bone">
            <span className="text-bone-ghost">target ⟶ </span>
            <span className="text-bone">{display}</span>
          </div>
          <p className="mt-2 max-w-[60ch] font-mono text-[11px] leading-snug text-bone-mute">
            <span className="text-bone-ghost">{"//"}</span> OWASP NodeGoat is a deliberately-vulnerable
            Node.js training app. Clicking submits it through the real pipeline — sandboxed scanners,
            normalization, triage layer. ~3–5 minutes on first run. Every finding you see is actual
            scanner output, not a baked fixture.
          </p>
        </div>
        <button
          type="button"
          onClick={start}
          disabled={busy}
          className={clsx(
            "inline-flex items-center gap-3 border px-6 py-3 font-mono text-[11px] uppercase tracking-widest2 transition-all",
            busy
              ? "border-ink-400 text-bone-mute"
              : "border-signal-live text-signal-live hover:bg-signal-live hover:text-ink"
          )}
        >
          <span aria-hidden className="text-[12px]">▶</span>
          {busy ? "submitting…" : "run sample scan"}
        </button>
      </div>
      {error && (
        <p className="border-t border-signal-critical bg-ink px-5 py-2 font-mono text-[11px] text-signal-critical">
          <span className="text-signal-critical/70">err:</span> {error}
        </p>
      )}
    </div>
  );
}

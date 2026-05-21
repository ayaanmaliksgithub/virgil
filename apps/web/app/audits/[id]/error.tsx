"use client";

import Link from "next/link";
import { useEffect } from "react";

/**
 * Audit-scope error boundary.
 *
 * Hit when the FastAPI backend is unreachable (ApiUnreachable) or when a
 * route handler explicitly throws on a 5xx. 404s use Next's `notFound()`
 * helper and render `app/not-found.tsx` instead.
 *
 * The visual intent is "stuck SSH connection" — diagnostic, calm, with a
 * retry that re-runs the page's data fetches.
 */
export default function AuditError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Surface to dev tools; production observability would ship this to a
    // collector. Never include the user's secrets — server errors are already
    // pre-redacted by the worker before they hit the wire.
    console.error("[audit-error]", error);
  }, [error]);

  const isOffline =
    error.name === "ApiUnreachable" ||
    /unreachable|fetch failed|ECONNREFUSED|network/i.test(error.message);

  return (
    <div className="mx-auto max-w-[78ch] py-12">
      <div className="term-label">EXIT 0x{(isOffline ? 0x6f : 0x05).toString(16)} · {isOffline ? "backend unreachable" : "internal error"}</div>

      <pre aria-hidden className="mt-6 text-[10px] leading-[1.2] text-ink-400">
{`┌──────────────────────────────────────────────────┐
│  ${isOffline ? "ECONNREFUSED  api.virgil:8000" : "EINTERNAL     audit route raised        "} │
└──────────────────────────────────────────────────┘`}
      </pre>

      <h1 className="mt-6 font-display text-[clamp(40px,6vw,80px)] leading-[0.95] tracking-tight">
        <span className="text-bone">{isOffline ? "can't reach" : "audit failed to"}</span>{" "}
        <span className="italic text-signal-critical">{isOffline ? "the backend" : "render"}</span>
      </h1>

      <p className="mt-5 font-mono text-[13px] leading-[1.7] text-bone-dim">
        <span className="text-bone-ghost">{"//"}</span>{" "}
        {isOffline
          ? "the api at /api/v1 did not respond. if you're running locally, check that the api service is up (docker compose ps), then retry."
          : "the page raised before rendering. error name and digest are logged in the console for triage."}
      </p>

      <dl className="mt-8 grid grid-cols-[120px_1fr] gap-x-6 gap-y-2 border border-ink-300 bg-ink-50 px-4 py-3 font-mono text-[12px]">
        <dt className="text-bone-ghost uppercase tracking-widest2 text-[10px]">name</dt>
        <dd className="text-bone-dim">{error.name || "Error"}</dd>
        <dt className="text-bone-ghost uppercase tracking-widest2 text-[10px]">message</dt>
        <dd className="text-bone-dim break-words">{error.message || "—"}</dd>
        {error.digest && (
          <>
            <dt className="text-bone-ghost uppercase tracking-widest2 text-[10px]">digest</dt>
            <dd className="text-bone-mute tabular">{error.digest}</dd>
          </>
        )}
      </dl>

      <div className="mt-8 flex flex-wrap gap-3">
        <button
          type="button"
          onClick={reset}
          className="inline-flex items-center gap-3 border border-signal-live px-5 py-2 font-mono text-[11px] uppercase tracking-widest2 text-signal-live hover:bg-signal-live hover:text-ink"
        >
          $ retry
        </button>
        <Link
          href="/audits/demo"
          className="inline-flex items-center gap-3 border border-ink-300 px-5 py-2 font-mono text-[11px] uppercase tracking-widest2 text-bone-mute hover:border-bone hover:text-bone"
        >
          → open demo case
        </Link>
        <Link
          href="/"
          className="inline-flex items-center gap-3 border border-ink-300 px-5 py-2 font-mono text-[11px] uppercase tracking-widest2 text-bone-mute hover:border-bone hover:text-bone"
        >
          $ cd /
        </Link>
      </div>
    </div>
  );
}

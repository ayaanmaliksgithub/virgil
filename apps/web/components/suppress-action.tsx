"use client";

/**
 * Inline suppress/unsuppress action for a finding (Phase 4 §17 #4 UI).
 *
 * Two surface states:
 *   - finding is NOT suppressed → renders `$ suppress…` link that opens a
 *     small inline form (reason + optional expiry) and POSTs to
 *     /v1/audits/:id/suppressions, then refreshes.
 *   - finding IS suppressed → renders the existing reason and a `$ unsuppress`
 *     action that DELETEs and refreshes.
 *
 * Demo mode (`auditId === "demo"`) short-circuits to a no-op so design review
 * doesn't depend on a live backend.
 */
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { createSuppression, deleteSuppression } from "@/lib/api";

export function SuppressAction({
  auditId,
  dedupeKey,
  suppressed,
  suppressionId,
  suppressionReason,
}: {
  auditId: string;
  dedupeKey: string | undefined;
  suppressed: boolean;
  suppressionId: string | null | undefined;
  suppressionReason: string | null | undefined;
}) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  if (!dedupeKey && !suppressed) {
    return null; // backend hasn't surfaced a dedupe_key; can't act.
  }

  if (suppressed) {
    return (
      <div className="border-l-2 border-bone-ghost bg-ink-50 px-4 py-3 font-mono text-[12px] text-bone-mute">
        <div className="mb-1 text-[10px] uppercase tracking-widest2 text-bone-ghost">
          [ suppressed ]
        </div>
        <p className="text-bone-dim">{suppressionReason || "no reason recorded"}</p>
        <button
          type="button"
          disabled={pending || !suppressionId}
          onClick={() => {
            if (!suppressionId) return;
            setError(null);
            start(async () => {
              try {
                await deleteSuppression(suppressionId);
                router.refresh();
              } catch (e) {
                setError((e as Error).message || "delete failed");
              }
            });
          }}
          className="mt-3 font-mono text-[10px] uppercase tracking-widest2 text-bone-mute hover:text-signal-critical disabled:opacity-40"
        >
          $ unsuppress
        </button>
        {error && <div className="mt-2 text-[11px] text-signal-critical">{error}</div>}
      </div>
    );
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="font-mono text-[11px] uppercase tracking-widest2 text-bone-mute hover:text-signal-live"
      >
        $ suppress…
      </button>
    );
  }

  return (
    <div className="border-l-2 border-signal-live bg-ink-50 px-4 py-3">
      <div className="mb-2 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
        suppress · reason required
      </div>
      <textarea
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="e.g. false positive — value is a fixture, not a real secret"
        rows={3}
        className="w-full border border-ink-300 bg-ink px-3 py-2 font-mono text-[12px] text-bone caret-signal-live outline-none placeholder:text-bone-fog"
      />
      <div className="mt-3 flex items-center gap-3">
        <button
          type="button"
          disabled={pending || !reason.trim() || !dedupeKey}
          onClick={() => {
            setError(null);
            start(async () => {
              try {
                await createSuppression(auditId, { dedupe_key: dedupeKey!, reason: reason.trim() });
                setOpen(false);
                setReason("");
                router.refresh();
              } catch (e) {
                setError((e as Error).message || "suppress failed");
              }
            });
          }}
          className="font-mono text-[10px] uppercase tracking-widest2 text-signal-live hover:text-bone disabled:opacity-40"
        >
          $ commit
        </button>
        <button
          type="button"
          disabled={pending}
          onClick={() => { setOpen(false); setReason(""); setError(null); }}
          className="font-mono text-[10px] uppercase tracking-widest2 text-bone-mute hover:text-bone"
        >
          $ abort
        </button>
        {pending && <span className="font-mono text-[10px] text-bone-ghost">…persisting</span>}
      </div>
      {error && <div className="mt-2 font-mono text-[11px] text-signal-critical">{error}</div>}
    </div>
  );
}

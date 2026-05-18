"use client";

import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { getQueueStatus, type QueueStatus } from "@/lib/api";

/**
 * Pre-scan placement panel.
 *
 * Renders when the audit is still in the queue (`state=pending`) or in the
 * very early "running" phases (`queued`/`cloning`) where the console stream
 * has nothing interesting to show yet. Once the backend reports `active=false`
 * the panel self-hides — the live console takes over from there.
 *
 * Polls `/v1/audits/:id/queue` on a 2.5 s cadence. Keeps the last good response
 * so a transient network error doesn't blank the UI mid-wait.
 */
const POLL_INTERVAL_MS = 2500;
const POLL_INTERVAL_MS_FAST = 1200;  // ramp up frequency once we know we're next

export function QueueBanner({
  auditId,
  initial,
}: {
  auditId: string;
  initial: QueueStatus;
}) {
  const [status, setStatus] = useState<QueueStatus>(initial);
  const [errored, setErrored] = useState(false);
  const cancelledRef = useRef(false);

  useEffect(() => {
    cancelledRef.current = false;

    async function tick() {
      if (cancelledRef.current) return;
      try {
        const next = await getQueueStatus(auditId);
        if (cancelledRef.current) return;
        setStatus(next);
        setErrored(false);
        if (!next.active) return;  // we're done — stop polling
        const delay = (next.position ?? 99) <= 1 ? POLL_INTERVAL_MS_FAST : POLL_INTERVAL_MS;
        setTimeout(tick, delay);
      } catch {
        if (cancelledRef.current) return;
        setErrored(true);
        setTimeout(tick, POLL_INTERVAL_MS * 2);
      }
    }
    if (initial.active) {
      const handle = setTimeout(tick, POLL_INTERVAL_MS);
      return () => { cancelledRef.current = true; clearTimeout(handle); };
    }
    return () => { cancelledRef.current = true; };
  }, [auditId, initial.active]);

  if (!status.active) return null;

  const ahead = status.ahead ?? 0;
  const inFlight = status.in_flight ?? 0;
  const position = status.position ?? 0;

  // Two distinct framings depending on what stage we're in:
  //   1. pending — we haven't been picked up yet. Show queue position prominently.
  //   2. running, phase=queued|cloning — we're up next or just started. Show
  //      the early phase message so the user knows the worker has them now.
  const isPending = status.state === "pending";
  const headline = isPending
    ? (position <= 1 ? "you're next" : `position ${position} in queue`)
    : (status.phase === "queued" ? "spinning up" : "cloning repository");

  // Progress bar shows "how close to the front" — only meaningful when pending.
  // We cap the visualization at 10 audits ahead so a long backlog doesn't read
  // as a flat 0%.
  const total = Math.max(1, Math.min(10, ahead + 1));
  const filled = Math.max(0, total - ahead);
  const bar = Array.from({ length: total }, (_, i) => i < filled);

  return (
    <div className="mb-6">
      <div className="mb-2 flex items-baseline justify-between">
        <span className="term-label">submission.queue</span>
        <span className="font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
          state=<span className="text-bone-mute">{status.state}</span>
          {" · "}phase=<span className="text-bone-mute">{status.phase}</span>
          {errored && (
            <>
              {" · "}
              <span className="text-signal-critical">poll · retrying</span>
            </>
          )}
        </span>
      </div>

      <div className="panel pt-4">
        <span className="panel-title">queue · waiting room</span>

        <div className="grid grid-cols-[auto_1fr] items-baseline gap-5 px-5 py-4">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
              status
            </div>
            <div className={clsx(
              "mt-1 font-mono text-[18px] tracking-tight",
              isPending ? "text-bone" : "text-signal-live"
            )}>
              {headline}
            </div>
          </div>

          {isPending ? (
            <div className="font-mono text-[12px] leading-[1.7] text-bone-mute">
              <div>
                <span className="text-bone-ghost">{"//"}</span>{" "}
                <span className="text-bone-dim">{ahead}</span>{" "}
                <span className="text-bone-ghost">audit(s) ahead</span>{" "}
                <span className="text-bone-ghost">·</span>{" "}
                <span className="text-bone-dim">{inFlight}</span>{" "}
                <span className="text-bone-ghost">running now</span>
              </div>
              <div className="mt-3 flex items-center gap-[2px]">
                {bar.map((on, i) => (
                  <span
                    key={i}
                    className={clsx(
                      "h-3 w-4",
                      on ? "bg-signal-live" : "bg-ink-300"
                    )}
                  />
                ))}
                <span className="ml-3 text-bone-ghost">
                  [{filled.toString().padStart(2, "0")}/{total.toString().padStart(2, "0")}]
                </span>
              </div>
              <div className="mt-3 text-bone-fog">
                We don&apos;t estimate wait time — runtime varies wildly with repo
                size and scanner load. The console stream below will start the
                moment your job is picked up.
              </div>
            </div>
          ) : (
            <div className="font-mono text-[12px] leading-[1.7] text-bone-mute">
              <span className="text-bone-ghost">{"//"}</span>{" "}
              <span className="text-bone-dim">
                {status.phase === "cloning"
                  ? "the worker has your repo. scanner sandbox warms up after the clone completes."
                  : "your job was picked up. the worker is provisioning the sandbox container."}
              </span>
              <span className="term-cursor ml-2" />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

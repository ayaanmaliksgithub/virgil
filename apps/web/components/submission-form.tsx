"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import clsx from "clsx";
import { submitUrl, submitZip } from "@/lib/api";

type Mode = "url" | "zip";

export function SubmissionForm() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("url");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const audit = mode === "url"
        ? await submitUrl(url.trim())
        : file ? await submitZip(file) : Promise.reject(new Error("Select a .zip"));
      const a = await audit;
      router.push(`/audits/${a.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "submission failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="panel pt-4">
      <span className="panel-title">stdin</span>

      <div className="grid grid-cols-2 border-b border-ink-300">
        <ModeTab active={mode === "url"} onClick={() => setMode("url")} code="0x01">
          repo_url
        </ModeTab>
        <ModeTab active={mode === "zip"} onClick={() => setMode("zip")} code="0x02">
          zip_blob
        </ModeTab>
      </div>

      <div className="px-5 py-5">
        {mode === "url" ? (
          <label className="block">
            <div className="term-label">target.scheme</div>
            <div className="mt-3 flex items-baseline gap-3 border-b border-ink-400 pb-2">
              <span className="font-mono text-[12px] tracking-widest2 text-bone-ghost">https://</span>
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="github.com/owasp/nodegoat"
                spellCheck={false}
                className="w-full bg-transparent font-mono text-[15px] text-bone caret-signal-live outline-none placeholder:text-bone-fog"
                autoFocus
              />
            </div>
            <p className="mt-3 font-mono text-[11px] leading-snug text-bone-mute">
              <span className="text-bone-ghost">{"//"}</span> public repos only. clone runs in
              isolated sandbox; scan phase is <span className="text-signal-live">--network=none</span>.
            </p>
          </label>
        ) : (
          <ZipField file={file} setFile={setFile} />
        )}
      </div>

      <div className="flex items-center justify-between gap-6 border-t border-ink-300 px-5 py-4">
        <p className="max-w-[42ch] font-mono text-[11px] leading-snug text-bone-mute">
          <span className="text-bone-ghost">{"//"}</span> submission authorizes deterministic
          scanners against the target. host execution is never permitted.
        </p>
        <button
          type="submit"
          disabled={busy}
          className={clsx(
            "group relative inline-flex items-center gap-3 border px-6 py-3 font-mono text-[11px] uppercase tracking-widest2 transition-all",
            busy
              ? "border-ink-400 text-bone-mute"
              : "border-signal-live text-signal-live hover:bg-signal-live hover:text-ink"
          )}
        >
          <span aria-hidden className="text-[12px]">&gt;&gt;</span>
          {busy ? "filing case…" : "exec audit"}
        </button>
      </div>

      {error && (
        <p className="border-t border-signal-critical bg-ink-50 px-5 py-3 font-mono text-[11px] text-signal-critical">
          <span className="text-signal-critical/70">err:</span> {error}
        </p>
      )}
    </form>
  );
}

function ModeTab({
  active, onClick, children, code,
}: {
  active: boolean; onClick: () => void; children: React.ReactNode; code: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={clsx(
        "group flex items-baseline gap-3 px-5 py-3 text-left font-mono text-[11px] uppercase tracking-widest2 transition-colors first:border-r first:border-ink-300",
        active
          ? "bg-ink text-bone"
          : "text-bone-mute hover:text-bone"
      )}
    >
      <span className={clsx("tabular", active ? "text-signal-live" : "text-ink-400 group-hover:text-bone-ghost")}>{code}</span>
      {children}
    </button>
  );
}

function ZipField({
  file, setFile,
}: { file: File | null; setFile: (f: File | null) => void }) {
  const [dragOver, setDragOver] = useState(false);
  return (
    <label
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(e) => {
        e.preventDefault(); setDragOver(false);
        const f = e.dataTransfer.files?.[0]; if (f) setFile(f);
      }}
      className={clsx(
        "block cursor-pointer border border-dashed px-5 py-8 transition-colors",
        dragOver ? "border-signal-live bg-ink" : "border-ink-400"
      )}
    >
      <div className="term-label">archive.blob</div>
      <div className="mt-2 font-mono text-[14px] text-bone">
        {file
          ? <>{file.name} <span className="text-bone-ghost">({(file.size / 1024 / 1024).toFixed(1)} MB)</span></>
          : <>drop a <span className="text-signal-live">.zip</span> · or click to browse</>}
      </div>
      <p className="mt-3 font-mono text-[11px] text-bone-mute">
        <span className="text-bone-ghost">{"//"}</span> max 500 MB. path traversal, symlinks, and zip bombs are
        rejected before extraction.
      </p>
      <input
        type="file"
        accept=".zip,application/zip"
        className="hidden"
        onChange={(e) => setFile(e.target.files?.[0] ?? null)}
      />
    </label>
  );
}

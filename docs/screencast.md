# 90-second screencast — recording script + storyboard

> The README's hero block has a placeholder where the screencast embed
> should live. This file is the source-of-truth for *what* to record so
> a future contributor (or you, in three months) can reshoot when the
> UI changes without re-deciding what story to tell.

The screencast must do one thing: prove the product is real and works
end-to-end, in under 90 seconds, against a real codebase, with no
hand-waving.

If a viewer leaves with one impression, it should be:
**"Cloned a repo, watched real scanners run, got a triaged report."**

---

## Pre-record checklist

Run through this once before hitting record. Skipping any step shows in
the final cut.

- [ ] Fresh terminal at the repo root. Window styled with a readable
      monospace font; 14pt+ minimum so the recording legible at YouTube
      720p. Black background.
- [ ] Browser window at `http://localhost:3000`. Hard-refresh first so
      you're on the empty landing page. No DevTools open.
- [ ] `docker compose down -v` ahead of time so the stack is genuinely
      cold for the first compose-up. The first run is also the most
      honest run.
- [ ] If you want chat to work in the demo: set `ANTHROPIC_API_KEY` (or
      `OPENAI_API_KEY`) in `.env` *before* recording so the chat segment
      doesn't show the "configure a key" fallback.
- [ ] Pick a target repo. Default is OWASP NodeGoat (the homepage CTA
      submits it). Don't change this — it's the canonical example.
- [ ] Window arrangement: terminal on the LEFT half, browser on the
      RIGHT half. Both visible simultaneously so the viewer sees the
      stack come up while the UI populates.
- [ ] Record at 1920×1080. Final export H.264 MP4 < 25 MB so the file
      can be linked from a GitHub release asset; for in-README embed,
      upload to YouTube / Vimeo / Loom and link.

---

## Beats (target = 90s total)

### 0:00 → 0:08 · "What is this"

**On screen:** terminal showing a clean prompt. Title card (lower
third): "Virgil — self-hosted security audit. github.com/ayaanmaliksgithub/virgil"

**Voiceover (~15 words):**
> Virgil is a self-hosted security audit tool. Let me show you what it
> looks like.

### 0:08 → 0:18 · "One command to bring it up"

**On screen:**
```
git clone https://github.com/ayaanmaliksgithub/virgil
cd virgil
cp .env.example .env
docker compose up -d
```
(Type fast or use a pre-prepared screencast tool; do *not* sit through
the actual 3-minute build — cut to "stack ready" the moment compose
returns.)

**Voiceover (~22 words):**
> One command brings up the API, the worker, the web UI, and a Postgres
> Redis MinIO triple. Three minutes the first time, seconds after.

### 0:18 → 0:28 · "Empty UI on first visit, intentionally"

**On screen:** browser at `localhost:3000`. Camera pans to the
landing page. Show the "run sample scan" panel.

**Voiceover (~18 words):**
> The page is empty until you submit a target. The "run sample scan"
> button points at OWASP NodeGoat — a real vulnerable repo.

### 0:28 → 0:32 · "Click run"

**On screen:** click the button. Page navigates to `/audits/<id>`.
Phase timeline starts ticking.

**Voiceover (~10 words):**
> One click, real submission, real scanners spin up in the sandbox.

### 0:32 → 0:55 · "The live pipeline"

**On screen:** the audit console streams — cloning, analyzing,
scanning, correlating phases tick through. Console-stream component
populates as the worker emits SSE events.

This is the longest beat. The viewer needs to *see* real scanner
output — not synthetic, not pre-baked. Resist cutting it short.

**Voiceover (~38 words):**
> Semgrep, Trivy, and Gitleaks each run in their own sandbox container
> — read-only repo mount, network off, capabilities dropped, non-root
> UID. The normalize pass merges duplicates across scanners. Then the
> triage layer kicks in.

### 0:55 → 1:08 · "The triage view"

**On screen:** navigate to the *triage* tab. Show the priority queue
("fix.this_week" panel) and the cluster ledger underneath. Hover one
cluster row to show the fix-the-helper hint ("shared dir … shared
modules …").

**Voiceover (~25 words):**
> This is the priority queue. The auditor ranked these clusters by
> severity, KEV exposure, instance count, and reachability. Forty-seven
> SQL injections become one cluster — fix the helper, not the call sites.

### 1:08 → 1:18 · "Code-grounded chat"

**On screen:** open the chat tab. Click one of the suggested-question
buttons (e.g., "is this dep used?"). Watch the answer stream in,
citing specific finding IDs.

**Voiceover (~22 words):**
> Every answer is grounded in the stored findings and the redacted code
> we captured at scan time. No exploits, no patches, defensive guidance
> only.

### 1:18 → 1:25 · "Why did you flag this — the trace"

**On screen:** click one of the cited findings. Scroll past the prose
to the `why_we_flagged_this()` panel. Hover one of the inline `¶ trace`
links on an LLM-generated block to show the source artifact chain.

**Voiceover (~16 words):**
> Every LLM-surfaced line traces back to the scanner that produced it.
> No hallucinated findings.

### 1:25 → 1:30 · "Outro"

**On screen:** lower-third card with `github.com/ayaanmaliksgithub/virgil`,
the Apache 2.0 badge, "Open source · no telemetry · self-hosted".

**Voiceover (~10 words):**
> Apache 2.0, no telemetry, runs entirely on your machine.

---

## After the record

1. Trim to under 95 seconds — better short than complete.
2. Export as H.264 MP4, 1080p, with the system audio kept (the
   voiceover is the spine).
3. Upload to YouTube/Vimeo/Loom. Note the URL.
4. Open `README.md`, replace the placeholder comment under "Watch the
   90-second tour" with the embed/link.
5. Add a `docs/screencast-v0.1.url` text file with the URL pinned so
   future contributors can find the canonical version.

---

## Tooling notes

| Platform | Capture | Mic |
| --- | --- | --- |
| macOS    | QuickTime / ScreenFlow / Loom desktop / OBS | built-in is fine if room is quiet; AirPods mic is OK |
| Linux    | OBS Studio | any USB mic, plain `arecord` works for raw audio |
| Windows  | OBS Studio | any USB mic |

For the *typing* sequences, prefer a real keypress recording over
pasting — the viewer registers "this is happening live" subconsciously
when they see chars appear at a human speed. But don't be slow; you can
trim with the editor.

For the *3-minute compose build*, cut. Use a hard cut + a 0.2s fade.
No one needs to watch image layers download.

---

## Why this script and not a different one

Three rejected scripts and why:

1. **"Highlight reels" of every feature.** Tried; 90 seconds isn't
   enough to show clustering AND reachability AND compliance mapping
   AND chat AND SARIF AND priority list. Showing fewer features
   deeply beats listing all of them shallowly.
2. **Opening with the chat.** Tried; chat is the most distinctive
   feature but it presumes the viewer trusts the findings are real.
   Showing the live scan first earns that trust.
3. **No voiceover, captions only.** Tried; the visual UI is already
   information-dense (timeline + console + triage panel). Captions
   compete with the screen for attention. Voiceover narrates the
   stuff that isn't visible on screen (the "what's happening under the
   hood" bits).

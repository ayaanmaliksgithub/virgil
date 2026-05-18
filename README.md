# virgil

> An AI-assisted security **audit** platform for source code. Not an exploit
> tool, not an autopatcher. Reads your repo, runs real scanners in a
> sandbox, ranks the noise out, and explains what's left in the actual code.

```
$ virgil scan .
bundle /work/myrepo → zip → submit
┌─ [ virgil ] ────────────────────────────────────────────────────────────────┐
│ audit_id  c9b1…                                                            │
│ source    scan.zip                                                         │
│ state     succeeded  phase=completed                                       │
└────────────────────────────────────────────────────────────────────────────┘

 CRIT  HIGH  MED   LOW   INFO  KEV  unreach
   2     7    14    6     3     1     19

╭─ [ fix.this_week() · ranked ] ─────────────────────────────────────────────╮
│ // these are the clusters the auditor ranked for this week                 │
│                                                                            │
│ #01 [ CRIT ]  Hard-coded AWS access key in source  ×3                      │
│      Critical credential exposure with CISA-KEV-adjacent risk profile…     │
│                                                                            │
│ #02 [ HIGH ]  SQL injection via raw query helper  ×12                      │
│      12 callsites share src/db/query.py — fix the helper, not callsites.   │
│ …                                                                          │
╰────────────────────────────────────────────────────────────────────────────╯
```

## Why another security scanner

There are plenty of tools that hand you 200 findings and walk away. The bet
this project makes is that the real problem isn't *finding* issues —
Semgrep, Trivy, Gitleaks, CodeQL are great at that — it's **earning your
attention** with the output. So the focus is everything *after* a scanner
spits out JSON:

- **Cluster, don't list.** 47 SQL-injection findings across 12 callsites
  collapse into one cluster — pointed at the shared helper, not the 47
  rows you have to scroll through.
- **Reachability first.** Dep CVEs in packages you don't actually import
  drop one severity rung and hide by default. Five language families
  supported (Python, JS/TS, Go, Ruby, Java/Kotlin).
- **A "fix this week" queue.** The top-K clusters are ranked by the
  auditor with a one-line rationale per item. Works with or without an
  LLM key — there's a deterministic fallback.
- **Chat grounded in your code.** Every finding has a redacted 30-line
  code slice stored alongside it. The chat retriever uses it, so the
  auditor can say "the input on line 42 is already parameterized two
  lines up" instead of speaking in generalities.
- **Audit, not exploit.** Every LLM output is run through a safety
  validator that rejects payloads, diffs, and step-by-step content. Raw
  secrets are scrubbed before they're stored, rendered, or sent to a
  model.
- **Forensic-disassembler UI.** No glowing orbs. Tabular nums, hex
  gutters, terminal vibes. If you read code in JetBrains Mono by
  default, this will feel like home.

## 60-second install

Prereqs: Docker (Compose v2), ~6 GB free RAM. Anthropic / OpenAI key is
**optional** — see "No-LLM mode" below.

```bash
git clone https://github.com/ayaanmaliksgithub/virgil
cd virgil
cp .env.example .env

docker compose up -d
```

That's it. One command. On a cold cache the first run takes ~3–5 minutes
to bake the scanner image (Semgrep + Trivy + Gitleaks pre-warmed). After
that, every restart is seconds.

Open <http://localhost:3000>. The page is intentionally empty until you
submit a target — there's a one-click **"run sample scan"** button
pointed at [OWASP NodeGoat](https://github.com/OWASP/NodeGoat), a
deliberately-vulnerable Node.js training app. Clicking it submits the
real URL through the same `/v1/audits/json` route your own repos would
use; the pipeline runs end-to-end for ~3 minutes and every finding you
see is actual scanner output. Override the suggested target via
`NEXT_PUBLIC_DEMO_SCAN_URL` at web build time.

For UI-only design review, `/audits/demo` renders a static TS fixture
labeled clearly as such. No backend required.

### Submit a scan

```bash
# from the web UI:   http://localhost:3000  →  paste a GitHub URL
# from the CLI:
pip install virgilhq                          # or pipx install virgilhq — binary is `virgil`
virgil scan .                                 # current dir
virgil scan --url https://github.com/OWASP/NodeGoat
virgil findings <audit-id>
virgil report   <audit-id> --format sarif -o findings.sarif
```

Exit codes match what CI wants:

```bash
virgil scan . --fail-on critical              # exits 1 if any Critical lands
```

## Run it on every PR (GitHub Action)

Drop this in `.github/workflows/virgil.yml`:

```yaml
name: Virgil
on: [pull_request, push]
permissions:
  contents: read
  pull-requests: write     # for the sticky comment
  security-events: write   # for SARIF → GitHub Code Scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: ayaanmaliksgithub/virgil@v0.1.0
        with:
          fail-on: critical
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}  # optional
```

The Action spins up the Virgil stack on the runner, scans the PR in
PR-mode (only flagging findings on lines the PR touches), posts a
sticky comment with the ranked priority queue, and uploads SARIF for
GitHub's Code Scanning tab. ~3 minutes on a cold run; faster after.
A full example with all inputs is in
[examples/github-action-virgil.yml](examples/github-action-virgil.yml).

## What works today

Honest status: this is alpha-grade. The analysis engine is solid; the
distribution surface is still landing. Tracker is in
[ARCHITECTURE.md §16](ARCHITECTURE.md#16-build-status--deviations).

| Working | Notes |
|---|---|
| Public GitHub + ZIP intake | Private repos via paste-a-PAT (OAuth flow not yet) |
| Semgrep, Trivy, Gitleaks, opt-in CodeQL | Inside `--network=none --read-only --cap-drop=ALL` sandboxes |
| Per-finding LLM enrichment + executive narrative | Grounded in code context; safety-validated |
| Findings ledger + clustering + fix-the-helper | Web + CLI |
| LLM-ranked priority queue | Deterministic fallback when no LLM key |
| Reachability filter | Python, JS/TS, Go, Ruby, Java/Kotlin |
| Ask-the-Auditor chat | Streaming, grounded in stored findings + code |
| Suppressions + baseline diff | Per-repo, survives re-scans |
| PR-mode (base_sha → head_sha) | Filters findings to changed lines |
| Reports | JSON / Markdown / PDF / SARIF / CSV / XLSX |
| Compliance mapping | SOC2 / PCI-DSS / HIPAA / ISO27001 (best-effort, coarse) |
| Threat-intel (EPSS + CISA KEV) | Refreshed nightly |
| Outbound webhook on `audit.completed` | HMAC-signed |

## No-LLM mode

You do not need an Anthropic or OpenAI key to run the project. With
`LLM_PROVIDER=null` (or both keys empty), the audit pipeline:

- Skips per-finding LLM enrichment (you keep raw scanner output).
- Replaces the executive narrative with a deterministic severity-count
  summary.
- Falls back the **priority queue** to a deterministic ranker
  (severity × KEV × instance count × category) so you still get a
  "fix this week" view.
- Disables the ask-the-auditor chat (the chat refuses with a clear
  message; everything else works).

The clustering, reachability filter, fix-the-helper hints, suppressions,
baseline diff, PR-mode, compliance mapping, threat-intel, and all report
exports are **completely deterministic** — they run identically whether
or not an LLM provider is configured.

## Privacy

- **No telemetry.** This project never phones home. There is no analytics
  tracker, no anonymous-usage ping, no opt-in/opt-out toggle because
  there is nothing to opt into.
- **Secret scrubbing before storage.** AWS access keys, GitHub PATs,
  JWTs, Slack tokens, Google API keys, private-key blocks, RFC1918 IPs,
  and host paths are redacted *before* findings are persisted to the DB
  and *before* any prompt is sent to a model.
- **Sandboxed execution.** Repo code never executes on the host. Scanners
  run in `--network=none --read-only --cap-drop=ALL` containers with
  bounded CPU/memory/pids and a non-root UID.
- **Bring-your-own key.** If you configure an LLM provider, your prompts
  go to that provider directly — nothing routes through any third party.

## Repo layout

```
apps/
  api/      FastAPI service — routes, DB models, SSE stream
  worker/   Celery worker — sandbox runner, scanner adapters, normalize, LLM
  web/      Next.js 14 (App Router) — landing, audit console, findings, reports
  cli/      `virgil` CLI
packages/
  audit_core/         Shared Pydantic models + enums
  shared-schemas/     JSON Schema for the Finding contract
docker/               Per-service Dockerfiles (incl. the sandbox scanner image)
tests/                254 unit tests; pytest
```

Full design notes: [ARCHITECTURE.md](ARCHITECTURE.md).

## Contributing

Bug reports, PRs, and rule-pack contributions are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, test commands, and
the project's "no exploit content" line — the one inviolable rule
is that the platform does not generate payloads, exact patches, or
step-by-step reproduction. Defensive guidance only.

## License

Apache 2.0. See [LICENSE](LICENSE).

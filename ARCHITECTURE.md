# Virgil — Architecture

> An AI-assisted cybersecurity **audit and risk analysis** platform.
> This is **not** an exploit platform, attack tool, or auto-remediation system.

---

## 1. Product principles

| Allowed                                          | Not allowed                                              |
| ------------------------------------------------ | -------------------------------------------------------- |
| Explain what an issue is                         | Generate exploit payloads or PoCs                        |
| Explain why it matters and potential impact      | Provide step-by-step attack reproduction                 |
| Show affected files / locations                  | Provide exact code patches or auto-fix PRs               |
| Assign severity & confidence                     | Provide detailed remediation playbooks                   |
| High-level *defensive* guidance only             | Provide instructions that meaningfully aid exploitation  |

**Grounding rule.** Every AI-surfaced finding must trace back to a deterministic
artifact: scanner output, repository file, dependency manifest, or IaC/config file.
The LLM is a reasoning + summarization layer, never a source of vulnerabilities.

---

## 2. High-level system

```
                ┌─────────────────────────────────────────────────────┐
                │                    Frontend (Next.js)               │
                │  Landing · Job · Findings · Attack Surface · Report │
                └──────────────────────────┬──────────────────────────┘
                                           │ HTTPS / JSON
                ┌──────────────────────────▼──────────────────────────┐
                │                  API (FastAPI)                      │
                │  /audits  /jobs  /findings  /reports  /chat         │
                │  authn · validation · rate limiting · redaction     │
                └────────┬───────────────────┬────────────────────┬───┘
                         │                   │                    │
                ┌────────▼──────┐   ┌────────▼────────┐   ┌───────▼──────┐
                │  PostgreSQL   │   │     Redis       │   │ Object store │
                │ jobs/findings │   │ queue + cache   │   │ reports/logs │
                └────────┬──────┘   └────────┬────────┘   └──────────────┘
                         │                   │
                         │           ┌───────▼────────┐
                         │           │ Celery worker  │
                         │           │ orchestrator   │
                         │           └───────┬────────┘
                         │                   │ docker run --network=none …
                         │           ┌───────▼─────────────────────────┐
                         │           │   Per-job sandbox container     │
                         │           │  semgrep · trivy · gitleaks     │
                         │           └───────┬─────────────────────────┘
                         │                   │ raw JSON/SARIF
                         │           ┌───────▼────────┐
                         │           │ Normalizer +   │
                         │           │ Deduper        │
                         │           └───────┬────────┘
                         │                   │ unified findings
                         └───────────────────┤
                                             │
                                     ┌───────▼─────────┐
                                     │  LLM provider   │   ← pluggable
                                     │ (Anthropic /    │     (Claude or OpenAI)
                                     │  OpenAI)        │
                                     └─────────────────┘
```

---

## 3. Job lifecycle

```
queued → cloning → analyzing → scanning → correlating → reporting → completed
                                                                    └► failed
```

1. **submit** — user posts GitHub URL or uploads ZIP; API validates and creates an `audits` row + `jobs` row, enqueues `run_audit(job_id)`.
2. **cloning** — worker provisions a per-job temp workspace, validates the URL against an allowlist (scheme `https`, host `github.com|gitlab.com|…`), and runs `git clone --no-tags --single-branch` *inside* the sandbox container. By default the clone has unbounded depth on the default branch (no `--depth=`), so Gitleaks can walk the full commit history of that branch; tags and non-default branches are still excluded. Operators can pin to a shallow clone with `CLONE_DEPTH=<n>` (e.g. `CLONE_DEPTH=1` restores the original Phase-1 behavior). ZIP intake is the other path — uploaded archives are unpacked with path-traversal guards. The `max_bytes` cap is enforced after clone — runaway histories abort.
3. **analyzing** — detect languages, package managers, frameworks, IaC types. Emits a `repo_profile`.
4. **scanning** — runs scanner adapters in parallel inside the sandbox (`--network=none`, read-only mount of repo, capped CPU/RAM, wall-clock timeout, output size cap).
5. **correlating** — normalize → deduplicate → enrich (OWASP/CWE mapping) → persist findings.
6. **reporting** — LLM produces *executive summary*, *attack surface narrative*, and per-finding *business impact* + *safe guidance*. Inputs to the LLM are pre-redacted; raw secrets never leave the worker.
7. **completed** — final report artifacts uploaded to object storage; status flipped; webhook fired.

Idempotency: each step writes a checkpoint row so a crashed worker can resume from the last completed phase.

---

## 4. Sandboxing & host safety

- **Never** execute repository code on the host.
- Worker shells out to `docker run` (or `podman`) per scan with:
  - `--network=none` (scanners do not need internet; vuln DBs are pre-baked into the image)
  - `--read-only` rootfs, `--tmpfs /tmp:size=512m`
  - `--cap-drop=ALL`, `--security-opt=no-new-privileges`
  - `--pids-limit`, `--memory`, `--cpus`, `--ulimit nofile=…`
  - non-root UID, repo mounted read-only at `/repo`
  - `--stop-timeout` + outer wall-clock kill
- ZIP extraction uses a safe extractor that rejects absolute paths, `..` segments, symlinks pointing outside the workspace, and files exceeding size/count caps.
- Repo URL validator: scheme/host allowlist, no `@`, no credentials, no `file://`, no `git://`, no SSRF-y hosts (block RFC1918, link-local, metadata IPs).
- Output size caps on stdout/stderr; structured logging with PII/secret redaction before persistence.

---

## 5. Data model (Postgres)

```
users(id, email, created_at, …)                       # phase 3
audits(id, user_id, source_kind, source_ref, sha,
       created_at, status)
audit_secrets(id, audit_id, kind, encrypted_value,
              created_at)                            # phase 3 private repos
jobs(id, audit_id, state, phase, started_at,
     finished_at, error, attempts)
job_events(id, job_id, ts, phase, level, message)     # safe-redacted
repo_profiles(audit_id, languages jsonb, package_managers jsonb,
              frameworks jsonb, iac jsonb, loc int)
findings(id, audit_id, dedupe_key, title, severity,
         confidence, category, owasp_category, cwe, cve,
         affected_files jsonb, affected_lines jsonb,
         evidence text,            -- redacted
         explanation text,         -- LLM, grounded
         exploitability_summary text,
         business_impact text,
         safe_guidance text,
         source_tool text, raw_reference jsonb,
         status text, created_at)
reports(id, audit_id, kind, format, uri, created_at)  -- exec/tech, md/json/pdf
chat_sessions(id, audit_id, …)                        -- phase 2
chat_messages(id, session_id, role, content, citations jsonb)
```

`dedupe_key` = stable hash of `(normalized_rule_id, file, start_line, snippet_hash)`.

---

## 6. Unified finding schema

```jsonc
{
  "id": "uuid",
  "title": "Hardcoded AWS access key in source",
  "severity": "Critical",                       // Informational|Low|Medium|High|Critical
  "confidence": "High confidence",              // Low|Medium|High|Requires manual verification
  "category": "Secret Exposure",
  "owasp_category": "A02:2021 – Cryptographic Failures",
  "cwe": "CWE-798",
  "cve": null,
  "affected_files": ["src/config/aws.ts"],
  "affected_lines": [{"file": "src/config/aws.ts", "start": 14, "end": 14}],
  "evidence": "AKIA****************",           // redacted before storage
  "explanation": "A long-lived AWS access key is committed to the repository …",
  "exploitability_summary": "An attacker with read access to the repo could …",
  "business_impact": "Potential unauthorized access to cloud resources, billing exposure, data loss.",
  "safe_guidance": "Rotate the credential, move secrets to a managed secret store, and add pre-commit secret scanning. (High-level only — no operational steps.)",
  "source_tool": "gitleaks",
  "raw_reference": {"rule_id": "aws-access-token", "tool_version": "8.x"},
  "status": "open",
  "created_at": "2026-05-15T…"
}
```

`safe_guidance` is constrained by a system prompt + post-generation validator that rejects content containing payloads, exact diffs, exploit code, or step-by-step reproduction language.

---

## 7. Scanner adapter interface

All scanners implement a single Python protocol so adding CodeQL/Checkov/etc. later is mechanical:

```python
class ScannerAdapter(Protocol):
    name: str
    version: str
    def applicable(self, profile: RepoProfile) -> bool: ...
    def command(self, repo_path: Path, out_dir: Path) -> list[str]: ...
    def parse(self, out_dir: Path) -> list[RawFinding]: ...
```

Initial adapters:

| Tool       | Output       | Purpose                                  |
| ---------- | ------------ | ---------------------------------------- |
| Semgrep    | SARIF / JSON | SAST, multi-language rule packs          |
| Trivy      | JSON         | Dependency CVEs, IaC, secrets (cross-check) |
| Gitleaks   | JSON         | Secret detection (primary)               |
| CodeQL     | SARIF        | Opt-in deeper SAST (`ENABLE_CODEQL=true`) |

### Normalization pipeline

```
RawFinding → SeverityMapper → CategoryMapper → OWASP/CWE enricher
           → Redactor → Deduper → UnifiedFinding
```

- **SeverityMapper** translates each tool's native severity to the 5-level scale.
- **CategoryMapper** uses a static table (`rule_id → category`) plus fallbacks.
- **Redactor** scrubs secret values, internal IPs, absolute host paths, JWTs, etc., from `evidence` and any text fed to the LLM.
- **Deduper** groups by `dedupe_key`, keeps the highest-confidence record, merges `source_tool` into a list and unions `affected_*`.

---

## 8. AI reasoning layer

### Pluggable provider

```python
class LLMProvider(Protocol):
    def complete(self, system: str, messages: list[Msg],
                 *, response_schema: type[BaseModel] | None) -> Any: ...
```

Concrete: `AnthropicProvider`, `OpenAIProvider`. Selected by `LLM_PROVIDER` env var.

### Where the LLM runs

1. **Per-finding enrichment** — given the *normalized, redacted* finding + a short repo context blob, produce: `explanation`, `business_impact`, `safe_guidance`. Structured output (Pydantic) is required; free text outside schema is dropped.
2. **Attack-surface narrative** — given the aggregated findings + `repo_profile`, produce a non-technical executive summary and a categorized attack-surface overview.
3. **Ask the auditor (Phase 2)** — RAG over `findings`/`reports` only. The retriever returns finding IDs as citations; the answerer is system-prompted to refuse questions not answerable from cited context and to refuse all offensive requests.

### Safety controls on the LLM layer

- System prompt enumerates the **not allowed** list verbatim.
- Output validator: regex + small classifier check that rejects responses containing payload-shaped strings, shellcode hints, exact diffs, `curl`/`nc` reproduction lines, or "step 1 / step 2" attack instructions.
- Temperature low (≤ 0.3) for finding enrichment; structured output mode where supported.
- No raw secret values ever included in prompts (redaction happens *before* the LLM call).
- Token + cost budget per audit; hard cap.

---

## 9. API surface (Phase 1)

```
POST   /v1/audits                 # body: {source_kind, source_ref} or multipart ZIP
GET    /v1/audits/:id
GET    /v1/audits/:id/job
GET    /v1/audits/:id/events      # SSE stream of phase changes
GET    /v1/audits/:id/findings    # filters: severity, category, owasp, file, tool, confidence
GET    /v1/findings/:id
GET    /v1/audits/:id/report?view=executive|technical&format=json|md|pdf
POST   /v1/audits/:id/chat        # phase 2
```

All responses use the unified finding schema. Errors follow RFC 7807.

---

## 10. Frontend (Next.js + Tailwind + shadcn/ui)

Design intent: **security command center**, quiet premium dark UI, evidence-first.
Explicitly avoid: glowing orbs, fake AI shimmer, generic SaaS dashboards.

Pages:

| Route                          | Purpose                                                        |
| ------------------------------ | -------------------------------------------------------------- |
| `/`                            | Landing — submission (URL or ZIP), platform explainer          |
| `/audits/[id]`                 | Live audit console — phase timeline, log stream, partial stats |
| `/audits/[id]/findings`        | Findings dashboard — filters, severity grid, table             |
| `/audits/[id]/findings/[fid]`  | Finding detail — evidence, locations, reasoning, citations     |
| `/audits/[id]/attack-surface`  | Attack-surface categories: secrets, auth, API, deps, IaC       |
| `/audits/[id]/report`          | Executive & technical report tabs; export buttons              |
| `/audits/[id]/chat`            | Ask-the-auditor (Phase 2)                                      |

Shared: severity chips, confidence chips, OWASP badges, file-path links, copy-as-JSON. Real-time updates via SSE from `/events`.

---

## 11. Repository layout

```
virgil/
├── ARCHITECTURE.md
├── README.md
├── .env.example
├── docker-compose.yml
├── docker/
│   ├── api.Dockerfile
│   ├── worker.Dockerfile
│   ├── scanner.Dockerfile          # baked semgrep + trivy + gitleaks
│   └── web.Dockerfile
├── apps/
│   ├── api/                        # FastAPI service
│   │   ├── pyproject.toml
│   │   ├── alembic/
│   │   └── app/
│   │       ├── main.py
│   │       ├── config.py           # pydantic-settings; env validation
│   │       ├── deps.py
│   │       ├── db/
│   │       │   ├── models.py
│   │       │   └── session.py
│   │       ├── schemas/            # pydantic request/response
│   │       ├── routes/
│   │       │   ├── audits.py
│   │       │   ├── findings.py
│   │       │   ├── reports.py
│   │       │   └── events.py       # SSE
│   │       ├── services/
│   │       │   ├── intake.py       # URL validation, ZIP intake
│   │       │   └── reports.py
│   │       └── security/
│   │           ├── redaction.py
│   │           └── url_validator.py
│   ├── worker/                     # Celery worker + orchestration
│   │   ├── pyproject.toml
│   │   └── worker/
│   │       ├── celery_app.py
│   │       ├── tasks.py            # run_audit, phases
│   │       ├── sandbox/
│   │       │   ├── runner.py       # docker run wrapper
│   │       │   └── zip_extract.py
│   │       ├── profile/
│   │       │   └── detect.py       # language/framework detection
│   │       ├── scanners/
│   │       │   ├── base.py         # ScannerAdapter protocol
│   │       │   ├── semgrep.py
│   │       │   ├── trivy.py
│   │       │   └── gitleaks.py
│   │       ├── normalize/
│   │       │   ├── severity.py
│   │       │   ├── category.py
│   │       │   ├── owasp_cwe.py
│   │       │   ├── redact.py
│   │       │   └── dedupe.py
│   │       ├── ai/
│   │       │   ├── provider.py     # LLMProvider protocol
│   │       │   ├── anthropic_provider.py
│   │       │   ├── openai_provider.py
│   │       │   ├── prompts/        # system prompts (audit, chat, exec summary)
│   │       │   ├── enrich.py       # per-finding enrichment
│   │       │   ├── narrative.py    # exec summary + attack surface
│   │       │   └── safety.py       # output validator (deny payloads/diffs)
│   │       └── reporting/
│   │           ├── markdown.py
│   │           ├── json_export.py
│   │           └── pdf.py          # phase 2
│   └── web/                        # Next.js 14 app router
│       ├── package.json
│       ├── tailwind.config.ts
│       ├── app/
│       │   ├── page.tsx                          # landing
│       │   ├── audits/[id]/page.tsx              # live console
│       │   ├── audits/[id]/findings/page.tsx
│       │   ├── audits/[id]/findings/[fid]/page.tsx
│       │   ├── audits/[id]/attack-surface/page.tsx
│       │   ├── audits/[id]/report/page.tsx
│       │   └── audits/[id]/chat/page.tsx
│       ├── components/
│       │   ├── severity-chip.tsx
│       │   ├── confidence-chip.tsx
│       │   ├── owasp-badge.tsx
│       │   ├── phase-timeline.tsx
│       │   ├── findings-table.tsx
│       │   └── attack-surface-grid.tsx
│       └── lib/api.ts
├── packages/
│   └── shared-schemas/             # JSON schema for Finding (consumed by web + api)
└── tests/
    ├── normalize/                  # unit tests — severity/dedupe/redaction
    ├── reporting/                  # report generation snapshot tests
    ├── safety/                     # LLM output validator tests
    └── fixtures/
        ├── semgrep/*.json
        ├── trivy/*.json
        └── gitleaks/*.json
```

---

## 12. Configuration & environment

Validated at boot with `pydantic-settings` (fail-fast on missing).

```
# core
DATABASE_URL=
REDIS_URL=
OBJECT_STORE_URL=                  # s3://… or file://./var
JOB_TIMEOUT_SECONDS=900
MAX_REPO_BYTES=524288000           # 500 MB

# sandbox
SCANNER_IMAGE=virgil/scanner:latest
SANDBOX_CPUS=2
SANDBOX_MEMORY=4g
SANDBOX_PIDS=512

# llm
LLM_PROVIDER=anthropic             # anthropic | openai
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
LLM_MODEL=claude-opus-4-7
LLM_MAX_TOKENS_PER_AUDIT=200000
```

---

## 13. Testing strategy (Phase 1)

- **Unit:** normalization (severity, category, redaction, dedupe) — table-driven with real scanner fixtures captured from intentionally-vulnerable demo repos.
- **Contract:** every scanner adapter parses its committed fixture into the unified schema without loss; schema validated against `packages/shared-schemas`.
- **Safety:** LLM output validator — fixtures of disallowed responses (payloads, diffs, step-by-step) must be rejected; allowed responses pass.
- **API:** route-level tests with in-memory DB; happy path + URL-validation failures + ZIP-traversal rejection.
- **E2E (compose-based):** submit a fixture ZIP → poll job → assert findings + report exist. Scanners run in real containers.

---

## 14. Phased delivery

**Phase 1 (this build)** — public GitHub + ZIP ingestion, Semgrep + Trivy + Gitleaks integration, queue, normalization, dedupe, findings dashboard, JSON report.

**Phase 2** — LLM enrichment, attack-surface narrative, executive summary, Markdown + PDF export, Ask-the-auditor RAG chat.
Backend Phase 2 is complete. Frontend Phase 2 polish was intentionally skipped
for now per product direction: chat replies arrive whole rather than streamed,
and new-audit queue/progress UX is not being worked on in this backend pass.

**Phase 3** — GitHub OAuth, private repos, orgs/teams, historical diffs, continuous monitoring, CI/CD integrations.

**Phase 4 (audit depth & program scale)** — capabilities a serious audit
platform is expected to have that Phases 1–3 don't cover. Tracked as an
ordered backlog in §17 so the work happens methodically rather than as
ad-hoc additions. In rough leverage order: git-history secret scanning,
EPSS/KEV enrichment, license risk, finding lifecycle (suppression +
baseline diff), diff/PR-mode scanning, custom org policy rules,
compliance-control mapping (SOC2/PCI/HIPAA/ISO27001), reachability
filtering, API-spec analysis, AI/ML risk scanners, CSPM (live cloud
audit), threat-intel surfacing, human-in-the-loop review, and
branch-protection / repo-hygiene audit. Each item ships in its own
self-contained PR — no item is allowed to expand the scope of another.

---

## 15. Resolved decisions

1. **Object storage:** S3 (or S3-compatible, e.g. MinIO) for both dev and prod. `docker-compose` provisions MinIO locally; same `boto3` client code in both environments.
2. **PDF generator:** WeasyPrint — Apache-2.0, pure Python, no headless browser dep.
3. **Auth (Phase 1):** none. Single-tenant local deployment. Auth deferred to Phase 3 (GitHub OAuth).
4. **ZIP intake:** one archive per audit. Simpler invariant — an audit corresponds to a single source tree (URL *or* one ZIP). Multi-archive audits are not a real workflow; users can submit separate audits.
5. **Default Semgrep ruleset:** `p/owasp-top-ten` + `p/security-audit` + `p/secrets`. Aligned with the platform's audit framing (OWASP mapping is already a first-class field). `p/ci` is CI-tuned and skews toward fast/low-noise rather than thorough — wrong tradeoff for an audit tool. Configurable via env.

---

## 16. Build status & deviations

A running ledger of what is implemented vs. still pending, plus places the
shipped code diverged from the plan above. Keep this honest — it is the
fastest way for a future contributor to know what to trust.

### Backend — done

- [x] `packages/audit_core` — Pydantic models (`Finding`, `RawFinding`, `RepoProfile`, enums, ordering tables) and JSON Schema mirror at `packages/shared-schemas/finding.schema.json`. Path-installed by both `apps/api` and `apps/worker`.
- [x] Scanner adapter protocol (`worker/scanners/base.py`) + Semgrep · Trivy · Gitleaks adapters. Adapters only build argv and parse output — never execute.
- [x] Normalization pipeline (`worker/normalize/`): severity, category, OWASP/CWE enrichment, redaction, dedupe with cross-tool confidence bump.
- [x] Redaction module covers: AWS access keys, GitHub PATs, JWTs, Slack tokens, Google API keys, private-key blocks, RFC1918 IPs, `/Users` / `/home` host paths, generic `secret=` / `token=` / `password=` / `api_key=` assignments. `safe_for_llm()` also caps to 400 chars.
- [x] URL validator (`apps/api/app/security/url_validator.py`) — https-only, host allowlist (github / gitlab / bitbucket), rejects credentials in URL, non-standard ports, hosts resolving to private/loopback/link-local/reserved IPs.
- [x] Safe ZIP extractor (`worker/sandbox/zip_extract.py`) — rejects traversal, absolute paths, symlinks, oversize, suspicious compression ratios.
- [x] Sandbox runner (`worker/sandbox/runner.py`) — wraps `docker run` with `--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges`, non-root UID, bounded CPU/memory/pids, wall-clock timeout, and host-path scrubbing in log lines.
- [x] Cloning (`worker/clone.py`) — also containerized; the only phase that needs network egress. Caps the cloned tree size after clone.
- [x] FastAPI service (`apps/api`): routes for `POST /v1/audits` (multipart) and `POST /v1/audits/json`, `GET /v1/audits/:id`, `GET /v1/audits/:id/findings` with filtering, `GET /v1/findings/:id`, `GET /v1/audits/:id/report` (JSON/Markdown), and `GET /v1/audits/:id/events` (SSE).
- [x] SQLAlchemy 2.x models for `audits`, `findings`, `job_events`, `reports` (`apps/api/app/db/models.py`).
- [x] Celery worker (`apps/worker/worker/tasks.py`) — phase-state machine: cloning → analyzing → scanning → correlating → reporting → completed/failed. Writes a `JobEvent` row per phase; safe-redacted errors on failure.
- [x] Pluggable LLM provider (`worker/ai/provider.py`) with `AnthropicProvider`, `OpenAIProvider`, and a `_NullProvider` so the pipeline degrades gracefully without an API key.
- [x] Per-finding enrichment (`worker/ai/enrich.py`) and executive narrative (`worker/ai/narrative.py`) — both pre-redact inputs and run outputs through the safety validator.
- [x] Safety validator (`worker/ai/safety.py`) — regex-based rejector for payload shapes, unified diffs, step-numbered reproduction, and named offensive tooling. Fallbacks substitute defensive boilerplate.
- [x] Report generation (`apps/api/app/services/reports.py`) — `build_executive`, `build_technical`, `render_markdown`. JSON is on-disk truthy; Markdown is rendered on demand. PDF deferred to Phase 2.
- [x] `docker-compose.yml` with Postgres, Redis, MinIO, API, Worker, Web, and a one-shot `scanner-image-builder` service. Scanner Dockerfile bakes Semgrep + Trivy + Gitleaks + git and pre-warms the Trivy DB so scans can run `--network=none`.
- [x] `.env.example` covers core, sandbox, scanner, LLM, and API config.
- [x] Unit tests (47 passing) covering severity mapping, redaction patterns, dedupe (incl. cross-tool merge), OWASP/CWE normalization, the full normalization pipeline, URL validator, ZIP extractor security, and the LLM safety validator.

### Backend — pending

- [ ] **GitHub OAuth browser flow, orgs/teams, historical diffs, continuous monitoring, CI/CD integrations** — Phase 3.

### Backend — added since §16 first written

- [x] **Alembic** wired (`apps/api/alembic.ini`, `alembic/env.py`) with two migrations: `0001_initial` (audits/findings/job_events/reports) and `0002_chat` (chat_sessions/chat_messages). `alembic upgrade head` now works.
- [x] **S3/MinIO storage adapter** (`apps/api/app/services/storage.py`). Single boto3 client serves both dev (MinIO) and prod (real S3); auto-creates the bucket on first write; returns canonical `s3://bucket/key` URIs and an optional presigned GET. The worker now pre-bakes executive/technical JSON + Markdown reports, best-effort PDF artifacts when WeasyPrint is available, and persists `reports` rows for successfully stored artifacts. The report API prefers stored artifacts and falls back to live rendering if object storage is unavailable.
- [x] **Ask-the-Auditor chat (Phase 2)** — `worker/ai/chat.py` (keyword retriever, severity tiebreak, structured-JSON LLM call, citation gating, safety-validator filter) plus `apps/api/app/routes/chat.py` (`POST /v1/audits/:id/chat`, `GET /v1/audits/:id/chat/:session_id`). Sessions persist in Postgres; the user turn is committed before the LLM call so the convo survives a model crash.
- [x] **PDF export (Phase 2)** — `apps/api/app/services/pdf.py` renders an HTML doc tuned for WeasyPrint A4 with running page counters and a footer that re-states the platform's non-exploit positioning on every page. Report route now accepts `format=pdf`; returns 503 when WeasyPrint deps are missing on the host so the API stays up. API Dockerfile installs cairo / pango / dejavu fonts.
- [x] **52 unit tests passing** (was 47): added 5 retriever tests for the chat RAG path.
- [x] **API-level integration test suite** (`tests/api/test_api_routes.py`). Uses FastAPI `TestClient` against a disposable Postgres database via `TEST_DATABASE_URL` so JSONB behavior is exercised without a SQLite shim. Covers JSON audit intake/enqueue, URL rejection, audit 404s, findings filter/detail routes, stored-report preference + fallback, and no-findings chat persistence.
- [x] **Idempotent report artifact rows.** Worker report pre-baking deletes any prior `reports` row for the same `(audit_id, kind, format)` before inserting the new artifact URI, so retries do not accumulate stale rows.
- [x] **Opt-in compose smoke test** (`tests/e2e/test_compose_smoke.py`). With the compose stack running, `RUN_COMPOSE_SMOKE=1 API_BASE=http://localhost:8000 pytest tests/e2e/test_compose_smoke.py` submits a generated ZIP fixture, polls the audit to terminal state, asserts findings exist, and verifies the technical JSON report matches the completed audit.
- [x] **CodeQL adapter** (`worker/scanners/codeql.py`). Opt-in via `ENABLE_CODEQL=true`, limited to buildless/source-root analysis for Python, JavaScript/TypeScript, Ruby, and Go so the sandbox never runs repository build commands. Parses SARIF into `RawFinding`, maps CodeQL security severity into the unified severity scale, and bakes the CodeQL CLI into `docker/scanner.Dockerfile` for VPS/container builds.
- [x] **Private GitHub repository audit foundation.** URL intake accepts an optional `github_token`, requires `SECRET_ENCRYPTION_KEY`, stores the token encrypted in `audit_secrets`, and the worker decrypts it only for the clone phase. Cloning uses a temporary `GIT_ASKPASS` helper inside the per-job workspace, so the token is not embedded in the repo URL or `git clone` argv. This is not the full OAuth browser flow yet; it is the secure backend credential path that OAuth can later feed.
- [x] **Phase 4 #1 — git-history secret scanning.** `worker/clone.py` drops `--depth=1` by default (full history of the cloned branch — still `--single-branch --no-tags`) with a `CLONE_DEPTH` env escape hatch. `worker/scanners/gitleaks.py` walks git log when a `.git` dir is present on the **host** path (the worker orchestrator sets `host_repo_path` on the adapter before calling `command()` so detection happens on the worker filesystem, not the container-side `/repo`); falls back to `--no-git` for ZIP intake. Historical hits surface `Commit / Author / Date / Message` in `raw` and tag the title with the short SHA so triagers can tell a current-tree leak from a years-old commit.
- [x] **Phase 4 #2 — EPSS / KEV enrichment.** New `threat_intel` table (alembic `0004_threat_intel`) keyed by CVE. Nightly `worker.tasks.refresh_threat_intel` Celery-beat task (03:17 UTC) pulls EPSS CSV + CISA KEV JSON via the worker process (never from inside the `--network=none` scanner sandbox) and upserts via Postgres `ON CONFLICT`. `worker/normalize/threat_intel.py` joins on `findings.cve` between the normalize and reporting phases; the enriched fields are then persisted by `_persist_findings` and serialized by the findings list/detail routes, the technical report JSON+Markdown, and the chat reconstructor — full round-trip from worker → DB → API → report → chat context. `Finding` (Pydantic + JSON schema + SQLAlchemy + DDL) gains `epss_score`, `epss_percentile`, `kev`. UI surfacing of these fields is item #12.
- [x] **Code context made first-class.** Both halves of the
  "we capture it but never use it well" gap are now closed.

  1. **Inline code view on finding detail.** New
     `apps/web/components/code-context.tsx` parses the stored slice
     (`<lineno>  <line>` format), renders it as a styled code block
     with 1-indexed gutter, and highlights the offending line via a
     warm-phosphor left rail + bone-bright text against an ink-100
     row. Redaction markers (`<jwt-redacted>`, `<host-path>`, …) keep
     their text but pick up a muted style with `▒…▒` flanking so they
     read as "intentionally masked" rather than typos. Inserted as the
     headline block on the finding detail page (above `explanation()`)
     when `code_context` is present; the hex dump stays in the sidebar
     as the redaction-contract visual. API serializer also surfaces
     `code_context` so the field is consumable.
  2. **Per-finding LLM enrichment uses code_context.**
     `worker/ai/enrich.py` now passes the redacted slice into the
     user prompt as a delimited code block, with an explicit pointer
     to the offending line number. The prompt instructions tell the
     model to reference specific lines and variable names from the
     slice rather than speak generically, and to note when surrounding
     code already mitigates the issue (the "actually this is fine
     because input is parameterized two lines up" answer). Pipeline
     ordering in `tasks.py` runs `enrich_with_code_context` BEFORE
     `enrich_findings`, so every `explanation` / `business_impact` /
     `exploitability_summary` / `safe_guidance` regeneration sees the
     code by default — no opt-in needed. **4 new tests in
     `tests/test_enrich_code_context.py`** pin the prompt contract
     (no-context omits the block; presence triggers a delimited code
     block with the offending line called out; instructions explicitly
     require line/variable references and upstream-mitigation
     acknowledgement). Total **239 passing**.

- [x] **Triage layer follow-on (multi-lang reachability, suggested questions,
  fix-the-helper, suppression-driven refresh).** Four upgrades to the
  triage layer that landed in one session.

  1. **Reachability for Go / Ruby / Java / Kotlin.** Extended
     `worker/normalize/reachability.py` with collectors for `.go`,
     `.rb`, `.java`, `.kt`/`.kts` files. Go covers single-line and
     grouped `import (…)` forms incl. aliased imports; pkg matching
     uses `github.com/foo/bar` prefix (a finding on
     `github.com/foo/bar` is reachable if any import starts with
     `github.com/foo/bar/`). Ruby handles `require`, `require_relative`
     (filtered), and Gemfile-style `gem "name"`. Java strips the
     trailing class identifier (and the method for static imports) to
     get the package; Maven coord matching is by group-id prefix
     (Trivy reports `com.fasterxml.jackson.core:jackson-databind`, we
     match any import starting with `com.fasterxml.jackson.core`).
     Kotlin shares the Java index — semicolon-optional regex. **9 new
     tests in `tests/test_reachability.py`** covering single+grouped
     Go imports, ruby require-vs-relative, java package extraction,
     kotlin no-semicolon, maven group-id prefix, dep-not-imported
     demotion across all three.
  2. **Suggested chat questions** (`apps/api/app/services/suggested_questions.py`).
     New `GET /v1/audits/:id/chat/suggested` returns up to 3 concrete
     `{label, prompt}` pairs derived from the top priority clusters.
     Cluster-shape drives variant — KEV clusters get a "kev in this
     code?" prompt, dep clusters get "is this dep used?", high-instance
     get "shared root?", secret-exposure gets "rotation scope?",
     injection gets "trace the input flow?". Deterministic templates,
     no LLM call. Audit-wide generic fallbacks fill the slate when
     cluster-specific prompts run out. Frontend `ChatConsole` renders
     them as click-to-prefill buttons in place of the static example
     list. **7 new tests in `tests/test_suggested_questions.py`** —
     empty audit, max-3 cap, KEV path, secret-rotation path,
     high-instance path, all-unreachable exclusion, priority-list
     ordering.
  3. **Fix-the-helper hints** (`worker/normalize/helpers.py`). At audit
     completion, for each cluster with `instances ≥ 2` we compute:
     **shared_dir** (`os.path.commonpath` over affected_files, drops
     repo-root-only signal) and **shared_modules** (internal imports
     appearing in ≥70% of affected files, filtered to ones resolving
     to repo source files — external libs like `logging` / `react`
     don't count). Python imports include resolved-relative form so
     `from .utils import x` becomes `pkg/utils`. Stashed on
     `audit.profile.cluster_hints[cluster_key]`. API joins into the
     cluster response as `cluster.hint`; triage page renders a small
     `fix_the_helper: shared imports utils, db.helper · common dir
     src/handlers` line under each cluster row. **9 new tests in
     `tests/test_helpers_hint.py`** — single-file no-op, deepest
     common dir, root-only nil, internal-import detection, external-
     filter, 70% threshold, JS relative resolution, path-escape skip.
  4. **Suppression-driven priority refresh**
     (`apps/api/app/services/triage_refresh.py`). Suppressing or
     un-suppressing a finding now triggers a synchronous recompute of
     the priority list using the deterministic ranker (severity × KEV
     × instance count) over current non-suppressed findings — no LLM
     call, no UI lag. Suppressed clusters vanish from the top-K
     queue; un-suppressing restores them. POST/DELETE on
     `/v1/audits/:id/suppressions` and `/v1/suppressions/:id` call
     `refresh_priority_list` after commit; for DELETE we refresh
     every audit sharing the source_ref (suppressions are repo-scoped
     by design). Cluster hints are NOT refreshed (they need repo on
     disk, only available at audit time); they're stable hints about
     shared upstream modules, so staleness doesn't matter. **4 new
     tests in `tests/test_triage_refresh.py`** — remaining-cluster
     write, fully-suppressed-cluster drop, empty-after-suppress clear,
     empty-findings clear with profile preservation.

  Total **235 passing** (was 206; +29 across the four pieces). Web
  `tsc --noEmit` clean.
- [x] **Triage layer (clusters + LLM "fix this week" + code-grounded chat).**
  Three coupled features whose point is to convert "wall of findings" into
  "ranked, code-aware triage queue."

  1. **Clustering** — `apps/api/app/services/clusters.py` groups findings by
     a stable `cluster_key = sha1(category | cwe | rule_signature)[:16]`.
     `rule_signature` is `pkg:<name>` for Trivy dep CVEs (one bump fixes N
     CVEs on the same package), `rule:<id>` for Semgrep / Gitleaks /
     misconfigs, `title:<sha1>` last-resort. Representative finding is the
     highest-severity + most-confident instance; clusters surface
     `instances`, deduped `files[:12]`, deduped `cves[:8]`,
     `kev` (any-instance), `any_unreachable` / `all_unreachable`. New route
     `GET /v1/audits/:id/findings/clusters` (hides all-unreachable clusters
     by default).
  2. **Priority list** — `apps/worker/worker/ai/priority.py` runs once at
     audit completion. Sends compact cluster signals (no raw evidence) to
     the LLM with a strict JSON schema (`cluster_key` + 280-char `reason`),
     filters hallucinated/duplicate keys, sanitizes reasons through the
     safety validator. Deterministic fallback (severity + KEV + instance
     counts → templated reason) so OSS deployments without an LLM provider
     still get a useful triage view. Stashed on `audit.profile.priority_list`.
  3. **Code-grounded chat** — `apps/worker/worker/normalize/code_context.py`
     reads a ~30-line window around each finding's first affected_line
     (`CONTEXT_LINES_BEFORE=12`, `CONTEXT_LINES_AFTER=18`), renders with
     1-indexed line numbers, redacts line-by-line (avoids `redact()`'s
     600-char single-blob cap silently chopping the window), enforces a
     2KB byte cap with `… (truncated)` marker, refuses paths that escape
     repo_path. Stored on new `findings.code_context` column (alembic
     `0009_code_context`). Chat `_finding_blob` includes it as
     `code_context_redacted`; system prompt instructs the LLM to ground
     answers in it (cite line numbers, note when surrounding code already
     mitigates) without quoting back verbatim. Affected lines list also
     surfaced (capped 4) so the LLM can cross-reference.

  New surface: `/audits/[id]/triage` page (added to the tab bar) renders the
  LLM priority list as a numbered queue with rationale per item above the
  cluster ledger. Each cluster row links to its representative finding.

  **30 new unit tests** across clusters (9), priority (7), reachability (12),
  code_context (8). Total 206 passing.
- [x] **Phase 4 #8 — Reachability filtering for dependency findings.**
  The single largest noise-reduction lever in any SCA pipeline. New
  `worker/normalize/reachability.py` walks the source tree, collects
  the set of TOP-LEVEL imported package names per language (Python via
  `ast` — `Import`/`ImportFrom`, skipping relatives; JS/TS via a tight
  regex over `import`/`require`/dynamic-`import` that handles
  `@scope/pkg`, sub-paths, JSX/TSX, ignores `./` and `/` paths), then
  joins against Trivy's `raw.pkg` for findings tagged
  `Vulnerable Dependency`. Findings whose package is unreachable get
  `reachable=False` and severity demoted one rung (Critical→High→…→Low,
  floor at Informational). Vendored dirs (`node_modules`, `.venv`,
  `dist`, …) are skipped. Parser failures (syntax errors) fail open.
  When zero source files of the relevant language were parsed the
  enricher **abstains** (returns `reachable=None`) rather than wrongly
  demote — biased toward not hiding real risk. Python dist-name
  normalization (`google-cloud-storage` → tries `google`,
  `google_cloud_storage`, etc.) covers the common dist↔import gap.
  Wired into `tasks.py` after compliance enrichment; per-scan counts
  surfaced as a phase event. New `findings.reachable` column (alembic
  `0008_reachability`, nullable). Surfaced on findings list/detail
  JSON, chat reconstructor, technical Markdown report. UI: a new
  `unreachable deps · N hidden` filter pill (hidden by default), an
  `[ unreach ]` chip on each row, and `[ reachable ]` / `[ unreachable ]`
  chips on the finding detail page. **12 new unit tests in
  `tests/test_reachability.py`** — AST + JS regex collectors, scoped
  packages, vendored-dir skip, fail-open on syntax error, dist-name
  normalization, abstain-without-signal, non-dep pass-through, severity
  demotion floor. Total 182 passing.
- [x] **Phase 5 #3 — Outbound webhook (minimum shape).** Global
  `WEBHOOK_URL` + `WEBHOOK_SECRET` env. After a successful audit the
  worker POSTs an `audit.completed` body with severity_breakdown +
  KEV count, HMAC-sha256 signed via `X-Audit-Signature: sha256=<hex>`.
  Delivery is fire-and-forget — receiver downtime never marks the audit
  failed; missing secret refuses to deliver unsigned; transport errors
  + non-2xx responses are logged and swallowed. Email digest (#5) and
  per-org endpoints with retry queue land with Phase 3 orgs/teams.
  **7 new unit tests in `tests/test_notifications.py`** covering payload
  shape, signature round-trip, no-op without config, refusal without
  secret, transport failure, non-2xx. Total 170 passing.
- [x] **Phase 5 #18 — CSV / XLSX findings export.** New
  `apps/api/app/services/findings_export.py` with a frozen
  append-only `COLUMNS` list (security teams paste into spreadsheets; a
  column shuffle erodes trust). `GET /v1/audits/:id/findings/export`
  accepts `?format=csv|xlsx` — CSV is stdlib, XLSX uses optional
  `openpyxl` and returns 503 if the dep is missing (mirrors the PDF
  fallback). Compliance dict serialized as `SOC2:CC6.1; PCI-DSS:3.4,8.2.1`,
  KEV as `yes`, line ranges as `file:Lstart`. **4 new unit tests (+1 xlsx
  test skipped when openpyxl absent)** in `tests/test_findings_export.py`.
  Total 163 passing.
- [x] **Phase 5 #17 — SARIF v2.1.0 export.** New `apps/api/app/services/sarif.py`
  emits one SARIF `run` per `source_tool` (so consumers can toggle tools
  independently), maps severity → SARIF `level` (`error`/`warning`/`note`/`none`)
  plus a `security-severity` rule property GitHub Code Scanning consumes
  (0–10 scale), surfaces CWE as `helpUri` to mitre.org and compliance as
  flat `tags` (`SOC2:CC6.1`), KEV/EPSS/CVE on result properties,
  `partialFingerprints.dedupeKey/v1` for stable cross-scan matching. Report
  route accepts `format=sarif` and returns
  `application/sarif+json`. **8 new unit tests in `tests/test_sarif.py`** —
  empty, multi-tool split, level mapping, security-severity, CWE helpUri,
  compliance tags, KEV/EPSS propagation, file-only fallback. Total 159
  passing.
- [x] **Phase 4 #12 — Threat-intel UX surfacing.** Findings table now
  shows a `[ KEV ]` chip + `EPSS=` chip (only when score≥0.5 to keep the
  ledger quiet) per row, a filter pill `[ KEV ] cisa kev hits · N`
  toggles a KEV-only view, and the findings page renders a top-of-page
  callout (`⚠ cisa kev · N active-exploit cves`) when there's at least
  one KEV hit. Finding detail page also shows KEV + EPSS chips alongside
  CVE, plus a new `compliance.controls()` block listing every framework's
  mapped control IDs (Phase 4 #7 surfacing too). Web types extended with
  `Finding.kev/epss_score/epss_percentile/compliance`. Web `tsc --noEmit`
  clean.
- [x] **Phase 4 #7 — Compliance control mapping.** New static
  `worker/normalize/compliance.py` mapping `(category, cwe)` → control IDs
  across SOC2, PCI-DSS, HIPAA Security Rule, and ISO/IEC 27001:2022.
  Category mapping + CWE override merge without duplicates. `Finding` gained
  `compliance: dict[str, list[str]]` (audit_core), new
  `findings.compliance` JSONB column (alembic `0007_compliance`,
  `server_default '{}'::jsonb`), and the enrichment runs immediately after
  threat-intel join. Surfaced everywhere we surface KEV/EPSS: findings list
  + detail JSON, technical Markdown report (`**Compliance controls:**`
  line per finding), chat reconstructor. **7 new unit tests in
  `tests/test_compliance.py`** covering category lookup, CWE override,
  no-duplicate merge, immutability of input. Total 151 passing.
- [x] **Phase 4 #6 — Custom Semgrep rule pack.** `SEMGREP_CUSTOM_RULES_DIR`
  env var points at a host directory of `*.yaml` Semgrep rules; the worker
  bind-mounts it read-only at `/custom-rules` and the adapter appends a
  `--config /custom-rules` arg AFTER the default packs (so the org pack
  layers on top, not replaces). Sandbox stays `--network=none`, so remote
  pack URLs must be pre-fetched into the bound dir — documented in
  `.env.example`. New `extra_mounts` param on `worker/sandbox/runner.py` that
  rejects collisions with `/repo`, `/out`, `/tmp` and validates the mode
  flag; adapters declare mounts via an `extra_mounts` attr that `tasks.py`
  forwards. **4 new unit tests in `tests/test_custom_rules.py`** covering
  absent-env, present-dir, missing-dir-silently-skipped, and runner
  reserved-path rejection. Total 144 passing.
- [x] **Phase 4 #5 — Diff / PR-mode scanning.** New `base_sha` + `head_sha`
  columns on `audits` (alembic `0006_pr_mode`), accepted via
  `POST /v1/audits/json` (both required together, hex pattern enforced).
  After normalization the worker calls `worker/pr_mode.compute_changed_lines`
  (re-enters the scanner container with `--network=none --read-only` and runs
  `git diff -U0 base..head`), then `filter_findings_by_diff` keeps only
  findings whose `affected_lines` intersect the head-side line set —
  repo-wide findings with no line context fall back to a file-match (so dep
  CVEs touching a changed file survive). Adapter inputs are unchanged on
  purpose: Semgrep taint / Gitleaks history would lose signal if narrowed
  pre-scan. **6 new unit tests in `tests/test_pr_mode.py`** for the diff
  parser (multi-hunk, deletions, basename-suffix path match) and the filter.
  Total 140 passing.
- [x] **Phase 4 #4 — Finding lifecycle UI.** `components/findings-table.tsx`
  gained a `lifecycle · vs baseline` filter group (`[ NEW ]` / `[ RECUR ]`
  pills) and a `$ show/hide suppressed` toggle that flips the
  `?include_suppressed=true` query. Each row shows `[ NEW ]` / `[ RECUR ]`
  next to the severity chip when a baseline is set, and suppressed rows
  render struck-through with a `[ suppressed ]` tag. New
  `components/suppress-action.tsx` (client component) on the finding detail
  page handles inline suppress (reason required) / unsuppress via the new
  API; uses `router.refresh()` to re-fetch server data. Findings page
  also renders a baseline banner pointing at the prior audit and a `$ cat
  diff.json` link to `/v1/audits/:id/diff`. Web types extended with
  `Lifecycle`, `Finding.lifecycle/suppressed/suppression_reason/suppression_id/dedupe_key`,
  and `Audit.baseline_audit_id`. Web `tsc --noEmit` clean.
- [x] **Phase 4 #4 — Finding lifecycle: suppression + baseline diff (backend).**
  New `suppressions` table keyed by `(source_ref, dedupe_key)` so
  suppressions survive re-scans of the same GitHub URL; alembic migration
  `0005_finding_lifecycle`. `audits.baseline_audit_id` column lets a re-scan
  diff against a prior audit. `app/services/lifecycle.py` exposes a pure
  `diff_against_baseline(current, baseline)` returning new/recurring/resolved
  buckets plus DB-backed `compute_audit_diff` and `active_suppressions`
  (filters expired). Worker `tasks.py` auto-selects the previous succeeded
  audit of the same `source_ref` as the baseline at completion. New routes:
  `POST/GET /v1/audits/:id/suppressions`, `DELETE /v1/suppressions/:id`,
  `PATCH /v1/audits/:id/baseline`, `GET /v1/audits/:id/diff`. The findings
  list now hides suppressed by default (`include_suppressed=true` to show),
  accepts a `lifecycle=new|recurring|resolved` filter, and stamps each row
  with `lifecycle`, `suppressed`, `suppression_reason`. **5 new unit tests
  in `tests/test_lifecycle.py`**; total 134 passing. UI surfacing in next item.
- [x] **Phase 4 #3 — License risk findings via Trivy.** `--scanners` now includes `license`; new `worker/normalize/licenses.py` policy classifier (`LICENSE_POLICY=permissive|strict|copyleft-only`, default permissive) maps SPDX IDs to severity. `worker/scanners/trivy.py` emits a `license/<spdx>` rule-id per non-permissive dependency, MIT/BSD/Apache/etc. are suppressed entirely, and the categorizer routes the prefix to a new "License Risk" category. **100 unit tests passing** (was 81).

### Frontend — skipped / pending by direction

- [x] **Ask-the-Auditor backend hookup beyond demo (streaming).** Anthropic and OpenAI providers grew `stream_json` that yields raw text deltas (`anthropic_provider.py`, `openai_provider.py`). `worker/ai/chat.py` added `answer_stream()` plus a stateful `_AnswerFieldExtractor` that walks the JSON envelope character-by-character and emits only the `answer` field's value as `("token", str)` events, followed by a single `("final", ChatResult)` once safety validation and citation gating run on the full output. New `POST /v1/audits/:id/chat/stream` SSE route in `apps/api/app/routes/chat.py` persists the user turn first, streams `event: token` frames, then `event: done` with the canonical assistant turn + history (so safety-substituted refusals override anything tokens already painted). Frontend `lib/api.ts` gained `streamChat()` using fetch + ReadableStream + manual SSE frame parser (EventSource is GET-only). `components/chat-console.tsx` renders the in-flight stream as a styled "auditor> streaming" draft, then replaces it wholesale on `done`. Cleans up via `AbortController` on unmount.
- [x] **Submission progress / queue position.** New `GET /v1/audits/:id/queue` returns `{ state, phase, active, position?, ahead?, in_flight? }` — position is 1-indexed against `created_at` over `pending` rows, plus a count of `running` audits. `active=false` for terminal states or running audits past the `cloning` phase, so the UI hands off cleanly to the console stream. Frontend `QueueBanner` client component polls every 2.5 s (1.2 s once `position<=1`), with the initial snapshot rendered server-side via `loadQueueStatus` so the page never flashes empty. Banner self-hides when `active=false`. Two visual modes: pending shows `position N` + a stepped progress bar against the closest 10 audits; running/cloning shows a "spinning up" / "cloning repository" placeholder while the worker provisions the sandbox.

These items were carried over from the Phase-2 backend-focused push and are now closed.

### Frontend — added since §16 first written

- [x] **SSE wired into `ConsoleStream`.** Live mode opens an `EventSource` against `/v1/audits/:id/events`, handles `log` and `done` frames, reconnects with exponential backoff capped at 10 s, and surfaces connection state (`connecting · open · done · error`) in the panel header. Demo mode continues to replay the baked tape.
- [x] **Real-data error UI.** A `lib/server.ts` module translates `ApiError(404)` → Next's `notFound()` (which renders the 404 page) and lets everything else propagate to a new `apps/web/app/audits/[id]/error.tsx` boundary. The boundary renders a styled `ECONNREFUSED` or `EINTERNAL` panel with retry, demo, and "go home" actions, and a diagnostic table showing `name / message / digest`.
- [x] **Loading skeleton** at `apps/web/app/audits/[id]/loading.tsx` so audit pages never paint empty during server-side data fetch.
- [x] **PDF export link** in the report view header alongside `report.md` and `report.json`.
- [x] **Pluggable API client error types** — `ApiError` (status + detail) and `ApiUnreachable` (network failure) replace the bare `Error('HTTP %d')` so callers can branch on a typed cause.

---

### Frontend — done

- [x] Next.js 14 (app router) at `apps/web` with the full set of pages outlined in §10.
- [x] Tailwind theme + globals tuned for a **forensic-memory / disassembler aesthetic**: warm-ink background (`#0B0B0A`), bone-paper text (`#D9D3C2`), warm phosphor accent (`#E8C26A`).
- [x] Typography: **JetBrains Mono** as primary face, **IBM Plex Mono** for display moments. No serifs anywhere in product chrome. Editorial serifs were tried (Fraunces + Newsreader) and rejected as off-brand.
- [x] CRT scanline overlay (`body::before`, multiply blend) + radial vignette + faint analog grain. Subtle jitter animation so the screen reads as a live signal.
- [x] Severity chips as `[ CRIT ]` / `[ HIGH ]` / `[ MED ]` / `[ LOW ]` / `[ INFO ]` log-level tags.
- [x] Confidence chips render as stepped EQ-style bars + `conf=hi|md|lo|manual`.
- [x] Reusable `.panel` component with notched `┤ panel_title ├` headers — ncurses-window energy.
- [x] Case header with `0x00000000` address gutter and hex-numbered tabs (`0x00:console`, `0x01:findings`, …).
- [x] Phase timeline rendered as syslog-style ledger with `[████████░░░░]` progress strip and per-phase `[ run · … ]` / `[ ok ]` / `[ waiting ]` status codes.
- [x] Live console styled as `tail -f /dev/audit/console` with 6-hex offsets, microsecond timestamps, and bracketed phase tags. Demo audits replay a baked tape on a 360 ms cadence.
- [x] Findings ledger with offsets (`0x00000000`, `0x00000020`, …), a `$` shell-prompt search box, and severity/category/scanner filter rails.
- [x] Severity ribbon — proportional stacked bar plus a 5-cell grid of 2-digit padded counts with hex sub-addresses.
- [x] **Finding detail page**: the headline visual is a real hex dump (`hexdump -C` style) of the evidence string — offsets, 16-byte rows, and an ASCII gutter, with redacted byte ranges rendered as `▒` glyphs over washed hex pairs. Sections are function-call labels (`explanation()`, `safe_guidance() · defensive only`, etc.).
- [x] Attack-surface page renders six pillars as memory-mapped quadrants with a `[████░░]` magnitude bar; each card links to its top finding and lists the rest.
- [x] Report view has `[exec]` / `[tech]` switch and two export links styled as `$ cat report.md`. The executive view exposes the LLM narrative inside a `// auditor.narrative` block; technical view is a register dump of every finding. OWASP distribution renders as a horizontal `[████░░]` bar table.
- [x] 404 styled as `SIGSEGV: segment not found`.
- [x] Demo mode — visiting any `/audits/demo/...` route renders against a baked fixture (`lib/demo.ts`) with no backend required. Useful for design review and the live screencast.

### Aesthetic direction (canonical statement)

The product reads as a **forensic memory tool / disassembler interface**, not as a SaaS dashboard. Decisions follow from that:

- Mono-first typography. The one decorative move is IBM Plex Mono italics on a single accent phrase per page.
- A single live accent (`#E8C26A`, warm phosphor) — never Hollywood green, never neon cyan, never purple gradients.
- Severity colors remain restrained: cadmium red, amber, olive, slate-green, slate-blue. No saturation spikes.
- Every grouped surface is a notched `.panel`. Every numeric column is `tabular-nums`. Every address is hex.
- The redaction primitive is the visual contract of the product. It is the same mnemonic on every surface (chip, hex-dump byte range, evidence block) so users learn: *we saw it, you don't see it, the model doesn't see it.*

### Deviations from §10 (Frontend) worth knowing

- The originally planned `phase-timeline` punch-card cells were replaced with a vertical syslog ledger. Vertical scans better at narrow widths and matches the "log file" mental model.
- `attack-surface-grid` shipped six pillars (the doc said five plus "cloud/IaC"); cloud is folded into the `infra_iac` pillar to avoid sparse cells on small repos.
- `Ask-the-auditor` chat page exists and can call the backend; streaming replies are intentionally deferred.
- The old Phase 1 SSE/demo-tape note is obsolete: `ConsoleStream` now consumes the real `/events` stream in live mode and keeps the demo tape only for `/audits/demo`.

---

## 17. Phase 4 backlog (ordered)

The single source of truth for the Phase 4 work. Items are ordered by
leverage-per-unit-effort; later items often assume earlier ones are
done. Tick each one when its PR lands, and add a one-line note pointing
at the modules touched — same convention as §16.

1. [x] **Git-history secret scanning.** `clone.py` drops `--depth=1`
   by default for the *selected branch only* — the clone is still
   `--single-branch --no-tags`, so non-default branches and tags are
   not walked. `CLONE_DEPTH` env restores shallow. `gitleaks.py`
   walks git log when the **host** `.git` dir is present (the
   orchestrator passes `host_repo_path` so detection runs on the
   worker, not the container-side `/repo`); falls back to `--no-git`
   for ZIP intake. Parser captures `Commit / Author / Date / Message`
   and tags historical hits in the title.
2. [x] **EPSS / KEV enrichment.** `threat_intel` table + alembic
   migration `0004`; nightly `worker.tasks.refresh_threat_intel` beat
   task pulls EPSS CSV + CISA KEV JSON; `enrich_with_threat_intel`
   step runs after `normalize_findings` in `tasks.py`. `Finding`
   gains `epss_score`, `epss_percentile`, `kev` fields (Pydantic +
   JSON schema + SQLAlchemy + DDL). UI surfacing deferred to item #12.
3. [x] **License risk findings.** Trivy `--scanners` now includes
   `license`; new `worker/normalize/licenses.py` classifier maps SPDX
   IDs to severity by `LICENSE_POLICY` env (`permissive` default /
   `strict` / `copyleft-only`). `worker/scanners/trivy.py` emits
   `license/<spdx>` rule-IDs; permissive licenses are suppressed so
   the ledger doesn't drown. Categorizer recognizes the prefix as
   "License Risk".
4. [x] **Finding lifecycle (suppression + baseline diff).** Backend
   landed: `suppressions(source_ref, dedupe_key, reason, actor,
   expires_at)` keyed by `source_ref` so suppressions survive re-scans;
   `audits.baseline_audit_id` (auto-set by worker to previous
   succeeded audit of same source_ref). `app/services/lifecycle.py` +
   routes for suppression CRUD, baseline PATCH, and a `/diff` endpoint
   returning new/recurring/resolved buckets. Findings list hides
   suppressed by default and stamps each row with `lifecycle`,
   `suppressed`, `suppression_reason`. Alembic `0005_finding_lifecycle`.
   UI surfacing tracked as its own sub-item below.
5. [x] **Diff / PR mode scanning.** `audits.base_sha` + `audits.head_sha`
   (alembic `0006_pr_mode`) accepted on `POST /v1/audits/json`. Worker
   calls `worker/pr_mode.compute_changed_lines` after normalization and
   `filter_findings_by_diff` intersects findings with the head-side
   line ranges. Adapter inputs are unchanged on purpose — narrowing
   pre-scan would lose taint-flow and history signal; we filter post.
   Repo-wide findings (no line context) survive on a file-match.
6. [x] **Custom org policy rules.** `SEMGREP_CUSTOM_RULES_DIR` env
   bind-mounts a host directory of `*.yaml` rules at `/custom-rules`
   read-only and the Semgrep adapter appends `--config /custom-rules`
   after the default packs. Runner gained an `extra_mounts` parameter
   (validates against `/repo`/`/out`/`/tmp` collisions). Remote rule
   URLs must be pre-fetched — sandbox stays `--network=none`.
7. [x] **Compliance control mapping.** `worker/normalize/compliance.py`
   maps `(category, cwe)` → SOC2 / PCI-DSS / HIPAA / ISO27001 control
   IDs (category baseline + CWE-level overrides, merged without
   duplicates). `Finding.compliance: dict[str, list[str]]` (alembic
   `0007_compliance`); surfaced on findings list/detail JSON, technical
   Markdown report, and chat reconstructor. Dedicated compliance report
   view (SOC2 evidence packet etc.) lives in Phase 5 #22.
8. [x] **Reachability filtering on dependency findings.** Python
   (`ast`) + JS/TS (regex) import-graph collectors. Dep findings whose
   package isn't imported anywhere get `reachable=False` and severity
   demoted one rung; non-dep findings pass through. UI hides them by
   default behind a count pill. This is the noise-reduction floor of
   the product — call-graph reachability is deferred (not cost-effective
   in a generalist tool).
9. [ ] **API spec analysis.** Detect OpenAPI / GraphQL schemas in the
   repo profile; new scanner adapter that flags missing auth on
   routes, PII overexposure in response shapes, and unsafe verbs on
   sensitive paths.
10. [ ] **AI/ML risk scanners.** Detect prompt-injection-prone prompt
    templates, exposed model weights / training data, and unsafe
    `eval`/`exec` over LLM output. A small Semgrep ruleset is the cheap
    starting point.
11. [—] **CSPM (live cloud audit).** [DEFERRED — off the indie line;
    see [ROADMAP.md](ROADMAP.md).] Optional read-only AWS/GCP
    credential at intake → adapter runs `prowler`/`steampipe`-style
    checks against the cloud account, output normalized into the same
    finding schema. Behind `ENABLE_CSPM=true`. Needs the secrets and
    operational story of a hosted service to be worth doing.
12. [x] **Threat-intel UX surfacing.** Findings ledger gained `[ KEV ]`
    + `EPSS=` chips per row (EPSS only when ≥0.5 to keep the ledger
    quiet) and a `[ KEV ] cisa kev hits · N` filter pill. Top-of-page
    callout when KEV count > 0. Finding detail surfaces KEV/EPSS chips
    next to CVE plus the compliance.controls() panel.
13. [ ] **Human-in-the-loop review.** Analyst can annotate findings,
    override severity / confidence with a justification, and "attest"
    to a finding before report export. New `finding_annotations` table;
    report renders attested findings differently.
14. [—] **Branch protection / repo hygiene audit.** [DEFERRED — needs
    OAuth; see [ROADMAP.md](ROADMAP.md).] Pulls repo settings
    (required reviews, signed commits, force-push protection,
    secret-scanning enabled) and emits findings for non-compliant
    defaults.
15. [ ] **SBOM generation (CycloneDX + SPDX).** Per-audit SBOM artifact
    emitted by Trivy (`trivy sbom`) and persisted as a `reports` row
    with `format=cbom` / `format=spdx`. Surface on the report view as a
    download alongside the existing JSON/MD/PDF links.
16. [ ] **VEX intake.** Users can attach an OpenVEX or CycloneDX-VEX
    document to an audit (or per repo). Findings whose CVE is marked
    `not_affected` / `fixed` in the VEX doc are suppressed automatically
    with a justification line. Complements #4 — VEX is the upstream-
    vendor version of suppression.
17. [x] **SARIF export.** `apps/api/app/services/sarif.py` →
    `format=sarif` on the report route, one run per source_tool,
    GitHub-Code-Scanning-compatible `security-severity` property,
    CWE helpUri, compliance tags, KEV/EPSS propagation,
    `partialFingerprints.dedupeKey/v1` for cross-scan matching.
18. [x] **CSV / XLSX export of findings.** `GET /v1/audits/:id/findings/export`
    with `format=csv|xlsx`. Frozen append-only `COLUMNS` list, compliance/
    KEV/EPSS/lines flattened, XLSX via optional openpyxl (503 if missing).
19. [ ] **Side-by-side audit comparison view.** Builds on #4's diff
    service. UI page that takes two audit IDs and renders a 3-column
    diff (new / recurring / resolved) with severity deltas. Useful for
    release-over-release reviews.
20. [ ] **DAST module (large).** Optional dynamic scanner adapter that
    crawls a running target (URL + optional auth recipe), runs ZAP
    baseline + active scans inside the sandbox, and normalizes the
    output into the unified finding schema. Behind `ENABLE_DAST=true`.
    Scope-flag: this is multi-week and may split into its own backlog.

**Discipline rule.** Each item ships as one PR with its own tests. If
work on an item surfaces something that belongs to another item, write
it down here as a sub-bullet — don't grow the current PR.

---

## 18. What's next (indie-OSS direction)

The project's active line is **indie OSS** — a self-hostable audit
tool for solo devs, small teams, and security consultants. The full
roadmap (including paths intentionally not on this line, like multi-
tenant orgs / SSO / billing) lives in [ROADMAP.md](ROADMAP.md). What
follows is the short list that's on the active path.

Same discipline as §17: one PR per item, with tests. Items below are
ordered by leverage; later items can assume earlier ones are done.

1. [ ] **VS Code extension.** Inline annotations on findings in the
   open file, "explain this finding" sidebar calling the chat
   endpoint, status-bar item for the latest audit on this branch.
   Talks to the same `localhost:8000` API the CLI uses.
2. [x] **GitHub Action** (no GitHub App). Composite action at the
   repo root (`action.yml`); other repos use it with
   `uses: ayaanmaliksgithub/virgil@v0.1.0`. Spins up the compose stack
   on the runner, builds the scanner image, waits for `/healthz`, runs
   `virgil scan` with PR-mode SHAs auto-detected from the event
   payload, posts a sticky priority-queue comment, uploads SARIF as an
   artifact. Copy-paste example in
   [`examples/github-action-virgil.yml`](examples/github-action-virgil.yml).
3. [ ] **SBOM generation** (CycloneDX + SPDX). Trivy already supports
   `trivy sbom`; we just need to invoke + persist the artifact as a
   `reports` row. One-day item.
4. [ ] **VEX intake.** Users attach OpenVEX / CycloneDX-VEX docs to an
   audit; findings whose CVE is marked `not_affected` / `fixed`
   auto-suppress with the upstream justification carried through.
5. [ ] **Audit comparison view.** Builds on the existing diff service
   (§17 #4). New page that takes two audit IDs and renders a 3-column
   diff (new / recurring / resolved) with severity deltas.
6. [ ] **More reachability languages.** PHP, Rust, C# next. Same
   shape as the existing collectors — ~30 lines each plus a `_looks_*`
   helper.
7. [ ] **API spec analysis** (§17 #9 carried forward). Detect OpenAPI /
   GraphQL schemas in the profile; flag missing auth on routes, PII
   overexposure, unsafe verbs.
8. [ ] **AI/ML risk scanners** (§17 #10 carried forward). Detect
   prompt-injection-prone templates, exposed model weights, unsafe
   `eval`/`exec` over LLM output. Starts as a Semgrep rule pack.
9. [ ] **"Why did you flag this?" trace.** Every LLM-surfaced line on
   a finding gets a hover-trace back to the deterministic artifact
   (rule id, file/line, raw scanner output). Reinforces §1's
   grounding rule visually.
10. [ ] **Sample audit on first launch.** New install seeds the DB
    with a pre-baked OWASP NodeGoat audit so `localhost:3000` is
    never empty on first visit.
11. [~] **`pipx install virgilhq` distribution.** CLI `pyproject.toml`
    has full PyPI metadata (classifiers, urls, keywords, README) and a
    `.github/workflows/publish-cli.yml` workflow publishes on tagged
    release via PyPI Trusted Publishing (OIDC, no API token). PyPI
    project name is **`virgilhq`** — bare `virgil` was taken on PyPI
    before we got there; the CLI binary remains `virgil`. One-time
    Trusted Publisher registration on PyPI is the only remaining step
    before the first `pip install virgilhq` works. Homebrew formula
    follows once the PyPI package has stabilized.
12. [ ] **Documentation site.** A simple static site (`docs/`) with
    install, scanner tour, FAQ, screenshot gallery. README does
    double-duty today; a docs site reduces friction for new visitors.

Items punted from the active line (auth, orgs, SSO, billing,
portfolio, SAML, audit log) live in [ROADMAP.md](ROADMAP.md) as
"off the current path." They are designed but not in flight.

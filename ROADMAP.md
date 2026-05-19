# Roadmap

This file documents two roadmaps: the **active line** (what we're
building now) and the **off-path** items (designed but not in flight,
documented so contributors who want to take one on have a reference).

The project's current line is **indie OSS** — a self-hostable audit
tool. Items that require multi-tenant infrastructure (orgs, SSO,
billing, audit log, etc.) are intentionally *not* on the active line.
They're listed below in case a contributor or sponsor wants to take
one on, but the maintainers' time is going elsewhere.

---

## Active line — indie OSS

The short list lives in [ARCHITECTURE.md §18](ARCHITECTURE.md#18-whats-next-indie-oss-direction).
It's mirrored here so this file alone is a complete tour. Tick items
as their PRs land.

### Distribution + DX

- [ ] VS Code extension (inline annotations + chat sidebar)
- [x] Reusable GitHub Action workflow (no GitHub App needed) — composite
      action at repo root, copy-paste example at
      `examples/github-action-virgil.yml`
- [~] `pipx install virgilhq` on PyPI — metadata + OIDC publish workflow
      shipped; pending one-time Trusted Publisher registration on PyPI.
      Package name is `virgilhq` (bare `virgil` was already taken on PyPI);
      CLI binary is still `virgil`. Homebrew once stable.
- [ ] Static docs site (`docs/`)
- [x] First-launch demonstration — one-click "run sample scan" button
      submits OWASP NodeGoat (override via `NEXT_PUBLIC_DEMO_SCAN_URL`)
      through the live pipeline. Every finding is real scanner output.
      `docker compose up` is now one command (scanner-image-builder is
      a worker dependency). The TS-fixture `/audits/demo` route is
      kept for design review and clearly labeled as such.

### Analysis depth

- [ ] SBOM generation (CycloneDX + SPDX, via Trivy)
- [ ] VEX intake — auto-suppress on `not_affected` / `fixed`
- [ ] Audit comparison view (3-column new/recurring/resolved)
- [ ] More reachability languages: PHP, Rust, C#
- [ ] API-spec analysis (OpenAPI / GraphQL)
- [ ] AI/ML risk Semgrep rule pack

### UX

- [x] "Why did you flag this?" trace — each LLM prose block on the
      finding detail page carries a `└─ from <scanner>:<rule> · file:Lline ¶ trace`
      footer; the sidebar's old prose "provenance" block was replaced
      by a structured panel listing every deterministic artifact the
      LLM was grounded in (scanner+rule, file+lines, evidence, CWE
      → mitre.org, CVE → nvd.nist.gov + KEV/EPSS, OWASP, code context
      anchor). Footer cleanly distinguishes LLM-described vs.
      scanner-only audits.
- [ ] Inline finding diff on the audit comparison view
- [ ] Bulk-suppress from cluster row (one justification, N rows)

### Inviolable constraints (these are *not* roadmap items — they are
the line that makes the project the project)

- No payload generation, no exact patches, no step-by-step
  reproduction — in any feature, ever.
- Sandbox isolation flags
  (`--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges`)
  are not weakened.
- The redactor runs before persistence and before any LLM prompt.
  New code paths that send finding data to an LLM must go through it.
- No telemetry, no analytics tracker, no usage ping. The project
  never phones home.

---

## Off the current path

These are real product directions, designed in some detail, that the
active line is *not* pursuing. They're documented so anyone who
wants to fork or contribute toward them has a starting blueprint —
but they pull the project toward multi-tenant SaaS, which the current
maintainers aren't building.

### Auth & multi-tenancy

- **GitHub OAuth browser flow.** Replaces the `github_token` paste
  with a proper OAuth handoff. Token storage already exists
  (`audit_secrets`); the missing piece is the browser callback +
  signed session cookies.
- **Orgs, teams, roles.** Multi-tenant data model: `orgs`, `teams`,
  `org_members`, `audits.owner_org_id`. Roles `owner` / `admin` /
  `member` / `viewer`. Every existing route would need to be scoped
  by `owner_org_id`. Migration burden is high — every existing query
  filters by `audit_id` today, which would become `org_id ∧
  audit_id`.
- **SAML / OIDC SSO.** Required by any enterprise buyer. Falls back
  to GitHub OAuth for individual accounts.
- **Audit log of viewer / exporter actions.** Compliance ask: record
  who viewed / exported / suppressed what, retention configurable.
  New `org_audit_log` table; every state-changing route writes a row.

### Portfolio (depends on orgs)

- **Portfolio dashboard.** Top-N riskiest repos, severity trend over
  30/90 days, MTTR per team, KEV exposure across the portfolio.
- **Cross-repo search.** "Show me every place we have an exposed AWS
  key" across every audit in the org. Materialized view of
  latest-per-repo findings.
- **Asset inventory.** Searchable inventory of services, deps, and
  secret types across all scanned repos. "What would Log4Shell hit?"
  lookup.
- **Per-team severity SLAs.** Teams declare "Criticals in 7d, Highs
  in 30d." Dashboards highlight breaches.

### Workflow integrations (most depend on orgs)

- **GitHub App + PR check + inline comments.** A real GitHub App
  (vs. the reusable Action on the active line) that installs on a
  repo and posts inline PR comments. Needs OAuth + installation
  tokens. The Action workflow on the active line covers the same
  use-case without the org infrastructure.
- **Slack / Teams app.** Audit-complete notifications, daily digest
  of new Criticals, slash-command Ask-the-Auditor. Needs per-org
  webhook endpoints to be useful at scale.
- **Jira / Linear / GitHub Issues sync.** Create ticket from finding,
  ticket close pings a webhook that flips the finding to `resolved`.

### Collaboration

- **Comments / threads on a finding** with `@mentions` and
  notification routing.
- **Assignment + due date** per finding.
- **Per-finding severity / confidence override** with audit-trail
  justification (overlaps §17 #13 human-in-the-loop).
- **Share-finding signed links.** Time-limited signed URL for an
  external auditor / contractor.

### Reporting upgrades

- **White-label + customer logo on cover** (PDF + Markdown).
- **Customizable report templates** — exec 1-pager, board deck, full
  technical, SOC2 evidence packet.
- **Per-team report breakdown** keyed off CODEOWNERS or assignment.
- **Public status page** — uptime + scanner versions, doubles as a
  trust signal.

### Chat polish

- **Cross-audit chat.** Ask about the whole portfolio, not just one
  audit. Retriever expands across all org audits with permission
  filtering.
- **Saved + named + shareable chat sessions.**

### Onboarding & growth

- **Guided first-audit tour.** Five-step in-app tour.
- **In-app changelog.** "Newly added rules / scanners since your
  last visit."
- **Retroactive new-rule alert.** When a new rule pack lands,
  background job re-scans the latest audit per repo and alerts on
  *new* findings the new rule would catch.

### Billing (only if monetizing)

- **Usage quotas.** Per-org caps on audits/month, repo size, LLM
  tokens.
- **Subscription tiers + Stripe.** Free / Team / Org.
- **Per-org LLM provider override.** Paid orgs bring their own
  Anthropic / OpenAI key.

### Pre-prod hardening (if running a hosted instance)

The indie path explicitly does not run hosted infrastructure. If
someone forks this and wants to: rate limiting (`slowapi`), TLS at a
reverse proxy, externalized secrets, real S3 instead of MinIO,
Sentry, healthcheck endpoints that ping DB+Redis+S3, Postgres backup
runbook.

---

## How to take something off the back burner

If you want to ship one of the "off the current path" items:

1. Open an issue tagged `enterprise-track` describing the slice you
   want to build and your timeline.
2. Be aware: items here are designed against the project's existing
   architecture but haven't been re-validated against the most
   recent changes. Some will have drifted.
3. The non-negotiable rules in [ARCHITECTURE.md §1](ARCHITECTURE.md#1-product-principles)
   and [CONTRIBUTING.md](CONTRIBUTING.md) still apply — no exploit
   content, no sandbox weakening, no telemetry, redactor stays in
   the path.

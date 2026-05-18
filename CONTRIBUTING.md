# Contributing

Thanks for considering a contribution. This file covers the local dev
loop, what kinds of changes are welcome, and the one project-wide rule
that's not negotiable.

## The non-negotiable rule

This is an **audit** platform, not an exploit platform. Patches that
add capabilities for any of the following will be closed without
discussion:

- generating exploit payloads or proof-of-concept attacks
- generating exact code patches or auto-fix PRs
- generating step-by-step attack reproduction
- removing or weakening the safety validator, the redactor, or the
  sandbox isolation flags

We will gladly accept PRs that improve the **finding signal**
(scanners, normalizers, reachability, clustering), the **defensive
narrative** (better high-level guidance, compliance mapping), the
**developer experience** (CLI, docs, perf), or the **infrastructure
hygiene** (sandbox hardening, tests, CI).

If you're unsure whether your idea fits, open a discussion before
writing code.

## Local dev

Prereqs: Python 3.11+, Node 20+, Docker (Compose v2), ~6 GB free RAM.

### Backend / worker

```bash
# from repo root
python3 -m pip install --user --break-system-packages \
    -e packages/audit_core \
    -e apps/api \
    -e apps/worker \
    -e apps/cli

# run the unit suite (no Postgres needed)
pytest tests/ --ignore=tests/api --ignore=tests/e2e
```

The 254 unit tests run in under a second and cover the normalizer,
safety validator, reachability, clustering, priority list,
suggested questions, fix-the-helper, lifecycle, exports, and the
CLI. They do NOT need Docker, Postgres, or an LLM key.

### API integration tests

```bash
# spin up Postgres separately, then:
TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/test_audit \
    pytest tests/api
```

### Frontend

```bash
cd apps/web
npm install
npm run dev          # http://localhost:3000
npx tsc --noEmit     # typecheck
```

### Full stack via Compose

```bash
docker compose up scanner-image-builder
docker compose run --rm api alembic upgrade head
docker compose up -d
```

## Writing tests

Every PR should ship tests. The patterns we use:

- **Unit tests** at `tests/test_*.py` for pure functions. No DB, no
  Docker, no network. These are the fastest signal — most of the
  254 tests are this shape.
- **Stubbed-row tests** when you need to exercise serializer or
  service code that takes a SQLAlchemy model — use the
  `StubFindingRow`/`StubAudit` dataclass pattern in
  `tests/test_threat_intel_serialization.py` as a template.
- **API integration tests** at `tests/api/` for route-level
  behavior. Skipped unless `TEST_DATABASE_URL` is set.
- **Compose smoke** at `tests/e2e/test_compose_smoke.py` — opt-in
  via `RUN_COMPOSE_SMOKE=1`.

If you're adding an LLM-touching feature, write the deterministic
fallback path AND test it. The product runs without an LLM key by
design; PRs that regress that get bounced.

## Code style

- Python: standard library first, third-party second, local imports
  last. No new dependencies without a discussion.
- Comments explain *why*, not *what*. The codebase leans on naming
  + structure for the *what*; comments are reserved for hidden
  constraints, surprising invariants, or "we tried X, didn't
  work, here's why we ended up at Y."
- Don't add docstrings that just restate the function name. If a
  function is self-explanatory, no docstring is correct.
- Frontend: TypeScript, strict mode, `tsc --noEmit` must pass.
- No emoji in code or commit messages unless explicitly relevant.

## Submitting a PR

1. Fork and create a branch.
2. Make the change. Add tests.
3. Run `pytest tests/ --ignore=tests/api --ignore=tests/e2e` —
   must pass.
4. For frontend changes: `cd apps/web && npx tsc --noEmit` —
   must pass.
5. Update `ARCHITECTURE.md` if you changed an externally-visible
   contract (route shape, schema, env var, scanner pipeline order).
6. Open the PR. Describe **what changed and why**. Skip "what
   I did" line-by-line — the diff has that.

## Reporting bugs

Open an issue with:

- What you ran (CLI invocation, web action, API call).
- What happened (error message, unexpected behavior).
- What you expected.
- A minimal repro if possible.

For security issues *in the project itself* (sandbox escape, secret
leak path, redactor bypass), please email rather than file publicly.
See [SECURITY.md](SECURITY.md) once it's added.

## License

By submitting a contribution, you agree it will be licensed under the
Apache License 2.0 — see [LICENSE](LICENSE).

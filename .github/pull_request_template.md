## What changed

One or two sentences. The diff has the rest.

## Why

The motivation, not the implementation.

## Checklist

- [ ] Unit tests added/updated (`pytest tests/ --ignore=tests/api --ignore=tests/e2e`)
- [ ] If a route shape, schema, env var, or pipeline order changed:
      `ARCHITECTURE.md` updated
- [ ] If a frontend file changed: `cd apps/web && npx tsc --noEmit` passes
- [ ] No new dependency added — or, if added, justified above
- [ ] No exploit content (payloads, exact patches, step-by-step
      reproduction) added anywhere in the codebase

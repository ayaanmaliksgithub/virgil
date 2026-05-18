# virgil

> Terminal client for [Virgil](https://github.com/ayaanmaliksgithub/virgil) —
> self-hosted security audit with the triage built in. Real scanners +
> clustering + LLM priority queue + code-grounded chat.

The CLI is a thin shell over a running Virgil API. It bundles your working
directory, submits a scan, streams progress, and prints the ranked findings
with CI-friendly exit codes.

## Install

```bash
pip install virgil          # or: pipx install virgil
```

You'll also need a running Virgil instance. The standard self-hosted setup
is `docker compose up` from the [main repo](https://github.com/ayaanmaliksgithub/virgil)
— takes about a minute the first time.

## Usage

```bash
# Scan the current directory and wait for the result.
virgil scan .

# Scan a GitHub URL instead of a local path.
virgil scan --url https://github.com/OWASP/NodeGoat

# PR mode — only flag findings on lines changed between two SHAs.
virgil scan . --base-sha abc1234 --head-sha def5678

# Don't wait for the scan to finish; print the audit ID and return.
virgil scan . --no-wait

# Check on a previously-submitted scan.
virgil status <audit-id>

# Print the findings table for a completed scan.
virgil findings <audit-id>

# Fetch the report in any supported format.
virgil report <audit-id> --format md
virgil report <audit-id> --format sarif -o findings.sarif
virgil report <audit-id> --format json
virgil report <audit-id> --format pdf
```

## CI integration

```bash
virgil scan . --fail-on critical     # exits 1 on any Critical
virgil scan . --fail-on high         # exits 1 on Critical or High
virgil scan . --fail-on never        # always exits 0
```

Exit codes:

| Code | Meaning |
| ---: | --- |
| `0` | scan finished, no findings exceeded `--fail-on` |
| `1` | scan finished, findings exceed the configured threshold |
| `2` | the audit itself failed (clone error, scanner crash, etc.) |
| `3` | could not reach the Virgil API |

## Environment

| Variable | Default | What it does |
| --- | --- | --- |
| `VIRGIL_API` | `http://localhost:8000` | API base URL. Set to a remote URL to scan against a non-local instance. |

## What the output looks like

```
$ virgil scan .
bundle /work/myrepo → zip → submit
┌─ [ virgil ] ───────────────────────────────────────────────────────────────┐
│ audit_id  c9b1…                                                            │
│ source    scan.zip                                                         │
│ state     succeeded  phase=completed                                       │
└────────────────────────────────────────────────────────────────────────────┘

 CRIT  HIGH  MED   LOW   INFO  KEV  unreach
   2     7    14    6     3     1     19

╭─ [ fix.this_week() · ranked ] ─────────────────────────────────────────────╮
│ #01 [ CRIT ]  Hard-coded AWS access key in source  ×3                      │
│      Critical credential exposure with CISA-KEV-adjacent risk profile…     │
│ #02 [ HIGH ]  SQL injection via raw query helper  ×12                      │
│      12 callsites share src/db/query.py — fix the helper, not callsites.   │
╰────────────────────────────────────────────────────────────────────────────╯
```

## License

Apache-2.0. See [LICENSE](https://github.com/ayaanmaliksgithub/virgil/blob/main/LICENSE).

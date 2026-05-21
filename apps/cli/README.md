# virgil

> Terminal client for [Virgil](https://github.com/ayaanmaliksgithub/virgil) —
> self-hosted security audit with the triage built in. Real scanners +
> clustering + LLM priority queue + code-grounded chat.

The CLI is a thin shell over a running Virgil API. It bundles your working
directory, submits a scan, streams progress, and prints the ranked findings
with CI-friendly exit codes.

## Install

`virgil` is a CLI tool, so the right installer is **pipx** — it puts the
binary on your `$PATH` and isolates the dependencies from your system Python:

```bash
pipx install virgilhq
```

Don't have pipx yet? Either install it once, or fall back to user-mode pip:

```bash
# macOS
brew install pipx && pipx ensurepath

# Linux / other
python3 -m pip install --user pipx && pipx ensurepath

# Fallback if you don't want pipx at all:
python3 -m pip install --user virgilhq
```

The PyPI package is `virgilhq` (the bare `virgil` name was already taken).
The command on your `$PATH` is still just `virgil`.

> **Why pipx and not `pip install`?** Modern Python distributions
> (Homebrew Python, Debian/Ubuntu's python3, etc.) mark the system
> interpreter as externally managed per
> [PEP 668](https://peps.python.org/pep-0668/) — a bare `pip install`
> errors out. `pipx` quietly handles the venv for you, which is what
> you want for CLI tools anyway: each one gets its own isolated
> environment so a `virgil` upgrade can't break some other tool.

You'll also need a running Virgil instance. The standard self-hosted setup
is `docker compose up` from the [main repo](https://github.com/ayaanmaliksgithub/virgil)
— takes about a minute the first time. The CLI's defaults
(`http://localhost:8000` for the API, `http://localhost:3000` for the
web app) match that setup exactly, so no config is needed.

If you're pointing at a remote Virgil instead:

```bash
virgil config set api_url=https://virgil.example.com/api
virgil config set web_url=https://virgil.example.com
```

## Usage

```bash
# Scan and land on triage (counts → ranked clusters → next-steps hint).
virgil scan .                                 # local directory
virgil scan                                   # …also defaults to the cwd
virgil scan github.com/OWASP/NodeGoat         # remote, bare host
virgil scan OWASP/NodeGoat                    # remote, GitHub shorthand
virgil scan https://github.com/OWASP/NodeGoat # remote, full URL

# Land on a different surface after the scan finishes.
virgil scan . --show report                   # exec narrative
virgil scan . --show surface                  # languages / frameworks / IaC profile
virgil scan . --show ask_virgil               # drop into the chat REPL pre-flighted

# PR mode — only flag findings on lines changed between two SHAs.
virgil scan . --base-sha abc1234 --head-sha def5678

# Don't wait for the scan to finish; print the audit ID and return.
virgil scan . --no-wait

# After a scan, drill in:
virgil clusters <audit-id>               # every cluster, sorted by severity
virgil clusters <audit-id> --sev high    # filter
virgil cluster  <audit-id> <key>         # one cluster in detail (prefix match ok)
virgil findings <audit-id>               # raw findings table
virgil chat     <audit-id>               # interactive Q&A grounded in this audit
virgil chat     <audit-id> -m "what's the worst finding?"   # one-shot
virgil open     <audit-id>               # launch the web app on the triage tab
virgil open     <audit-id> --page chat   # …or chat / findings / report / attack-surface
virgil status   <audit-id>

# Reports in any supported format.
virgil report <audit-id> --format md
virgil report <audit-id> --format sarif -o findings.sarif
virgil report <audit-id> --format json
virgil report <audit-id> --format pdf
```

## Config

Persistent settings live in `~/.config/virgil/config.json`:

```bash
virgil config show
virgil config set api_url=https://virgil.example.com/api
virgil config set web_url=https://virgil.example.com
virgil config set default_fail_on=high
virgil config set default_post_scan_view=ask_virgil     # triage | report | surface | ask_virgil
virgil config unset default_fail_on
virgil config path
```

Resolution order for each setting: **env var → config file → built-in default.**

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
| `VIRGIL_API` | `http://localhost:8000` | API base URL. |
| `VIRGIL_WEB` | `http://localhost:3000` | Web app base URL used by `virgil open`. |
| `VIRGIL_FAIL_ON` | `critical` | Default `--fail-on` threshold for `virgil scan`. |
| `VIRGIL_SHOW` | `triage` | Default `--show` surface after `virgil scan` (`triage` / `report` / `surface` / `ask_virgil`). |
| `VIRGIL_CONFIG_DIR` | `~/.config/virgil` | Override the config directory. |

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

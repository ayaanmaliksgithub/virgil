"""Reachability analysis for dependency findings (Phase 4 §17 #8).

The single biggest signal-to-noise problem in any SCA tool: most
"vulnerable dependency" findings live in transitive packages that the
user's code never touches. Treating those identically to a CVE in the
hot path teaches users to ignore the whole feed.

This module walks the source tree, collects the set of top-level
package names actually imported, and joins that against
dependency-finding `raw.pkg` values. Findings whose package is not
imported are marked `reachable=False` and their severity drops one
level — they stay in the ledger (some orgs need to track lockfile
exposure for compliance) but sort to the bottom and don't drown the
real signal.

What this is NOT:
  * A call-graph reachability check. We answer "is the package imported
    anywhere?", not "is the *vulnerable function* called?". The former
    cuts 60–80% of dep noise in practice; the latter is per-CVE work
    that would multiply by every package version pair and is not
    cost-effective in a generalist audit tool.
  * A guarantee. AST parsing fails open: any file the parser can't
    handle conservatively contributes nothing to the import set, but
    the join still requires at least one source file to have been
    parsed for the language. If the parser saw nothing, we abstain
    (return `None`) rather than wrongly mark everything unreachable.

Languages covered:
  * Python — `ast` module, handles `import X`, `from X import …`,
    `from X.sub import …`.
  * JavaScript / TypeScript — regex over `import … from "X"`,
    `require("X")`, dynamic `import("X")`. Tolerates JSX/TSX.
  * Go — `import "path/to/pkg"` (single + grouped). Reports the full
    import path; reachability lookup matches Trivy's `pkg` field
    (Trivy reports e.g. `github.com/dgrijalva/jwt-go`).
  * Ruby — `require "gem"` / `require_relative` / `gem "name"`.
  * Java / Kotlin — `import package.Class;`. Reports the package, not
    the class. Coarse but useful: Trivy reports Maven coords like
    `com.fasterxml.jackson.core:jackson-databind`, and we match by
    the group-id prefix.

Other languages return `None` (skip), which leaves dep findings at
their raw severity. Extending: add a collector + a `_looks_*` check.
"""
from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from audit_core import Finding, Severity

log = logging.getLogger(__name__)

# Files we never read — vendored directories, build output, lockfiles
# themselves (already represented by the dep manifest), and binary blobs
# that would only slow the walk.
_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", "target", ".next", ".tox", "site-packages",
    "vendor", "third_party", "coverage", ".pytest_cache",
}

# Per-language file extension → collector function.
# Collectors return the set of TOP-LEVEL package names referenced; the
# join key matches Trivy's `pkg` field.
_PY_SUFFIXES = (".py",)
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
_GO_SUFFIXES = (".go",)
_RB_SUFFIXES = (".rb",)
_JAVA_SUFFIXES = (".java", ".kt", ".kts")

# Severity demotion ladder. `reachable=False` drops one rung; nothing
# falls off Informational.
_DEMOTE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFORMATIONAL,
    Severity.INFORMATIONAL: Severity.INFORMATIONAL,
}


@dataclass(frozen=True)
class ImportIndex:
    """The set of imported top-level package names per language.

    `<lang>_seen_files` is >0 once the walker has parsed at least one
    file of that language — used to decide whether we have enough
    signal to assert reachability for a given finding (no signal =
    abstain = leave `reachable=None`).
    """
    python: frozenset[str]
    javascript: frozenset[str]
    go: frozenset[str]
    ruby: frozenset[str]
    java: frozenset[str]
    python_seen_files: int
    javascript_seen_files: int
    go_seen_files: int
    ruby_seen_files: int
    java_seen_files: int


def build_import_index(repo_path: Path, *, max_files: int = 5000) -> ImportIndex:
    """Walk the repo and collect imported top-level package names."""
    py: set[str] = set()
    js: set[str] = set()
    go: set[str] = set()
    rb: set[str] = set()
    java: set[str] = set()
    py_n = js_n = go_n = rb_n = java_n = 0
    seen = 0

    if not repo_path.exists() or not repo_path.is_dir():
        return ImportIndex(
            frozenset(), frozenset(), frozenset(), frozenset(), frozenset(),
            0, 0, 0, 0, 0,
        )

    for path in _iter_source_files(repo_path):
        if seen >= max_files:
            log.info("reachability walker hit max_files=%d cap", max_files)
            break
        seen += 1

        suffix = path.suffix.lower()
        try:
            if suffix in _PY_SUFFIXES:
                py.update(_python_imports(path))
                py_n += 1
            elif suffix in _JS_SUFFIXES:
                js.update(_js_imports(path))
                js_n += 1
            elif suffix in _GO_SUFFIXES:
                go.update(_go_imports(path))
                go_n += 1
            elif suffix in _RB_SUFFIXES:
                rb.update(_ruby_imports(path))
                rb_n += 1
            elif suffix in _JAVA_SUFFIXES:
                java.update(_java_imports(path))
                java_n += 1
        except Exception as e:  # parser bugs must never break the scan
            log.debug("reachability skip %s: %s", path, type(e).__name__)
            continue

    return ImportIndex(
        frozenset(py), frozenset(js), frozenset(go), frozenset(rb), frozenset(java),
        py_n, js_n, go_n, rb_n, java_n,
    )


_ALL_SUFFIXES = _PY_SUFFIXES + _JS_SUFFIXES + _GO_SUFFIXES + _RB_SUFFIXES + _JAVA_SUFFIXES


def _iter_source_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        # Skip if any path part is in the deny list. Cheap O(depth) check.
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in _ALL_SUFFIXES:
            yield path


def _python_imports(path: Path) -> set[str]:
    """Parse a Python file with `ast` and return imported top-level packages."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except SyntaxError:
        return set()
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.add(_top_level(alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:  # ignore relative imports
                out.add(_top_level(node.module))
    return out


# JS/TS import / require / dynamic-import patterns. We deliberately don't
# parse the language — it's too expensive for marginal benefit at this
# layer and the regexes catch what matters for SCA reachability.
_JS_IMPORT_RE = re.compile(
    r"""(?:
        \bimport\s+(?:[^'"]*?\bfrom\s+)?['"]([^'"]+)['"] |   # import X from "pkg" / import "pkg"
        \brequire\s*\(\s*['"]([^'"]+)['"]\s*\)         |   # require("pkg")
        \bimport\s*\(\s*['"]([^'"]+)['"]\s*\)              # import("pkg")
    )""",
    re.VERBOSE,
)


def _js_imports(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    out: set[str] = set()
    for m in _JS_IMPORT_RE.finditer(text):
        spec = next(g for g in m.groups() if g)
        # Relative imports aren't packages.
        if spec.startswith(".") or spec.startswith("/"):
            continue
        out.add(_js_top_level(spec))
    return out


def _top_level(module: str) -> str:
    """`foo.bar.baz` → `foo`. Python distribution names sometimes use
    dashes (`google-cloud-storage`) but import names always use underscores
    (`google.cloud.storage`); SCA tools normally report the install name,
    so we also emit a normalized form. The enricher checks both."""
    return module.split(".", 1)[0]


def _js_top_level(spec: str) -> str:
    """`@scope/pkg/sub` → `@scope/pkg`; `pkg/sub` → `pkg`."""
    if spec.startswith("@"):
        parts = spec.split("/", 2)
        return "/".join(parts[:2]) if len(parts) >= 2 else spec
    return spec.split("/", 1)[0]


# Go: `import "path"` (single) and `import ( … )` (grouped). Aliased imports
# (`alias "path"`) are also covered by the inner-quote capture.
_GO_SINGLE_RE = re.compile(r'^\s*import\s+(?:[A-Za-z_][\w]*\s+)?"([^"]+)"', re.MULTILINE)
_GO_GROUP_RE = re.compile(r"import\s*\(([^)]*)\)", re.DOTALL)
_GO_INNER_QUOTE_RE = re.compile(r'"([^"]+)"')


def _go_imports(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    out: set[str] = set()
    for m in _GO_SINGLE_RE.finditer(text):
        out.add(m.group(1))
    for grp in _GO_GROUP_RE.finditer(text):
        for q in _GO_INNER_QUOTE_RE.finditer(grp.group(1)):
            out.add(q.group(1))
    return out


# Ruby: `require "gem"` / `require 'gem'` / `require_relative` (filtered out,
# not a package). Also `gem "name"` from Gemfile-adjacent code, which is rare
# in `.rb` files but tolerated.
_RB_REQUIRE_RE = re.compile(
    r"""\b
        (?: require | gem )      # gemfile entries land here too
        \s+ ['"] ([^'"]+) ['"]
    """,
    re.VERBOSE,
)


def _ruby_imports(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    out: set[str] = set()
    for m in _RB_REQUIRE_RE.finditer(text):
        spec = m.group(1)
        # `require_relative "path"` matches but is intra-repo; reject obvious
        # relative paths.
        if spec.startswith(".") or "/" in spec and not spec.startswith(("rails", "active")):
            # Allow common Ruby gem sub-paths like `active_record` but reject
            # bare `foo/bar` filesystem-y specs. The check is heuristic; false
            # positives just leave a finding at full severity.
            if spec.startswith((".", "./", "../")) or "../" in spec:
                continue
        out.add(spec.split("/", 1)[0])
    return out


# Java / Kotlin: `import com.fasterxml.jackson.databind.ObjectMapper;` — we
# want the PACKAGE (everything before the final dot), since Maven coords are
# `group:artifact` and the group matches the package prefix. Static imports
# (`import static org.junit.Assert.assertEquals;`) reference a method on a
# class, so the package is two segments up instead of one.
_JAVA_IMPORT_RE = re.compile(
    # Kotlin omits the trailing `;`, Java requires it. Match either.
    r"^\s*import(\s+static)?\s+([\w.]+)\s*;?\s*$", re.MULTILINE,
)


def _java_imports(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    out: set[str] = set()
    for m in _JAVA_IMPORT_RE.finditer(text):
        is_static = m.group(1) is not None
        full = m.group(2)
        parts = full.split(".")
        # Drop the trailing class (and method, for static imports).
        drop = 2 if is_static else 1
        if len(parts) > drop:
            out.add(".".join(parts[:-drop]))
        else:
            out.add(full)
    return out


# ---- enricher --------------------------------------------------------------


def _dep_package_name(finding: Finding) -> str | None:
    """Return the dep package name from a finding, or None if it's not a
    dependency finding we can reason about."""
    if finding.category != "Vulnerable Dependency":
        return None
    pkg = (finding.raw_reference or {}).get("pkg")
    return str(pkg) if pkg else None


def _normalize_py(name: str) -> set[str]:
    """A Python dist name and its likely import name often differ. Build
    a small set of candidates that the import-index lookup will try.

    Bias is deliberately toward "match when in doubt" — wrongly demoting a
    real vulnerability is worse than missing a chance to mark something
    unreachable. Examples covered:
      requests              → {requests}
      python-dateutil       → {python-dateutil, python_dateutil, dateutil}
      google-cloud-storage  → {google-cloud-storage, google_cloud_storage, google}
        (google.cloud.storage → top-level import `google`)
    """
    base = name.lower()
    candidates = {base, base.replace("-", "_"), base.replace("_", "-")}
    # `python-foo` / `py-foo` commonly import as `foo`.
    for prefix in ("python-", "py-"):
        if base.startswith(prefix):
            candidates.add(base[len(prefix):])
    # `foo-bar-baz` may import as the top-level namespace `foo`. We add the
    # first dash-segment as a candidate. False positives here just leave a
    # finding at full severity, which is the safe direction.
    if "-" in base:
        candidates.add(base.split("-", 1)[0])
    return candidates


def _looks_python(file_path: str, target: str | None) -> bool:
    """Trivy's `target` for Python deps usually ends in `requirements.txt`,
    `Pipfile.lock`, `poetry.lock`, `pyproject.toml`, etc."""
    blob = (target or file_path or "").lower()
    return any(t in blob for t in ("requirements", "pipfile", "poetry", "pyproject", "setup.py"))


def _looks_javascript(file_path: str, target: str | None) -> bool:
    blob = (target or file_path or "").lower()
    return any(t in blob for t in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock"))


def _looks_go(file_path: str, target: str | None) -> bool:
    blob = (target or file_path or "").lower()
    return any(t in blob for t in ("go.mod", "go.sum"))


def _looks_ruby(file_path: str, target: str | None) -> bool:
    blob = (target or file_path or "").lower()
    return any(t in blob for t in ("gemfile", "gemfile.lock", ".gemspec"))


def _looks_java(file_path: str, target: str | None) -> bool:
    blob = (target or file_path or "").lower()
    return any(t in blob for t in ("pom.xml", "build.gradle", "build.gradle.kts", ".jar"))


def _java_pkg_match(pkg: str, imports: frozenset[str]) -> bool:
    """Trivy reports Maven coords like `com.fasterxml.jackson.core:jackson-databind`.
    Match if any imported Java package starts with the group-id (before `:`)."""
    group = pkg.split(":", 1)[0].lower()
    if not group:
        return False
    return any(imp.lower().startswith(group) for imp in imports)


def _go_pkg_match(pkg: str, imports: frozenset[str]) -> bool:
    """Go module paths are hierarchical (`github.com/foo/bar`). A dep is
    reachable if any imported path starts with the module path — e.g. an
    import of `github.com/foo/bar/internal/x` satisfies `github.com/foo/bar`."""
    needle = pkg.lower()
    return any(imp.lower() == needle or imp.lower().startswith(needle + "/") for imp in imports)


def enrich_with_reachability(
    findings: Iterable[Finding], repo_path: Path
) -> tuple[list[Finding], dict[str, int]]:
    """Mark dep findings reachable/unreachable; demote severity of unreachable.

    Returns the new finding list plus a small stats dict so the worker can log
    `dropped` / `kept` counts and the operator can audit the impact per scan.
    """
    index = build_import_index(repo_path)
    stats = {"checked": 0, "reachable": 0, "unreachable": 0, "abstained": 0}
    out: list[Finding] = []

    for f in findings:
        pkg = _dep_package_name(f)
        if pkg is None:
            out.append(f)
            continue

        target = None
        if f.affected_files:
            target = f.affected_files[0]

        is_py = _looks_python(target or "", target)
        is_js = _looks_javascript(target or "", target)
        is_go = _looks_go(target or "", target)
        is_rb = _looks_ruby(target or "", target)
        is_java = _looks_java(target or "", target)

        stats["checked"] += 1
        reachable: bool | None = None

        if is_py and index.python_seen_files > 0:
            reachable = bool(_normalize_py(pkg) & index.python)
        elif is_js and index.javascript_seen_files > 0:
            reachable = pkg in index.javascript or pkg.lower() in index.javascript
        elif is_go and index.go_seen_files > 0:
            reachable = _go_pkg_match(pkg, index.go)
        elif is_rb and index.ruby_seen_files > 0:
            reachable = pkg.lower() in {i.lower() for i in index.ruby}
        elif is_java and index.java_seen_files > 0:
            reachable = _java_pkg_match(pkg, index.java)

        if reachable is None:
            stats["abstained"] += 1
            out.append(f.model_copy(update={"reachable": None}))
            continue

        if reachable:
            stats["reachable"] += 1
            out.append(f.model_copy(update={"reachable": True}))
        else:
            stats["unreachable"] += 1
            new_sev = _DEMOTE.get(f.severity, f.severity)
            out.append(f.model_copy(update={"reachable": False, "severity": new_sev}))

    return out, stats

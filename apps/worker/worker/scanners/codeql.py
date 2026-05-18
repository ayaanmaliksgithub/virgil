"""CodeQL adapter.

CodeQL is heavier than the default scanners, so it is opt-in via
ENABLE_CODEQL=true. The adapter uses buildless/source-root database creation
only; it must not run repository build commands inside the sandbox.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from audit_core import RawFinding, RepoProfile


LANGUAGE_SPECS = {
    "python": {
        "profile_keys": {"Python"},
        "codeql": "python",
        "suite": "/opt/codeql/codeql/python/ql/src/codeql-suites/python-security-and-quality.qls",
    },
    "javascript-typescript": {
        "profile_keys": {"JavaScript", "TypeScript"},
        "codeql": "javascript-typescript",
        "suite": "/opt/codeql/codeql/javascript/ql/src/codeql-suites/javascript-security-and-quality.qls",
    },
    "ruby": {
        "profile_keys": {"Ruby"},
        "codeql": "ruby",
        "suite": "/opt/codeql/codeql/ruby/ql/src/codeql-suites/ruby-security-and-quality.qls",
    },
    "go": {
        "profile_keys": {"Go"},
        "codeql": "go",
        "suite": "/opt/codeql/codeql/go/ql/src/codeql-suites/go-security-and-quality.qls",
    },
}


class CodeQLAdapter:
    name = "codeql"
    version = "2.x"

    def __init__(self) -> None:
        self._languages: list[str] = []

    def applicable(self, profile: RepoProfile) -> bool:
        if os.environ.get("ENABLE_CODEQL", "").lower() not in {"1", "true", "yes", "on"}:
            return False
        self._languages = _languages_for(profile)
        return bool(self._languages)

    def command(self, repo_path: Path, out_dir: Path) -> list[str]:
        if not self._languages:
            # The worker only calls command() after applicable(), but keep the
            # argv inert if someone invokes the adapter directly in a test.
            return ["sh", "-lc", "true"]

        script_parts = ["set -eu", "export HOME=/tmp"]
        for lang in self._languages:
            spec = LANGUAGE_SPECS[lang]
            db_dir = f"/tmp/codeql-db-{lang}"
            sarif = out_dir / f"codeql-{lang}.sarif"
            script_parts.append(
                "codeql database create "
                f"{db_dir} "
                f"--language={spec['codeql']} "
                f"--source-root={repo_path} "
                "--overwrite"
            )
            script_parts.append(
                "codeql database analyze "
                f"{db_dir} "
                f"{spec['suite']} "
                "--format=sarif-latest "
                f"--output={sarif} "
                "--threads=0 "
                "--ram=3072"
            )
        return ["sh", "-lc", " && ".join(script_parts)]

    def parse(self, out_dir: Path) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for sarif in sorted(out_dir.glob("codeql-*.sarif")):
            try:
                data = json.loads(sarif.read_text())
            except json.JSONDecodeError:
                continue
            findings.extend(_parse_sarif(data))
        return findings


def _languages_for(profile: RepoProfile) -> list[str]:
    present = set(profile.languages)
    allowed = _languages_for_env()
    return [
        lang
        for lang, spec in LANGUAGE_SPECS.items()
        if lang in allowed
        if present.intersection(spec["profile_keys"])
    ]


def _languages_for_env() -> list[str]:
    enabled = os.environ.get("CODEQL_LANGUAGES", "").strip()
    if not enabled:
        return list(LANGUAGE_SPECS)
    return [lang for lang in (p.strip() for p in enabled.split(",")) if lang in LANGUAGE_SPECS]


def _parse_sarif(data: dict) -> list[RawFinding]:
    out: list[RawFinding] = []
    for run in data.get("runs", []) or []:
        rules = _rules_by_id(run)
        for result in run.get("results", []) or []:
            rule_id = str(result.get("ruleId") or "codeql-unknown")
            rule = rules.get(rule_id, {})
            location = _primary_location(result)
            if location is None:
                continue
            message = _message(result.get("message")) or _message(rule.get("fullDescription")) or _message(rule.get("shortDescription"))
            title = _message(rule.get("shortDescription")) or rule.get("name") or rule_id
            props = rule.get("properties", {}) or {}
            tags = props.get("tags") or []

            out.append(RawFinding(
                source_tool="codeql",
                rule_id=rule_id,
                title=str(title)[:256],
                raw_severity=_severity(result, rule),
                message=str(message or "")[:8000],
                file=location["file"],
                start_line=location["start_line"],
                end_line=location["end_line"],
                snippet=None,
                cwe=_first_tag(tags, "external/cwe/cwe-"),
                cve=None,
                owasp=_first_owasp(tags),
                raw={
                    "rule_id": rule_id,
                    "level": result.get("level"),
                    "precision": props.get("precision"),
                    "security_severity": props.get("security-severity"),
                },
            ))
    return out


def _rules_by_id(run: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for tool in (run.get("tool") or {}).get("extensions", []) or []:
        for rule in tool.get("rules", []) or []:
            if rule.get("id"):
                out[str(rule["id"])] = rule
    for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules", []) or []:
        if rule.get("id"):
            out[str(rule["id"])] = rule
    return out


def _primary_location(result: dict) -> dict | None:
    locations = result.get("locations") or []
    if not locations:
        return None
    physical = (locations[0].get("physicalLocation") or {})
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    uri = str(artifact.get("uri") or "")
    if not uri:
        return None
    return {
        "file": uri,
        "start_line": int(region.get("startLine") or 1) or 1,
        "end_line": int(region.get("endLine") or 0) or None,
    }


def _message(value) -> str | None:
    if isinstance(value, dict):
        return value.get("text") or value.get("markdown")
    if value:
        return str(value)
    return None


def _severity(result: dict, rule: dict) -> str | None:
    props = rule.get("properties", {}) or {}
    security = props.get("security-severity")
    try:
        if security is not None:
            score = float(security)
            if score >= 9:
                return "CRITICAL"
            if score >= 7:
                return "HIGH"
            if score >= 4:
                return "MEDIUM"
            return "LOW"
    except (TypeError, ValueError):
        pass
    level = str(result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "").lower()
    return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFORMATIONAL"}.get(level)


def _first_tag(tags: list, prefix: str) -> str | None:
    for tag in tags:
        text = str(tag).lower()
        if text.startswith(prefix):
            raw = text.removeprefix(prefix)
            if raw.isdigit():
                return f"CWE-{int(raw)}"
            return f"CWE-{raw.upper()}"
    return None


def _first_owasp(tags: list) -> str | None:
    for tag in tags:
        text = str(tag)
        if "external/owasp/owasp-" in text.lower():
            return text.rsplit("/", 1)[-1].upper()
    return None

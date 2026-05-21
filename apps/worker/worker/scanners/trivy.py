"""Trivy adapter.

Filesystem scan covers OS/lang dependency CVEs, IaC misconfigurations, and
secrets. We rely on Gitleaks for primary secret detection but keep Trivy's
secret findings as cross-confirmation (handled by the deduper).
"""
from __future__ import annotations

import json
from pathlib import Path

from audit_core import RawFinding, RepoProfile

from worker.normalize.licenses import classify_license

from .base import ScannerAdapter


class TrivyAdapter:
    name = "trivy"
    version = "0.x"

    def applicable(self, profile: RepoProfile) -> bool:
        return profile.file_count > 0

    def command(self, repo_path: Path, out_dir: Path) -> list[str]:
        return [
            "trivy", "fs",
            "--skip-db-update", "--skip-java-db-update",
            "--scanners", "vuln,misconfig,secret,license",
            "--format", "json",
            "--output", str(out_dir / "trivy.json"),
            "--quiet",
            "--no-progress",
            "--timeout", "5m",
            "--exit-code", "0",
            str(repo_path),
        ]

    def parse(self, out_dir: Path) -> list[RawFinding]:
        out_file = out_dir / "trivy.json"
        if not out_file.exists():
            return []
        try:
            data = json.loads(out_file.read_text())
        except json.JSONDecodeError:
            return []

        findings: list[RawFinding] = []
        for result in data.get("Results", []) or []:
            target = result.get("Target", "")
            findings += _parse_vulns(result.get("Vulnerabilities") or [], target)
            findings += _parse_misconfigs(result.get("Misconfigurations") or [], target)
            findings += _parse_secrets(result.get("Secrets") or [], target)
            findings += _parse_licenses(result.get("Licenses") or [], target)
        return findings


def _parse_vulns(items, target) -> list[RawFinding]:
    out = []
    for v in items:
        cwe_ids = v.get("CweIDs") or []
        out.append(RawFinding(
            source_tool="trivy",
            rule_id=str(v.get("VulnerabilityID", "trivy-vuln")),
            title=f"{v.get('VulnerabilityID', 'CVE')}: {v.get('PkgName', '')} {v.get('InstalledVersion', '')}"[:256],
            raw_severity=v.get("Severity"),
            message=str(v.get("Description") or v.get("Title") or "")[:8000],
            file=str(target),
            start_line=1,
            end_line=None,
            snippet=None,
            cwe=(cwe_ids[0] if cwe_ids else None),
            cve=v.get("VulnerabilityID") if str(v.get("VulnerabilityID", "")).startswith("CVE-") else None,
            owasp=None,
            raw={"pkg": v.get("PkgName"), "fixed_version": v.get("FixedVersion"), "primary_url": v.get("PrimaryURL")},
        ))
    return out


def _parse_misconfigs(items, target) -> list[RawFinding]:
    out = []
    for m in items:
        loc = m.get("CauseMetadata") or {}
        start = int(loc.get("StartLine") or 1) or 1
        end = int(loc.get("EndLine") or 0) or None
        out.append(RawFinding(
            source_tool="trivy",
            rule_id=str(m.get("ID", "trivy-misconfig")),
            title=str(m.get("Title") or m.get("ID") or "Misconfiguration")[:256],
            raw_severity=m.get("Severity"),
            message=str(m.get("Description") or m.get("Message") or "")[:8000],
            file=str(target),
            start_line=start,
            end_line=end,
            snippet=None,
            cwe=None,
            cve=None,
            owasp=None,
            raw={"id": m.get("ID"), "type": m.get("Type")},
        ))
    return out


def _parse_licenses(items, target) -> list[RawFinding]:
    """Emit a finding per non-permissive dependency license.

    Severity is governed by `LICENSE_POLICY` (see worker.normalize.licenses).
    Permissive licenses (MIT/BSD/Apache/etc.) are suppressed — `classify_license`
    returns None and the entry is skipped, so the findings ledger doesn't drown
    in 400 "uses MIT" rows.
    """
    out = []
    for lic in items:
        name = str(lic.get("Name") or "").strip()
        pkg = str(lic.get("PkgName") or "")
        severity = classify_license(name or None)
        if severity is None:
            continue  # permissive license under the active policy — not a finding
        display_name = name or "unknown"
        file_path = str(lic.get("FilePath") or target or "")
        out.append(RawFinding(
            source_tool="trivy",
            rule_id=f"license/{display_name}",
            title=f"License risk: {pkg or 'dependency'} uses {display_name}"[:256],
            raw_severity=severity,
            message=(
                f"Dependency '{pkg or 'unknown'}' is licensed under "
                f"{display_name or 'an unidentified license'}. "
                "Trivy category: " + str(lic.get("Category") or "unknown") + "."
            )[:2000],
            file=file_path or target,
            start_line=1,
            end_line=None,
            snippet=None,
            cwe=None,
            cve=None,
            owasp=None,
            raw={
                "pkg": pkg or None,
                "license": display_name,
                "trivy_category": lic.get("Category"),
                "confidence": lic.get("Confidence"),
            },
        ))
    return out


def _parse_secrets(items, target) -> list[RawFinding]:
    out = []
    for s in items:
        out.append(RawFinding(
            source_tool="trivy",
            rule_id=f"secret/{s.get('RuleID', 'unknown')}",
            title=f"Secret detected: {s.get('Title', s.get('RuleID', 'secret'))}"[:256],
            raw_severity=s.get("Severity"),
            message=str(s.get("Match") or "")[:2000],
            file=str(target),
            start_line=int(s.get("StartLine") or 1) or 1,
            end_line=int(s.get("EndLine") or 0) or None,
            snippet=s.get("Match"),
            cwe="CWE-798",
            cve=None,
            owasp="A07:2021 - Identification and Authentication Failures",
            raw={"rule_id": s.get("RuleID"), "category": s.get("Category")},
        ))
    return out

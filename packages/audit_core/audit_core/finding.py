"""Unified finding model. Mirrors packages/shared-schemas/finding.schema.json."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


SEVERITY_ORDER = {s: i for i, s in enumerate(
    [Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
)}


class Confidence(str, Enum):
    LOW = "Low confidence"
    MEDIUM = "Medium confidence"
    HIGH = "High confidence"
    MANUAL = "Requires manual verification"


CONFIDENCE_ORDER = {c: i for i, c in enumerate(
    [Confidence.MANUAL, Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
)}


class Status(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"


class AuditPhase(str, Enum):
    QUEUED = "queued"
    CLONING = "cloning"
    ANALYZING = "analyzing"
    SCANNING = "scanning"
    CORRELATING = "correlating"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class AuditState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class AffectedLine(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file: str
    start: int = Field(ge=1)
    end: int | None = Field(default=None, ge=1)


class RawFinding(BaseModel):
    """Pre-normalized finding emitted by a scanner adapter's parse() method.

    Adapters are responsible only for faithful translation of scanner output;
    severity/category/redaction/dedupe are applied downstream.
    """

    model_config = ConfigDict(extra="forbid")

    source_tool: str
    rule_id: str
    title: str
    raw_severity: str | None = None
    message: str
    file: str
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    snippet: str | None = None
    cwe: str | None = None
    cve: str | None = None
    owasp: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Canonical normalized finding. Persisted and returned by the API."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    id: UUID = Field(default_factory=uuid4)
    audit_id: UUID | None = None
    dedupe_key: str
    title: str = Field(min_length=1, max_length=256)
    severity: Severity
    confidence: Confidence
    category: str
    owasp_category: str | None = None
    cwe: str | None = None
    cve: str | None = None
    affected_files: list[str]
    affected_lines: list[AffectedLine]
    evidence: str
    explanation: str
    exploitability_summary: str | None = None
    business_impact: str | None = None
    safe_guidance: str | None = None
    source_tool: list[str] = Field(min_length=1)
    raw_reference: dict[str, Any] = Field(default_factory=dict)
    # Threat-intel enrichment (Phase 4). Populated post-normalization from the
    # nightly-refreshed `threat_intel` table when `cve` is set. Absent fields
    # mean "unknown / not in feed" — never assume zero.
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    kev: bool = False
    # Compliance control mapping (Phase 4 #7). Keyed by framework:
    # `{"SOC2": ["CC6.1"], "PCI-DSS": ["3.4"], "HIPAA": ["164.312(a)(1)"]}`.
    # Populated post-normalization from a static `(category, cwe)` table; an
    # empty dict means "no controls mapped" (NOT "compliant" — absence of
    # mapping just means the issue doesn't tie to a tracked control).
    compliance: dict[str, list[str]] = Field(default_factory=dict)
    # Reachability (Phase 4 #8). For dependency findings only:
    #   True  → the vulnerable package is imported somewhere in the source tree
    #   False → the package is in the lockfile but no source file imports it.
    #           Severity is dropped one level by the enricher; the finding stays
    #           in the ledger (some org policies require tracking unreachable
    #           deps) but is sorted to the bottom.
    #   None  → reachability could not be determined (non-dep finding, language
    #           the analyzer doesn't cover yet, or scanner didn't report a pkg).
    reachable: bool | None = None
    # Redacted code slice around the first affected_line — captured at audit
    # time so the ask-the-auditor chat can ground its answers in actual code,
    # not just finding metadata. Always pre-redacted by the worker (host
    # paths, secret patterns scrubbed) before storage. ~30 lines centered on
    # the line, hard-capped at 2KB so prompt budgets stay sane.
    code_context: str | None = None
    status: Status = Status.OPEN
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

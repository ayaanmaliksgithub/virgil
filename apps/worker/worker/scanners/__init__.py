from .base import ScannerAdapter
from .codeql import CodeQLAdapter
from .semgrep import SemgrepAdapter
from .trivy import TrivyAdapter
from .gitleaks import GitleaksAdapter

ALL_ADAPTERS: list[type[ScannerAdapter]] = [
    SemgrepAdapter,
    TrivyAdapter,
    GitleaksAdapter,
    CodeQLAdapter,
]

__all__ = [
    "ScannerAdapter",
    "SemgrepAdapter",
    "TrivyAdapter",
    "GitleaksAdapter",
    "CodeQLAdapter",
    "ALL_ADAPTERS",
]

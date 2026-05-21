import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "worker"))
sys.path.insert(0, str(ROOT / "apps" / "api"))
sys.path.insert(0, str(ROOT / "apps" / "cli"))
sys.path.insert(0, str(ROOT / "packages" / "audit_core"))

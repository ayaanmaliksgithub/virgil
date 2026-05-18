"""Language / package manager / framework / IaC detection.

Pure file-system inspection — never executes repo code.
"""
from __future__ import annotations

from pathlib import Path

from audit_core import RepoProfile

LANG_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go",
    ".rs": "Rust", ".rb": "Ruby", ".java": "Java", ".kt": "Kotlin",
    ".cs": "C#", ".php": "PHP", ".c": "C", ".h": "C", ".cpp": "C++",
    ".hpp": "C++", ".m": "Objective-C", ".swift": "Swift",
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".yaml": "YAML", ".yml": "YAML", ".tf": "Terraform",
    ".sql": "SQL",
}

PKG_MANAGER_FILES = {
    "package.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "requirements.txt": "pip",
    "pyproject.toml": "pip",
    "Pipfile": "pipenv",
    "poetry.lock": "poetry",
    "go.mod": "go-modules",
    "Cargo.toml": "cargo",
    "Gemfile": "bundler",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "composer.json": "composer",
}

FRAMEWORK_HINTS = {
    "next.config.js": "Next.js", "next.config.mjs": "Next.js", "next.config.ts": "Next.js",
    "nuxt.config.ts": "Nuxt", "nuxt.config.js": "Nuxt",
    "manage.py": "Django", "wsgi.py": "Django/Flask",
    "fastapi": "FastAPI",  # detected via dependency parse later if needed
    "rails": "Rails",
    "angular.json": "Angular",
    "svelte.config.js": "Svelte",
}


def build_profile(repo: Path, *, max_files: int = 50_000) -> RepoProfile:
    languages: dict[str, int] = {}
    package_managers: set[str] = set()
    frameworks: set[str] = set()
    iac: set[str] = set()
    file_count = 0
    loc = 0

    for path in repo.rglob("*"):
        if file_count >= max_files:
            break
        if not path.is_file():
            continue
        name = path.name
        ext = path.suffix.lower()
        rel = path.relative_to(repo).as_posix().lower()

        file_count += 1

        if ext in LANG_BY_EXT:
            languages[LANG_BY_EXT[ext]] = languages.get(LANG_BY_EXT[ext], 0) + 1

        if name in PKG_MANAGER_FILES:
            package_managers.add(PKG_MANAGER_FILES[name])
        if name in FRAMEWORK_HINTS:
            frameworks.add(FRAMEWORK_HINTS[name])

        if name == "Dockerfile" or name.startswith("Dockerfile.") or rel.endswith("/dockerfile"):
            iac.add("Dockerfile")
        if ext == ".tf" or name == "terraform.tfvars":
            iac.add("Terraform")
        if "kubernetes" in rel or "k8s" in rel or name in ("kustomization.yaml", "kustomization.yml"):
            iac.add("Kubernetes")
        if rel.startswith("helm/") or name == "Chart.yaml":
            iac.add("Helm")
        if name in ("cloudformation.yaml", "cloudformation.yml") or "cloudformation" in rel:
            iac.add("CloudFormation")
        if name == ".github/workflows" or "/.github/workflows/" in "/" + rel:
            iac.add("GitHub Actions")

        # cheap LoC for text-y files
        if ext in LANG_BY_EXT and path.stat().st_size < 2 * 1024 * 1024:
            try:
                loc += sum(1 for _ in path.open("rb"))
            except OSError:
                pass

    return RepoProfile(
        languages=languages,
        package_managers=sorted(package_managers),
        frameworks=sorted(frameworks),
        iac=sorted(iac),
        loc=loc,
        file_count=file_count,
    )

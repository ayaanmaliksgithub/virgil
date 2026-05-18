from __future__ import annotations
from pydantic import BaseModel, Field


class RepoProfile(BaseModel):
    languages: dict[str, int] = Field(default_factory=dict)  # language -> file count
    package_managers: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    iac: list[str] = Field(default_factory=list)  # terraform, k8s, dockerfile, helm, ...
    loc: int = 0
    file_count: int = 0

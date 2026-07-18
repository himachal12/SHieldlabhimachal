"""Structured, provenance-aware patch proposals for Python remediation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import os


def source_sha256(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def repository_relative_path(path: str, repository_root: str) -> str | None:
    """Return a safe repository-relative path, never a temporary absolute path."""
    if not path:
        return None
    root = os.path.realpath(repository_root)
    candidate = os.path.realpath(path)
    try:
        relative = os.path.relpath(candidate, root)
    except ValueError:
        return None
    if relative == os.pardir or relative.startswith(os.pardir + os.sep):
        return None
    return relative.replace(os.sep, "/")


@dataclass(frozen=True)
class PatchProposal:
    repository_relative_path: str
    source_file_sha256: str
    start_line: int | None
    end_line: int | None
    expected_original_code: str
    replacement_code: str
    patch_kind: str
    fix_source: str
    validation_status: str = "suggested"
    repository_commit: str | None = None
    finding_rule_id: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)

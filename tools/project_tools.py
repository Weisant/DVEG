"""Project filesystem helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from agent.models import GeneratedFile


def create_run_directory(output_root: Path, project_name: str) -> Path:
    """Create the timestamped output directory for one run."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_root / f"{timestamp}-{_sanitize_project_name(project_name)}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def write_project(root: Path, files: list[GeneratedFile]) -> list[str]:
    """Write generated files and return their relative paths."""
    written_paths: list[str] = []
    for generated_file in files:
        target_path = root / generated_file.path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(generated_file.content, encoding="utf-8", newline="\n")
        written_paths.append(generated_file.path)
    return written_paths


def _sanitize_project_name(value: str) -> str:
    """Convert a project name into a directory-safe form."""
    cleaned_chars: list[str] = []
    for char in value.lower():
        if char.isalnum() or char in {"-", "_"}:
            cleaned_chars.append(char)
        elif char in {" ", "."}:
            cleaned_chars.append("-")
    cleaned = "".join(cleaned_chars).strip("-")
    return cleaned or "db-env-project"

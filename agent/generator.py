"""LLM-driven Docker project generator and writer.

The planner owns build strategy and resource availability. The generator
consumes that EnvironmentPlan, produces complete ProjectArtifacts file content,
and writes the files to disk.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from agent.llm import JsonChatClient
from agent.models import EnvironmentPlan, ProjectArtifacts
from agent.prompt_loader import load_prompt
from tools.project_tools import create_run_directory, write_project


GENERATOR_TEMPERATURE = 0.1
StatusCallback = Callable[[str], None]


def _update_status(status_callback: StatusCallback | None, operation: str) -> None:
    """Publish one generator operation when terminal progress is enabled."""
    if status_callback is not None:
        status_callback(operation)


def generate_project(
    blueprint: EnvironmentPlan,
    output_directory: Path,
    client: JsonChatClient,
    status_callback: StatusCallback | None = None,
) -> tuple[ProjectArtifacts, Path, list[str]]:
    """Generate complete project files from an EnvironmentPlan and write them."""
    _update_status(status_callback, "Preparing EnvironmentPlan file-generation prompt")
    response = client.chat_json(
        system_prompt=_generator_system_prompt(),
        user_prompt=(
            "Generate the final ProjectArtifacts JSON from this EnvironmentPlan. "
            "Use only planner-selected strategy and planner-provided resource facts.\n\n"
            "Build blueprint:\n"
            f"{json.dumps(blueprint.to_dict(), ensure_ascii=False, indent=2)}"
        ),
        temperature=GENERATOR_TEMPERATURE,
        model=client.settings.generator_model,
        timeout_seconds=300,
    )
    _update_status(status_callback, "Parsing ProjectArtifacts output")
    artifacts = ProjectArtifacts.from_dict(response)
    _normalize_project_artifact_identity(artifacts, blueprint)
    return write_generated_project(
        artifacts=artifacts,
        output_directory=output_directory,
        status_callback=status_callback,
    )


def write_generated_project(
    artifacts: ProjectArtifacts,
    output_directory: Path,
    status_callback: StatusCallback | None = None,
) -> tuple[ProjectArtifacts, Path, list[str]]:
    """Write generated ProjectArtifacts into a timestamped output directory."""
    _update_status(status_callback, "Creating timestamped project directory")
    run_dir = create_run_directory(output_directory, artifacts.project_name)
    _update_status(status_callback, "Writing Docker project artifacts")
    written_files = write_project(run_dir, artifacts.files)
    _update_status(status_callback, "Finalizing Generator Module output")
    return artifacts, run_dir, written_files


def _normalize_project_artifact_identity(
    artifacts: ProjectArtifacts,
    blueprint: EnvironmentPlan,
) -> None:
    project_name = str(
        blueprint.generation_requirements.get("project_name") or artifacts.project_name
    ).strip()
    cve_id = str(blueprint.generation_requirements.get("cve_id") or artifacts.cve_id).strip()
    db_type = str(blueprint.generation_requirements.get("db_type") or "").strip()
    version_requirement = blueprint.generation_requirements.get("version")
    if isinstance(version_requirement, dict):
        fallback_version = (
            version_requirement.get("final")
            or version_requirement.get("requested")
            or ""
        )
    else:
        fallback_version = version_requirement or ""
    version = str(blueprint.build_plan.selected_version or fallback_version).strip()
    artifacts.project_name = _project_name_with_identifiers(
        base_name=project_name,
        db_type=db_type,
        cve_id=cve_id,
        version=version,
    )
    if cve_id:
        artifacts.cve_id = cve_id


def _project_name_with_identifiers(
    *,
    base_name: str,
    db_type: str,
    cve_id: str,
    version: str,
) -> str:
    """Rebuild the project name into a stable subject-version_cve shape."""
    subject = _clean_project_subject(
        base_name=base_name,
        db_type=db_type,
        cve_id=cve_id,
        version=version,
    )
    normalized_version = version.strip()
    normalized_cve_id = cve_id.strip().upper()
    name = f"{subject}-{normalized_version}" if normalized_version else subject
    if normalized_cve_id:
        name = f"{name}_{normalized_cve_id}"
    return name


def _clean_project_subject(
    *,
    base_name: str,
    db_type: str,
    cve_id: str,
    version: str,
) -> str:
    """Remove previously appended CVE/version fragments from a base project name."""
    subject = base_name.strip() or db_type.strip() or "db-env-project"
    for token in _project_name_tokens_to_remove(cve_id=cve_id, version=version):
        subject = subject.replace(token, "")
        subject = subject.replace(token.lower(), "")
        subject = subject.replace(token.upper(), "")
    subject = subject.strip("-_ .")
    return subject or db_type.strip() or "db-env-project"


def _project_name_tokens_to_remove(*, cve_id: str, version: str) -> list[str]:
    tokens: list[str] = []
    normalized_cve_id = cve_id.strip()
    normalized_version = version.strip()
    if normalized_cve_id:
        tokens.extend(
            [
                normalized_cve_id,
                normalized_cve_id.replace("-", "_"),
            ]
        )
    if normalized_version:
        tokens.extend(
            [
                normalized_version,
                normalized_version.replace(".", "-"),
                normalized_version.replace(".", "_"),
            ]
        )
    return [token for token in tokens if token]


def _generator_system_prompt() -> str:
    """Compose the generator rules and build-path policy."""
    sections = [
        load_prompt("generator/core.md"),
        load_prompt("generator/direct.md"),
        load_prompt("generator/build_paths.md"),
    ]
    return "\n\n---\n\n".join(section.strip() for section in sections if section.strip())

"""Minimal LLM ProjectArtifacts generator used for ablation experiments."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from agent.generator import write_generated_project
from agent.llm import JsonChatClient
from agent.models import EnvironmentPlan, ProjectArtifacts


MINIMAL_GENERATOR_TEMPERATURE = 0.1
StatusCallback = Callable[[str], None]


def _update_status(status_callback: StatusCallback | None, operation: str) -> None:
    if status_callback is not None:
        status_callback(operation)


def generate_project_minimal(
    blueprint: EnvironmentPlan,
    output_directory: Path,
    client: JsonChatClient,
    status_callback: StatusCallback | None = None,
) -> tuple[ProjectArtifacts, Path, list[str]]:
    """Generate minimal ProjectArtifacts and write them through the project writer."""
    artifacts = generate_project_artifacts_minimal(
        blueprint=blueprint,
        client=client,
        status_callback=status_callback,
    )
    return write_generated_project(
        artifacts=artifacts,
        output_directory=output_directory,
        status_callback=status_callback,
    )


def generate_project_artifacts_minimal(
    blueprint: EnvironmentPlan,
    client: JsonChatClient,
    status_callback: StatusCallback | None = None,
) -> ProjectArtifacts:
    """Generate ProjectArtifacts from an EnvironmentPlan with only schema-level rules."""
    _update_status(status_callback, "Preparing minimal ProjectArtifacts prompt")
    response = client.chat_json(
        system_prompt=_minimal_generator_system_prompt(),
        user_prompt=(
            "EnvironmentPlan:\n"
            f"{json.dumps(blueprint.to_dict(), ensure_ascii=False, indent=2)}"
        ),
        temperature=MINIMAL_GENERATOR_TEMPERATURE,
        model=client.settings.generator_model,
        timeout_seconds=300,
    )
    _update_status(status_callback, "Parsing minimal ProjectArtifacts output")
    return ProjectArtifacts.from_dict(response)


def _minimal_generator_system_prompt() -> str:
    return """
You are a minimal Docker project generator for an ablation experiment.

You will receive exactly one EnvironmentPlan JSON object. Generate a Docker
project as exactly one ProjectArtifacts JSON object.

Use the EnvironmentPlan as the only input. Do not call external tools. Do not
claim verification, availability, or vulnerability status unless it is already
present in the EnvironmentPlan.

Output schema:
{
  "project_name": "string",
  "cve_id": "string",
  "files": [
    {
      "path": "relative/path",
      "purpose": "string",
      "content": "complete file content"
    }
  ],
  "run_instructions": ["string"],
  "summary": "string"
}

Rules:
- Return only the JSON object. Do not include Markdown fences or commentary.
- File paths must be relative paths.
- File contents must be complete, not patches or excerpts.
- Include docker-compose.yml and README.md.
- Include Dockerfile unless the EnvironmentPlan clearly uses a direct official
  image without a build step.
- Do not include exploit payloads, proof-of-concept code, bypass payloads,
  destructive operations, or vulnerability-triggering validation commands.
""".strip()

"""Data models for project generation, artifact plans, and state summaries."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .profile_models import EvidenceItem
from .task_models import TaskInput
from .utils import (
    _ensure_bool,
    _ensure_dict_of_str,
    _ensure_list_of_dict,
    _ensure_list_of_str,
    _ensure_str,
)


@dataclass
class GeneratedFile:
    """Single file object to be written to disk."""

    path: str
    purpose: str
    content: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GeneratedFile":
        """Restore one generated file object from a dictionary."""
        return cls(
            path=_ensure_str(data.get("path"), "files[].path"),
            purpose=_ensure_str(data.get("purpose"), "files[].purpose"),
            content=_ensure_str(data.get("content"), "files[].content"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert one generated file object back to a dictionary."""
        return asdict(self)


@dataclass
class ProjectArtifacts:
    """Complete project file set output by the generator agent."""

    project_name: str
    cve_id: str
    files: list[GeneratedFile]
    run_instructions: list[str]
    summary: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProjectArtifacts":
        """Restore the complete project file set from generator output."""
        files = data.get("files") or []
        if not isinstance(files, list):
            raise ValueError("files must be a list.")
        return cls(
            project_name=_ensure_str(data.get("project_name"), "project_name"),
            cve_id=_ensure_str(data.get("cve_id"), "cve_id"),
            files=[GeneratedFile.from_dict(item) for item in files],
            run_instructions=_ensure_list_of_str(
                data.get("run_instructions"), "run_instructions"
            ),
            summary=_ensure_str(data.get("summary"), "summary"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert the complete project file set back to a serializable structure."""
        return {
            "project_name": self.project_name,
            "cve_id": self.cve_id,
            "files": [file.to_dict() for file in self.files],
            "run_instructions": self.run_instructions,
            "summary": self.summary,
        }


@dataclass
class ArtifactFact:
    """External artifact fact collected by the tools layer."""

    fact_type: str
    source: str
    identifier: str
    version: str
    ref: str
    available: bool
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert an artifact fact object back to a dictionary."""
        return asdict(self)


@dataclass
class ParsedTaskBundle:
    """Complete parser agent output: standardized task plus evidence."""

    task: TaskInput
    evidence: list[EvidenceItem]
    inferred_db_type: str
    vulnerability_info: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert parser output into a loggable structure."""
        return {
            "task": self.task.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "inferred_db_type": self.inferred_db_type,
            "vulnerability_info": self.vulnerability_info,
        }


@dataclass
class TargetProfile:
    """Final target in the reproduction profile."""

    cve_id: str
    project_name: str
    db_type: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TargetProfile":
        """Restore the final target from a dictionary."""
        return cls(
            cve_id=_ensure_str(data.get("cve_id"), "profile.target.cve_id"),
            project_name=_ensure_str(
                data.get("project_name"), "profile.target.project_name"
            ),
            db_type=_ensure_str(data.get("db_type"), "profile.target.db_type"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return {
            "cve_id": self.cve_id,
            "db_type": self.db_type,
            "project_name": self.project_name,
        }


@dataclass
class AssetProfile:
    """Affected asset in the reproduction profile."""

    relevance_type: str
    component_name: str
    component_type: str
    vendor: str
    package_ecosystem: str
    package_name: str | None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AssetProfile":
        """Restore the affected asset from a dictionary."""
        return cls(
            relevance_type=_ensure_str(
                data.get("relevance_type"), "profile.asset.relevance_type"
            ),
            component_name=_ensure_str(
                data.get("component_name"), "profile.asset.component_name"
            ),
            component_type=_ensure_str(
                data.get("component_type"), "profile.asset.component_type"
            ),
            vendor=_ensure_str(data.get("vendor"), "profile.asset.vendor"),
            package_ecosystem=_ensure_str(
                data.get("package_ecosystem"),
                "profile.asset.package_ecosystem",
                "unknown",
            ),
            package_name=_ensure_optional_str(
                data.get("package_name"), "profile.asset.package_name"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return asdict(self)


@dataclass
class VersionCandidate:
    """Affected candidate version available for planner probing."""

    version: str
    ecosystem: str
    upstream_version: str | None
    package_version: str | None
    reason: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VersionCandidate":
        """Restore a candidate version from a dictionary."""
        return cls(
            version=_ensure_str(
                data.get("version"), "profile.version.candidate_versions[].version"
            ),
            ecosystem=_ensure_str(
                data.get("ecosystem"),
                "profile.version.candidate_versions[].ecosystem",
                "unknown",
            ),
            upstream_version=_ensure_optional_str(
                data.get("upstream_version"),
                "profile.version.candidate_versions[].upstream_version",
            ),
            package_version=_ensure_optional_str(
                data.get("package_version"),
                "profile.version.candidate_versions[].package_version",
            ),
            reason=_ensure_str(
                data.get("reason"), "profile.version.candidate_versions[].reason"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return asdict(self)

@dataclass
class VersionProfile:
    """Version decision in the reproduction profile."""

    requested_version: str | None
    final_version: str | None
    candidate_versions: list[VersionCandidate]
    selection_reason: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VersionProfile":
        """Restore the version decision from a dictionary."""
        candidate_payload = data.get("candidate_versions")
        candidate_versions = [
            VersionCandidate.from_dict(item)
            for item in _ensure_list_of_dict(
                candidate_payload, "profile.version.candidate_versions"
            )
        ]
        return cls(
            requested_version=_ensure_optional_str(
                data.get("requested_version"), "profile.version.requested_version"
            ),
            final_version=_ensure_optional_str(
                data.get("final_version"), "profile.version.final_version"
            ),
            candidate_versions=candidate_versions,
            selection_reason=_ensure_str(
                data.get("selection_reason"), "profile.version.selection_reason"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return asdict(self)

@dataclass
class RuntimeProfile:
    """Runtime parameters in the reproduction profile."""

    port: str
    database: str
    username: str
    password: str
    root_password: str
    config: dict[str, str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuntimeProfile":
        """Restore runtime parameters from a dictionary."""
        return cls(
            port=_ensure_str(data.get("port"), "profile.runtime.port"),
            database=_ensure_str(data.get("database"), "profile.runtime.database"),
            username=_ensure_str(data.get("username"), "profile.runtime.username"),
            password=_ensure_str(data.get("password"), "profile.runtime.password"),
            root_password=_ensure_str(
                data.get("root_password"), "profile.runtime.root_password"
            ),
            config=_ensure_dict_of_str(data.get("config"), "profile.runtime.config"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return asdict(self)


@dataclass
class ArtifactRequirement:
    """Artifact requirement in the reproduction profile."""

    kind: str
    identifier: str
    version_constraint: str
    purpose: str
    notes: list[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ArtifactRequirement":
        """Restore an artifact requirement from a dictionary."""
        return cls(
            kind=_ensure_str(data.get("kind"), "profile.artifact_requirements[].kind"),
            identifier=_ensure_str(
                data.get("identifier"), "profile.artifact_requirements[].identifier"
            ),
            version_constraint=_ensure_str(
                data.get("version_constraint"),
                "profile.artifact_requirements[].version_constraint",
            ),
            purpose=_ensure_str(
                data.get("purpose"), "profile.artifact_requirements[].purpose"
            ),
            notes=_ensure_list_of_str(
                data.get("notes"), "profile.artifact_requirements[].notes"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return asdict(self)


@dataclass
class DockerHubImageCandidate:
    """Unverified DockerHub image candidate proposed by the profiler."""

    repository: str
    tags: list[str]
    reason: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DockerHubImageCandidate":
        """Restore a DockerHub image candidate from a dictionary."""
        return cls(
            repository=_ensure_str(
                data.get("repository"),
                "profile.dockerhub_image_candidates[].repository",
            ),
            tags=_ensure_list_of_str(
                data.get("tags"),
                "profile.dockerhub_image_candidates[].tags",
            ),
            reason=_ensure_str(
                data.get("reason"),
                "profile.dockerhub_image_candidates[].reason",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return asdict(self)


@dataclass
class VulnerabilityCondition:
    """Condition required for the vulnerability to hold."""

    name: str
    description: str
    category: str
    applies_at: str
    required: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VulnerabilityCondition":
        """Restore a vulnerability condition from a dictionary."""
        return cls(
            name=_ensure_str(
                data.get("name"), "profile.vulnerability_conditions[].name"
            ),
            description=_ensure_str(
                data.get("description"),
                "profile.vulnerability_conditions[].description",
            ),
            category=_ensure_str(
                data.get("category"),
                "profile.vulnerability_conditions[].category",
            ),
            applies_at=_ensure_str(
                data.get("applies_at"),
                "profile.vulnerability_conditions[].applies_at",
            ),
            required=_ensure_bool(
                data.get("required"),
                "profile.vulnerability_conditions[].required",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return asdict(self)


@dataclass
class ConstructionConstraints:
    """Build semantic constraints in the reproduction profile."""

    artifact_semantics: str
    requires_source_build: bool
    source_build_reason: str
    requires_build_time_configuration: bool
    setup_requirements: list[str]
    forbidden_choices: list[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConstructionConstraints":
        """Restore constraints from a dictionary."""
        return cls(
            artifact_semantics=_ensure_str(
                data.get("artifact_semantics"),
                "profile.construction_constraints.artifact_semantics",
                "unknown",
            ),
            requires_source_build=_ensure_bool(
                data.get("requires_source_build"),
                "profile.construction_constraints.requires_source_build",
            ),
            source_build_reason=_ensure_str(
                data.get("source_build_reason"),
                "profile.construction_constraints.source_build_reason",
            ),
            requires_build_time_configuration=_ensure_bool(
                data.get("requires_build_time_configuration"),
                "profile.construction_constraints.requires_build_time_configuration",
            ),
            setup_requirements=_ensure_list_of_str(
                data.get("setup_requirements"),
                "profile.construction_constraints.setup_requirements",
            ),
            forbidden_choices=_ensure_list_of_str(
                data.get("forbidden_choices"),
                "profile.construction_constraints.forbidden_choices",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return asdict(self)


@dataclass
class EnvironmentProfile:
    """Structured reproduction profile output by the profiler."""

    profile_status: str
    target: TargetProfile
    asset: AssetProfile
    version: VersionProfile
    runtime: RuntimeProfile
    dockerhub_image_candidates: list[DockerHubImageCandidate]
    artifact_requirements: list[ArtifactRequirement]
    vulnerability_conditions: list[VulnerabilityCondition]
    construction_constraints: ConstructionConstraints
    notes: list[str]
    warnings: list[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EnvironmentProfile":
        """Restore the structured reproduction profile from profiler output."""
        target_data = data.get("target") if isinstance(data.get("target"), dict) else {}
        asset_data = data.get("asset") if isinstance(data.get("asset"), dict) else {}
        if not asset_data:
            asset_data = {
                "relevance_type": "",
                "component_name": "",
                "component_type": "",
                "vendor": "",
                "package_ecosystem": "unknown",
                "package_name": None,
            }
        version_data = (
            data.get("version") if isinstance(data.get("version"), dict) else {}
        )
        if not version_data:
            version_data = {
                "requested_version": None,
                "final_version": None,
                "selection_reason": "",
            }
        construction_data = (
            data.get("construction_constraints")
            if isinstance(data.get("construction_constraints"), dict)
            else {}
        )
        artifact_payload = data.get("artifact_requirements")
        return cls(
            profile_status=_ensure_str(
                data.get("profile_status"), "profile.profile_status", "partial"
            ),
            target=TargetProfile.from_dict(target_data),
            asset=AssetProfile.from_dict(asset_data),
            version=VersionProfile.from_dict(version_data),
            runtime=RuntimeProfile.from_dict(
                data.get("runtime") if isinstance(data.get("runtime"), dict) else {}
            ),
            dockerhub_image_candidates=[
                DockerHubImageCandidate.from_dict(item)
                for item in _ensure_list_of_dict(
                    data.get("dockerhub_image_candidates"),
                    "profile.dockerhub_image_candidates",
                )
            ],
            artifact_requirements=[
                ArtifactRequirement.from_dict(item)
                for item in _ensure_list_of_dict(
                    artifact_payload, "profile.artifact_requirements"
                )
            ],
            vulnerability_conditions=[
                VulnerabilityCondition.from_dict(item)
                for item in _ensure_list_of_dict(
                    data.get("vulnerability_conditions"),
                    "profile.vulnerability_conditions",
                )
            ],
            construction_constraints=ConstructionConstraints.from_dict(
                construction_data
            ),
            notes=_ensure_list_of_str(data.get("notes"), "profile.notes"),
            warnings=_ensure_list_of_str(data.get("warnings"), "profile.warnings"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return {
            "profile_status": self.profile_status,
            "target": self.target.to_dict(),
            "asset": self.asset.to_dict(),
            "version": self.version.to_dict(),
            "runtime": self.runtime.to_dict(),
            "dockerhub_image_candidates": [
                item.to_dict() for item in self.dockerhub_image_candidates
            ],
            "artifact_requirements": [
                item.to_dict() for item in self.artifact_requirements
            ],
            "vulnerability_conditions": [
                item.to_dict() for item in self.vulnerability_conditions
            ],
            "construction_constraints": self.construction_constraints.to_dict(),
            "notes": self.notes,
            "warnings": self.warnings,
        }


def _ensure_optional_str(value: Any, field_name: str) -> str | None:
    """Normalize a nullable field into a string or None."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or null.")
    normalized = value.strip()
    return normalized or None


@dataclass
class BuildPlan:
    """Build plan output by the planner."""

    build_path: str
    selected_version: str
    selected_image: str
    selected_download_url: str
    selected_package_repo: str
    selected_package_name: str
    build_style: str
    build_resources: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return asdict(self)


@dataclass
class ProbeRequest:
    """Artifact probe requested by the planner for code execution."""

    action: str
    db_type: str
    version: str

@dataclass
class EnvironmentPlan:
    """Final output of the planner agent."""

    build_plan: BuildPlan
    generation_requirements: dict[str, Any]
    verified_artifacts: list[ArtifactFact]

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return {
            "build_plan": self.build_plan.to_dict(),
            "generation_requirements": self.generation_requirements,
            "verified_artifacts": [item.to_dict() for item in self.verified_artifacts],
        }

@dataclass
class ImageResolution:
    """DockerHub image resolution result."""

    db_type: str
    requested_version: str
    namespace: str
    repository: str
    matched_tag: str
    image_ref: str
    strategy: str
    availability: str
    checked_candidates: list[str]
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable structure."""
        return asdict(self)


@dataclass
class PipelineResult:
    """Summary result for one complete run."""

    run_dir: Path
    task: TaskInput
    evidence: list[EvidenceItem]
    environment_plan: EnvironmentPlan
    artifacts: ProjectArtifacts

    def to_dict(self) -> dict[str, Any]:
        """Convert the whole pipeline result back to a log structure."""
        return {
            "run_dir": str(self.run_dir),
            "task": self.task.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "environment_plan": self.environment_plan.to_dict(),
            "artifacts": self.artifacts.to_dict(),
        }

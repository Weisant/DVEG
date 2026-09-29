"""Small fallback builders used by ablation experiments."""

from __future__ import annotations

from agent.models import BuildPlan, EnvironmentPlan, EnvironmentProfile, ParsedTaskBundle


DEFAULT_PORTS = {
    "postgresql": "5432",
    "postgres": "5432",
    "mysql": "3306",
    "mariadb": "3306",
    "redis": "6379",
    "mongodb": "27017",
    "mongo": "27017",
    "elasticsearch": "9200",
    "clickhouse": "8123",
}


def build_minimal_profile_from_parser(parsed: ParsedTaskBundle) -> EnvironmentProfile:
    """Replace the profiler with a schema-valid profile built from CVE parser evidence."""
    task = parsed.task
    db_type = parsed.inferred_db_type
    decision = parsed.vulnerability_info.get("database_decision", {})
    if not isinstance(decision, dict):
        decision = {}
    relevance_type = str(decision.get("database_relevance_type") or "core_server").strip()
    if relevance_type not in {
        "core_server",
        "builtin_component",
        "official_extension",
        "official_tool",
        "distribution_package",
        "unrelated",
    }:
        relevance_type = "core_server"
    component_name = str(decision.get("component_name") or db_type).strip()
    version = _first_cpe_version(parsed.vulnerability_info)
    project_name = db_type or task.cve_id.lower() or "db-env-project"
    return EnvironmentProfile.from_dict(
        {
            "profile_status": "ablation_minimal",
            "target": {
                "cve_id": task.cve_id,
                "project_name": project_name,
                "db_type": db_type,
            },
            "asset": {
                "relevance_type": relevance_type,
                "component_name": component_name,
                "component_type": "database",
                "vendor": "",
                "package_ecosystem": "unknown",
                "package_name": None,
            },
            "version": {
                "requested_version": None,
                "final_version": version or None,
                "candidate_versions": (
                    [
                        {
                            "version": version,
                            "ecosystem": "unknown",
                            "upstream_version": version,
                            "package_version": None,
                            "reason": "Minimal parser-derived version.",
                        }
                    ]
                    if version
                    else []
                ),
                "selection_reason": "Profiler disabled by ablation.",
            },
            "runtime": {
                "port": DEFAULT_PORTS.get(db_type, ""),
                "database": "",
                "username": "",
                "password": "",
                "root_password": "",
                "config": {},
            },
            "dockerhub_image_candidates": [],
            "artifact_requirements": [],
            "vulnerability_conditions": [],
            "construction_constraints": {
                "artifact_semantics": "unknown",
                "requires_source_build": False,
                "source_build_reason": "",
                "requires_build_time_configuration": False,
                "setup_requirements": [],
                "forbidden_choices": [],
            },
            "notes": ["Profiler disabled by ablation."],
            "warnings": [],
        }
    )


def _first_cpe_version(vulnerability_info: dict) -> str:
    for match in vulnerability_info.get("nvd", {}).get("cpe_matches", []):
        if not isinstance(match, dict) or match.get("cpe_part") != "a":
            continue
        for version_range in match.get("version_ranges", []):
            if not isinstance(version_range, dict):
                continue
            versions = version_range.get("versions")
            if isinstance(versions, list) and versions:
                return str(versions[0]).strip()
    return ""


def build_profile_direct_plan(profile: EnvironmentProfile) -> EnvironmentPlan:
    """Wrap a profile in an empty EnvironmentPlan shell for no-planner ablation."""
    build_plan = BuildPlan(
        build_path="profile_direct",
        selected_version="",
        selected_image="",
        selected_download_url="",
        selected_package_repo="",
        selected_package_name="",
        build_style="",
    )
    return EnvironmentPlan(
        build_plan=build_plan,
        generation_requirements={
            "planner_disabled": True,
            "raw_profile": profile.to_dict(),
            "project_name": profile.target.project_name,
            "cve_id": profile.target.cve_id,
            "db_type": profile.target.db_type,
            "component": {
                "relevance_type": profile.asset.relevance_type,
                "name": profile.asset.component_name,
                "type": profile.asset.component_type,
                "package_ecosystem": profile.asset.package_ecosystem,
                "package_name": profile.asset.package_name or "",
            },
            "runtime": profile.runtime.to_dict(),
            "artifact_requirements": [],
            "vulnerability_conditions": [],
            "construction_constraints": profile.construction_constraints.to_dict(),
            "template_requirements": {},
            "artifact_probe_results": [],
            "unresolved_required_artifacts": [],
            "manual_notes": [
                "Planner disabled by ablation; generator receives raw_profile only.",
                "No build path, image, package, download URL, or artifact was selected or verified.",
            ],
        },
        verified_artifacts=[],
    )

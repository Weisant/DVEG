"""LLM-driven structured CVE reproduction profile generator.

The profiler inherits the parser CVE task, database type inference, relevance
classification, and integrated evidence context to generate a stable
reproduction profile. The planner later consumes only this profile and does not
re-decide database type, affected asset, version, or configuration.
"""

from __future__ import annotations

import json
from typing import Callable

from agent.llm import JsonChatClient
from agent.models import EnvironmentProfile, TaskInput
from agent.prompt_loader import load_prompt

StatusCallback = Callable[[str], None]


def _update_status(status_callback: StatusCallback | None, operation: str) -> None:
    if status_callback is not None:
        status_callback(operation)


def build_environment_profile(
    task: TaskInput,
    inferred_db_type: str,
    vulnerability_info: dict,
    client: JsonChatClient,
    status_callback: StatusCallback | None = None,
) -> EnvironmentProfile:
    """Generate a structured reproduction profile from the task and parser context."""
    _update_status(status_callback, "Building compact parser evidence context")
    system_prompt = load_prompt("profiler.md")
    profiler_context = _build_profiler_context(
        vulnerability_info=vulnerability_info,
        inferred_db_type=inferred_db_type,
    )
    user_prompt = (
        "Output a structured EnvironmentProfile JSON from the validated CVE task and parser context below.\n\n"
        "Validated CVE task:\n"
        f"{json.dumps({'cve_id': task.cve_id}, ensure_ascii=False, indent=2)}\n\n"
        "Parser context for the profiler:\n"
        f"{json.dumps(profiler_context, ensure_ascii=False, indent=2)}"
    )
    _update_status(status_callback, "Generating EnvironmentProfile with the LLM")
    response = client.chat_json(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=0,
        model=client.settings.profiler_model,
    )
    _update_status(status_callback, "Validating the EnvironmentProfile schema")
    return EnvironmentProfile.from_dict(response)


def _build_profiler_context(
    *,
    vulnerability_info: dict,
    inferred_db_type: str,
) -> dict[str, object]:
    """Prepare the slim parser context consumed by the profiler."""
    database_decision = (
        vulnerability_info.get("database_decision")
        if isinstance(vulnerability_info.get("database_decision"), dict)
        else {}
    )
    nvd = (
        vulnerability_info.get("nvd")
        if isinstance(vulnerability_info.get("nvd"), dict)
        else {}
    )
    official_advisories = (
        vulnerability_info.get("official_advisories")
        if isinstance(vulnerability_info.get("official_advisories"), list)
        else []
    )
    reference_advisories = (
        vulnerability_info.get("reference_advisories")
        if isinstance(vulnerability_info.get("reference_advisories"), list)
        else []
    )
    has_cve_value = vulnerability_info.get("has_cve")
    evidence_status_value = vulnerability_info.get("evidence_status")
    has_cve = has_cve_value if isinstance(has_cve_value, bool) else False
    evidence_status = (
        evidence_status_value
        if isinstance(evidence_status_value, str) and evidence_status_value
        else _infer_evidence_status(
            nvd=nvd,
            official_advisories=official_advisories,
            reference_advisories=reference_advisories,
        )
    )
    cwe_ids: list[str] = []
    cwe_items = nvd.get("cwe")
    if isinstance(cwe_items, list):
        for item in cwe_items:
            if not isinstance(item, dict):
                continue
            cwe_id = str(item.get("value", "")).strip()
            if cwe_id and cwe_id not in cwe_ids:
                cwe_ids.append(cwe_id)

    version_evidence: list[dict[str, object]] = []
    os_distribution_evidence: list[dict[str, object]] = []
    cpe_matches = nvd.get("cpe_matches")
    if isinstance(cpe_matches, list):
        for match in cpe_matches:
            if not isinstance(match, dict):
                continue
            cpe_uri = str(match.get("cpe_uri", "")).strip()
            cpe_part = str(match.get("cpe_part") or _cpe_part_from_uri(cpe_uri)).strip()
            cpe_part_label = str(
                match.get("cpe_part_label") or _cpe_part_label(cpe_part)
            ).strip()
            version_ranges: list[dict[str, object]] = []
            raw_ranges = match.get("version_ranges")
            if isinstance(raw_ranges, list):
                for raw_range in raw_ranges:
                    if not isinstance(raw_range, dict):
                        continue
                    candidate_versions = []
                    versions = raw_range.get("versions")
                    if isinstance(versions, list):
                        for version in versions:
                            version = str(version).strip()
                            if not version:
                                continue
                            candidate_versions.append(
                                {
                                    "version": version,
                                    "cpe_uri": cpe_uri,
                                    "cpe_part": cpe_part,
                                    "cpe_part_label": cpe_part_label,
                                }
                            )
                    else:
                        cpe_records = raw_range.get("cpe_records")
                        if isinstance(cpe_records, list):
                            for record in cpe_records:
                                if not isinstance(record, dict):
                                    continue
                                candidate_versions.append(
                                    {
                                        "version": record.get("version", ""),
                                        "cpe_uri": record.get("cpe_uri", ""),
                                        "cpe_part": record.get("cpe_part")
                                        or _cpe_part_from_uri(
                                            str(record.get("cpe_uri", ""))
                                        ),
                                        "cpe_part_label": record.get("cpe_part_label")
                                        or _cpe_part_label(
                                            _cpe_part_from_uri(
                                                str(record.get("cpe_uri", ""))
                                            )
                                        ),
                                    }
                                )
                    version_ranges.append(
                        {
                            "from": raw_range.get("from", ""),
                            "from_inclusive": raw_range.get("from_inclusive", False),
                            "to": raw_range.get("to", ""),
                            "to_inclusive": raw_range.get("to_inclusive", False),
                            "candidate_versions": candidate_versions,
                        }
                    )
            version_evidence.append(
                {
                    "source_type": "cpe",
                    "cpe_uri": cpe_uri,
                    "cpe_part": cpe_part,
                    "cpe_part_label": cpe_part_label,
                    "version_ranges": version_ranges,
                }
            )
            if cpe_part == "o":
                os_distribution_evidence.append(
                    {
                        "source_type": "cpe",
                        "cpe_uri": cpe_uri,
                        "vendor": _cpe_field(cpe_uri, 3),
                        "product": _cpe_field(cpe_uri, 4),
                        "release": _cpe_field(cpe_uri, 5),
                        "version_ranges": version_ranges,
                    }
                )

    return {
        "has_cve": has_cve,
        "evidence_status": evidence_status,
        "inferred_db_type": inferred_db_type,
        "database_decision": database_decision,
        "vulnerability_summary": {
            "description": nvd.get("description", ""),
            "published_at": nvd.get("published_at", ""),
            "last_modified_at": nvd.get("last_modified_at", ""),
            "cwe_ids": cwe_ids,
        },
        "version_evidence": version_evidence,
        "os_distribution_evidence": os_distribution_evidence,
        "official_advisories": official_advisories,
        "reference_advisories": _compact_reference_advisories(reference_advisories),
    }


def _infer_evidence_status(
    *,
    nvd: dict,
    official_advisories: list,
    reference_advisories: list,
) -> str:
    """Infer the evidence status enum when the parser does not provide one explicitly."""
    return (
        "available"
        if nvd.get("available") or official_advisories or reference_advisories
        else "none"
    )


def _compact_reference_advisories(advisories: list) -> list[dict[str, object]]:
    compacted: list[dict[str, object]] = []
    for advisory in advisories[:5]:
        if not isinstance(advisory, dict):
            continue
        snippets = advisory.get("snippets")
        compacted.append(
            {
                "source_type": advisory.get("source_type", ""),
                "source_name": advisory.get("source_name", ""),
                "source_url": advisory.get("source_url", ""),
                "reliability": advisory.get("reliability", ""),
                "snippets": snippets[:5] if isinstance(snippets, list) else [],
            }
        )
    return compacted


def _cpe_part_from_uri(cpe_uri: str) -> str:
    return _cpe_field(cpe_uri, 2).lower()


def _cpe_part_label(cpe_part: str) -> str:
    return {
        "a": "application",
        "o": "operating_system",
        "h": "hardware",
    }.get(cpe_part, "unknown")


def _cpe_field(cpe_uri: str, index: int) -> str:
    parts = cpe_uri.split(":")
    if len(parts) <= index:
        return ""
    return str(parts[index]).strip()

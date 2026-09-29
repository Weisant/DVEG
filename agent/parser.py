"""CVE-only task parser.

This module validates a single CVE ID into `TaskInput` and directly calls
evidence tools to collect external evidence for that CVE.
"""

from __future__ import annotations

import json
from typing import Callable

from agent.llm import JsonChatClient
from agent.models import ParsedTaskBundle, TaskInput
from agent.prompt_loader import load_prompt
from tools.evidence_tools import (
    DATABASE_TYPE_ALIASES,
    cve_info_to_evidence_items,
    fetch_nvd_cve_info,
    fetch_official_advisories,
    fetch_reference_advisories,
    integrate_cve_info,
    load_cached_cve_info,
    normalize_cve_id,
    normalize_database_type,
    save_cached_cve_info,
)

StatusCallback = Callable[[str], None]
NoticeCallback = Callable[[str], None]


def _update_status(status_callback: StatusCallback | None, operation: str) -> None:
    if status_callback is not None:
        status_callback(operation)


def parse_task(
    raw_request: str,
    client: JsonChatClient,
    status_callback: StatusCallback | None = None,
) -> TaskInput:
    """Validate the single supported user input and wrap it in TaskInput."""
    del client
    raw_request = raw_request.strip()
    if not raw_request:
        raise ValueError("CVE input cannot be empty.")

    _update_status(status_callback, "Validating CVE input")
    cve_id = normalize_cve_id(raw_request)
    return TaskInput(
        cve_id=cve_id,
        db_type="",
        version="",
        port="",
        database="",
        username="",
        password="",
        root_password="",
        project_name="",
        config={},
        notes=[],
        raw_request=cve_id,
        requested_version="",
    )


def parse_task_bundle(
    raw_request: str,
    client: JsonChatClient,
    *,
    refresh_cve_cache: bool = False,
    status_callback: StatusCallback | None = None,
    notice_callback: NoticeCallback | None = None,
) -> ParsedTaskBundle:
    """Parse CVE input and complete CVE evidence collection inside the parser."""
    task = parse_task(raw_request, client, status_callback)
    integrated_cve_info = collect_integrated_cve_info(
        task,
        client,
        refresh_cache=refresh_cve_cache,
        status_callback=status_callback,
        notice_callback=notice_callback,
    )
    _update_status(status_callback, "Normalizing the profiler evidence context")
    profiler_vulnerability_info = build_profiler_vulnerability_info(
        task,
        integrated_cve_info,
    )
    evidence = cve_info_to_evidence_items(profiler_vulnerability_info)
    inferred_db_type = normalize_database_type(
        str(profiler_vulnerability_info.get("db_type", ""))
    )
    return ParsedTaskBundle(
        task=task,
        evidence=evidence,
        inferred_db_type=inferred_db_type,
        vulnerability_info=profiler_vulnerability_info,
    )


def collect_integrated_cve_info(
    task: TaskInput,
    client: JsonChatClient,
    *,
    refresh_cache: bool = False,
    status_callback: StatusCallback | None = None,
    notice_callback: NoticeCallback | None = None,
) -> dict:
    """Build integrated CVE information in cache, NVD, parser decision, and official advisory order."""
    cve_id = normalize_cve_id(task.cve_id)
    _update_status(status_callback, f"Checking local CVE cache: {cve_id}")
    cached_info = None if refresh_cache else load_cached_cve_info(cve_id)
    if cached_info is not None:
        _update_status(status_callback, f"Using cached CVE evidence: {cve_id}")
        if notice_callback is not None:
            notice_callback(f"✓ Parser cache hit: using cached evidence for {cve_id}")
        decision = cached_info.get("database_decision")
        if isinstance(decision, dict) and _is_unrelated_database_decision(decision):
            raise ValueError(f"{cve_id} is not a database-related vulnerability: {decision.get('reason', '')}")
        return _apply_inferred_database_decision(cached_info)

    collection_errors: list[str] = []
    try:
        _update_status(status_callback, f"Querying NVD for {cve_id}")
        nvd_info = fetch_nvd_cve_info(cve_id)
    except (RuntimeError, ValueError) as exc:
        raise RuntimeError(f"NVD query failed for {cve_id}: {exc}") from exc
    else:
        _update_status(status_callback, "Classifying database relevance with the LLM")
        database_decision = classify_cve_database_relevance(
            cve_id=cve_id,
            nvd_info=nvd_info,
            client=client,
        )
        if _is_unrelated_database_decision(database_decision):
            raise ValueError(
                f"{cve_id} is not a database-related vulnerability: "
                f"{database_decision.get('reason', 'parser did not provide a reason')}"
            )

    integrated_candidate = {
        "database_decision": database_decision,
        "nvd": nvd_info,
    }
    database_decision = _resolve_database_decision(integrated_candidate)
    db_type = normalize_database_type(str(database_decision.get("db_type", "")))
    if not db_type:
        raise ValueError(f"{cve_id} was classified as a database vulnerability, but the database type could not be determined.")

    _update_status(status_callback, "Collecting official database advisories")
    official_advisories = fetch_official_advisories(
        db_type=db_type,
        cve_id=cve_id,
        collection_errors=collection_errors,
    )
    _update_status(status_callback, "Collecting relevant NVD reference evidence")
    reference_advisories = fetch_reference_advisories(
        cve_id=cve_id,
        db_type=db_type,
        reference_urls=(
            nvd_info.get("references", [])
            if isinstance(nvd_info.get("references"), list)
            else []
        ),
        collection_errors=collection_errors,
    )
    _update_status(status_callback, "Integrating and caching CVE evidence")
    vulnerability_info = integrate_cve_info(
        cve_id=cve_id,
        database_decision=database_decision,
        nvd_info=nvd_info,
        official_advisories=official_advisories,
        reference_advisories=reference_advisories,
        collection_errors=collection_errors,
    )
    save_cached_cve_info(cve_id, vulnerability_info)
    return vulnerability_info


def build_profiler_vulnerability_info(
    task: TaskInput,
    integrated_cve_info: dict,
) -> dict:
    """Build the context passed from parser to profiler, including CVE evidence."""
    task_payload = {"cve_id": task.cve_id}
    has_cve = bool(task.cve_id.strip())
    if not integrated_cve_info:
        return {
            "has_cve": has_cve,
            "evidence_status": "none",
            "requested_db_type": "",
            "affected_db_types": [],
            "cve_input_info": {
                "cve_id": task.cve_id,
                "parsed_task": task_payload,
            },
            "cve_id": task.cve_id,
            "db_type": "",
            "database_decision": {},
            "nvd": {},
            "official_advisories": [],
            "reference_advisories": [],
            "collection_errors": [],
        }

    nvd = (
        integrated_cve_info.get("nvd")
        if isinstance(integrated_cve_info.get("nvd"), dict)
        else {}
    )
    official_advisories = (
        integrated_cve_info.get("official_advisories")
        if isinstance(integrated_cve_info.get("official_advisories"), list)
        else []
    )
    reference_advisories = (
        integrated_cve_info.get("reference_advisories")
        if isinstance(integrated_cve_info.get("reference_advisories"), list)
        else []
    )
    database_decision = (
        integrated_cve_info.get("database_decision")
        if isinstance(integrated_cve_info.get("database_decision"), dict)
        else {}
    )
    return {
        "schema_version": integrated_cve_info.get("schema_version", ""),
        "has_cve": has_cve,
        "evidence_status": _build_evidence_status(
            nvd=nvd,
            official_advisories=official_advisories,
            collection_errors=integrated_cve_info.get("collection_errors", []),
        ),
        "requested_db_type": "",
        "affected_db_types": database_decision.get("affected_db_types", []),
        "cve_input_info": {
            "cve_id": task.cve_id,
            "parsed_task": task_payload,
        },
        "cve_id": integrated_cve_info.get("cve_id", task.cve_id),
        "db_type": integrated_cve_info.get("db_type", ""),
        "database_decision": database_decision,
        "nvd": nvd,
        "official_advisories": official_advisories,
        "reference_advisories": reference_advisories,
        "collection_errors": integrated_cve_info.get("collection_errors", []),
        "cached_at": integrated_cve_info.get("cached_at", ""),
    }


def _build_evidence_status(
    *,
    nvd: dict,
    official_advisories: list,
    collection_errors: object,
) -> str:
    """Normalize parser evidence collection results into an enum directly consumable by the profiler."""
    has_errors = bool(collection_errors) if isinstance(collection_errors, list) else False
    has_evidence = bool(nvd.get("available") or official_advisories)
    if has_evidence and has_errors:
        return "partial"
    if has_evidence:
        return "available"
    if has_errors:
        return "unavailable"
    return "none"


def classify_cve_database_relevance(
    *,
    cve_id: str,
    nvd_info: dict,
    client: JsonChatClient,
) -> dict:
    """Ask the parser to decide whether the CVE is database-related based on NVD information."""
    system_prompt = load_prompt("parser.md")
    user_prompt = (
        "Request type: classify_cve\n"
        "Decide whether this CVE is a database-related vulnerability based on the NVD information below.\n\n"
        f"{json.dumps({'cve_id': cve_id, 'nvd': nvd_info}, ensure_ascii=False, indent=2)}"
    )
    response = client.chat_json(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=0,
        model=client.settings.parser_model,
    )
    return _normalize_database_decision(response)


def _normalize_database_decision(response: dict) -> dict:
    """Normalize the parser database relevance decision output."""
    database_relevance_type = _normalize_database_relevance_type(
        response.get("database_relevance_type")
    )
    db_type = normalize_database_type(str(response.get("db_type", "")))
    affected_db_types = _normalize_affected_db_types(response.get("affected_db_types"))
    if db_type and db_type not in affected_db_types:
        affected_db_types.append(db_type)
    return {
        "database_relevance_type": database_relevance_type,
        "explanation": str(response.get("explanation", "")).strip(),
        "db_type": db_type,
        "affected_db_types": affected_db_types,
        "product_name": str(response.get("product_name", "")).strip(),
        "component_name": str(response.get("component_name", "")).strip(),
        "reason": str(response.get("reason", "")).strip(),
        "confidence": str(response.get("confidence", "")).strip() or "medium",
    }


def _apply_inferred_database_decision(integrated_cve_info: dict) -> dict:
    """Normalize cached CVE info without accepting user-provided db_type overrides."""
    if not isinstance(integrated_cve_info, dict):
        return integrated_cve_info
    updated_info = dict(integrated_cve_info)
    updated_info["database_decision"] = _resolve_database_decision(updated_info)
    updated_info["db_type"] = updated_info["database_decision"].get("db_type", "")
    return updated_info


def _resolve_database_decision(integrated_cve_info: dict) -> dict:
    """Resolve the inferred target db_type while preserving all affected database products."""
    raw_decision = (
        integrated_cve_info.get("database_decision")
        if isinstance(integrated_cve_info.get("database_decision"), dict)
        else {}
    )
    decision = dict(raw_decision)
    inferred_db_type = normalize_database_type(str(decision.get("db_type", "")))
    affected_db_types = _normalize_affected_db_types(decision.get("affected_db_types"))
    affected_db_types.extend(
        item
        for item in _affected_db_types_from_nvd(integrated_cve_info.get("nvd"))
        if item not in affected_db_types
    )
    if inferred_db_type and inferred_db_type not in affected_db_types:
        affected_db_types.append(inferred_db_type)

    decision["db_type"] = inferred_db_type
    decision["affected_db_types"] = affected_db_types
    return decision


def _normalize_affected_db_types(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for item in value:
        db_type = normalize_database_type(str(item))
        if db_type and db_type not in normalized:
            normalized.append(db_type)
    return normalized


def _affected_db_types_from_nvd(nvd_info: object) -> list[str]:
    if not isinstance(nvd_info, dict):
        return []
    cpe_matches = nvd_info.get("cpe_matches")
    if not isinstance(cpe_matches, list):
        return []
    affected: list[str] = []
    for match in cpe_matches:
        if not isinstance(match, dict):
            continue
        cpe_uri = str(match.get("cpe_uri", "")).strip()
        cpe_part = str(match.get("cpe_part") or _cpe_part_from_uri(cpe_uri)).strip()
        if cpe_part and cpe_part != "a":
            continue
        for db_type in _database_types_from_cpe_uri(cpe_uri):
            if db_type and db_type not in affected:
                affected.append(db_type)
    return affected


def _cpe_part_from_uri(cpe_uri: str) -> str:
    parts = cpe_uri.split(":")
    if len(parts) < 3:
        return ""
    return parts[2].strip().lower()


def _database_types_from_cpe_uri(cpe_uri: str) -> list[str]:
    parts = cpe_uri.split(":")
    if len(parts) < 6:
        return []
    values = [parts[4], parts[3]]
    known_db_types = set(DATABASE_TYPE_ALIASES.values())
    normalized: list[str] = []
    for value in values:
        db_type = normalize_database_type(value)
        if db_type not in known_db_types:
            continue
        if db_type and db_type not in normalized:
            normalized.append(db_type)
    return normalized


def _normalize_database_relevance_type(value: object) -> str:
    """Normalize the database vulnerability relevance category."""
    allowed = {
        "core_server",
        "builtin_component",
        "official_extension",
        "official_tool",
        "distribution_package",
        "unrelated",
    }
    normalized = str(value or "").strip().lower()
    return normalized if normalized in allowed else "unrelated"


def _is_unrelated_database_decision(decision: dict) -> bool:
    """Return whether the parser classification is explicitly unrelated to database vulnerabilities."""
    relevance_type = str(decision.get("database_relevance_type", "")).strip().lower()
    return relevance_type == "unrelated"

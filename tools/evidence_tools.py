"""Tools for CVE information extraction, official advisory fetching, and local persistence."""

from __future__ import annotations

import json
import html as html_lib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request

import trafilatura

from agent.models import EvidenceItem


REQUEST_TIMEOUT_SECONDS = 60
CPE_VERSION_LIMIT = 10
BASE_DIR = Path(__file__).resolve().parents[1]
CVE_INFO_DIR = BASE_DIR / "data" / "cve_info"
AGENT_ENV_FILE = BASE_DIR / "agent" / ".env"
SCHEMA_VERSION = "10"
MAX_REFERENCE_ADVISORIES = 5
MAX_REFERENCE_SNIPPETS_PER_ADVISORY = 8
MAX_REFERENCE_SNIPPET_CHARS = 700
REFERENCE_WINDOW_CHARS = 900
CPE_PART_LABELS = {
    "a": "application",
    "o": "operating_system",
    "h": "hardware",
}
REFERENCE_VERSION_KEYWORDS = {
    "affected version",
    "affected versions",
    "affected in",
    "fixed version",
    "fixed versions",
    "fixed in",
    "fixed in version",
    "fixed in versions",
    "found in version",
    "found in versions",
    "marked as found",
    "before",
    "prior to",
    "introduced",
    "through",
    "up to",
    "vulnerable version",
    "vulnerable versions",
    "version",
    "versions",
}
HIGH_VALUE_VERSION_PHRASES = {
    "affected version",
    "affected versions",
    "affected in",
    "fixed in version",
    "fixed in versions",
    "found in version",
    "found in versions",
    "marked as found",
    "vulnerable version",
    "vulnerable versions",
}
REFERENCE_PACKAGE_KEYWORDS = {
    "package",
    "packages",
    "redis-server",
    "postgresql",
    "mysql",
    "mariadb",
    "mongodb",
    "debian",
    "ubuntu",
    "rhel",
    "red hat",
    "alpine",
    "buster",
    "bullseye",
    "bookworm",
    "focal",
    "jammy",
    "bionic",
}
REFERENCE_CONFIG_KEYWORDS = {
    "configuration",
    "config",
    "setting",
    "option",
    "enabled",
    "disabled",
    "default",
    "module",
    "extension",
    "plugin",
    "compile",
    "linked",
    "packaging",
}
REFERENCE_WINDOW_KEYWORDS = (
    "affected version",
    "affected versions",
    "affected in",
    "fixed version",
    "fixed versions",
    "fixed in",
    "fixed in version",
    "fixed in versions",
    "found in version",
    "found in versions",
    "marked as found",
    "before",
    "prior to",
    "introduced",
    "through",
    "up to",
    "vulnerable version",
    "vulnerable versions",
    "version",
    "versions",
    "package",
    "packages",
    "configuration",
    "config",
    "setting",
    "option",
    "enabled",
    "disabled",
    "module",
    "extension",
    "plugin",
    "build",
    "compile",
    "packaging",
)

DATABASE_TYPE_ALIASES = {
    "apachecouchdb": "couchdb",
    "apachesolr": "solr",
    "cassandra": "cassandra",
    "clickhouse": "clickhouse",
    "crate": "cratedb",
    "cratedb": "cratedb",
    "couchdb": "couchdb",
    "duck": "duckdb",
    "duckdb": "duckdb",
    "elasticsearch": "elasticsearch",
    "h2": "h2database",
    "h2database": "h2database",
    "h2db": "h2database",
    "influxdb": "influxdb",
    "mariadb": "mariadb",
    "mongo": "mongo",
    "mongodb": "mongo",
    "mysql": "mysql",
    "neo4j": "neo4j",
    "opentsdb": "opentsdb",
    "pingcap": "tidb",
    "pingcaptidb": "tidb",
    "postgres": "postgres",
    "postgresql": "postgres",
    "redis": "redis",
    "solr": "solr",
    "sqlite": "sqlite",
    "tidb": "tidb",
}

OFFICIAL_SECURITY_ADVISORIES = {
    "postgres": [
        {
            "source_name": "PostgreSQL Security",
            "url": "https://www.postgresql.org/support/security/",
        }
    ],
    "mysql": [
        {
            "source_name": "Oracle Critical Patch Updates",
            "url": "https://www.oracle.com/security-alerts/",
        }
    ],
    "mariadb": [
        {
            "source_name": "MariaDB Security",
            "url": "https://mariadb.com/kb/en/security/",
        }
    ],
    "redis": [
        {
            "source_name": "Redis Security",
            "url": "https://redis.io/docs/latest/operate/oss_and_stack/management/security/",
        }
    ],
    "mongo": [
        {
            "source_name": "MongoDB Alerts",
            "url": "https://www.mongodb.com/alerts",
        }
    ],
    "elasticsearch": [
        {
            "source_name": "Elastic Security Announcements",
            "url": "https://discuss.elastic.co/c/announcements/security-announcements/31",
        }
    ],
    "clickhouse": [
        {
            "source_name": "ClickHouse Security",
            "url": "https://clickhouse.com/docs/whats-new/security-changelog",
        }
    ],
    "cratedb": [
        {
            "source_name": "CrateDB Security",
            "url": "https://cratedb.com/security/",
        }
    ],
    "couchdb": [
        {
            "source_name": "Apache CouchDB Security Issues / CVEs",
            "url": "https://docs.couchdb.org/en/stable/cve/index.html",
        }
    ],
    "duckdb": [
        {
            "source_name": "DuckDB Security Advisories",
            "url": "https://github.com/duckdb/duckdb/security/advisories",
        }
    ],
    "h2database": [
        {
            "source_name": "H2 Database Security Advisories",
            "url": "https://github.com/h2database/h2database/security/advisories",
        }
    ],
    "influxdb": [
        {
            "source_name": "InfluxData Security",
            "url": "https://www.influxdata.com/security/",
        }
    ],
    "neo4j": [
        {
            "source_name": "Neo4j Security",
            "url": "https://neo4j.com/security/advisories/",
        }
    ],
    "opentsdb": [
        {
            "source_name": "OpenTSDB Security Advisories",
            "url": "https://github.com/OpenTSDB/opentsdb/security/advisories",
        }
    ],
    "solr": [
        {
            "source_name": "Apache Solr Security",
            "url": "https://solr.apache.org/security-news.html",
        }
    ],
    "sqlite": [
        {
            "source_name": "SQLite Vulnerabilities",
            "url": "https://www.sqlite.org/cves.html",
        }
    ],
    "tidb": [
        {
            "source_name": "TiDB Security Advisories",
            "url": "https://github.com/pingcap/tidb/security/advisories",
        }
    ],
}


def normalize_cve_id(value: str) -> str:
    """Validate and normalize a CVE ID."""
    cve_id = value.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,10}", cve_id):
        raise ValueError(f"Invalid CVE ID: {value}")
    return cve_id


def normalize_database_type(value: str) -> str:
    """Normalize database names into stable internal project identifiers."""
    compact = value.strip().lower().replace(" ", "").replace("_", "").replace("-", "")
    for alias, canonical in DATABASE_TYPE_ALIASES.items():
        if alias in compact:
            return canonical
    return value.strip().lower()


def load_cached_cve_info(cve_id: str) -> dict[str, Any] | None:
    """Prefer reading integrated CVE information from data/cve_info."""
    path = _cve_cache_path(normalize_cve_id(cve_id))
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse cache file: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Invalid cache file format: {path}")
    if str(payload.get("schema_version", "")) != SCHEMA_VERSION:
        return None
    return payload


def save_cached_cve_info(cve_id: str, payload: dict[str, Any]) -> None:
    """Save integrated CVE information as JSON."""
    path = _cve_cache_path(normalize_cve_id(cve_id))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def fetch_nvd_cve_info(cve_id: str) -> dict[str, Any]:
    """Query NVD and extract full CVE information plus lightweight index fields."""
    cve_id = normalize_cve_id(cve_id)
    source_url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?"
        + parse.urlencode({"cveIds": cve_id})
    )
    payload = _fetch_json(source_url, headers=_nvd_request_headers())
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise ValueError(f"NVD did not return a vulnerability record for {cve_id}.")

    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise ValueError(f"NVD returned an invalid record format for {cve_id}.")
    raw_cve = item["cve"]
    return extract_nvd_info(cve_id=cve_id, raw_cve=raw_cve, source_url=source_url)


def build_unavailable_nvd_info(cve_id: str) -> dict[str, Any]:
    """Build a placeholder structure for unavailable NVD data."""
    cve_id = normalize_cve_id(cve_id)
    source_url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?"
        + parse.urlencode({"cveIds": cve_id})
    )
    return {
        "available": False,
        "source_url": source_url,
        "description": "",
        "published_at": "",
        "last_modified_at": "",
        "references": [],
        "cpe_matches": [],
        "cvss": [],
        "cwe": [],
    }


def extract_nvd_info(
    *,
    cve_id: str,
    raw_cve: dict[str, Any],
    source_url: str,
) -> dict[str, Any]:
    """Extract fields directly consumable by the profiler from an NVD CVE object."""
    return {
        "available": True,
        "source_url": source_url,
        "description": _extract_english_description(raw_cve),
        "published_at": _ensure_str(raw_cve.get("published")),
        "last_modified_at": _ensure_str(raw_cve.get("lastModified")),
        "references": _extract_reference_urls(raw_cve),
        "cpe_matches": _extract_all_cpe_matches(raw_cve),
        "cvss": _extract_cvss_metrics(raw_cve),
        "cwe": _extract_cwe_info(raw_cve),
    }


def fetch_official_advisories(
    *,
    db_type: str,
    cve_id: str,
    collection_errors: list[str],
) -> list[dict[str, Any]]:
    """Fetch official security advisories by database type and return text snippets near the CVE."""
    canonical_db_type = normalize_database_type(db_type)
    cve_id = normalize_cve_id(cve_id)
    sources = OFFICIAL_SECURITY_ADVISORIES.get(canonical_db_type, [])
    if not sources:
        collection_errors.append(
            f"official advisory sources not configured for db_type={canonical_db_type}"
        )
        return []

    advisories: list[dict[str, Any]] = []
    for source in sources:
        source_name = source["source_name"]
        source_url = source["url"]
        try:
            html = _fetch_text(source_url)
        except RuntimeError as exc:
            collection_errors.append(f"{source_name}: fetch failed: {exc}")
            continue

        page_text = _extract_webpage_text(html)
        snippet = _extract_cve_nearby_snippet(page_text, cve_id)
        if not snippet:
            collection_errors.append(f"{source_name}: {cve_id} not found")
            continue

        advisories.append(
            {
                "source_name": source_name,
                "matched": True,
                "snippet": snippet,
            }
        )
    return advisories


def fetch_reference_advisories(
    *,
    cve_id: str,
    db_type: str,
    reference_urls: list[str],
    collection_errors: list[str],
) -> list[dict[str, Any]]:
    """Fetch NVD reference URLs and keep only relevant evidence snippets."""
    cve_id = normalize_cve_id(cve_id)
    advisories: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for url in reference_urls:
        if len(advisories) >= MAX_REFERENCE_ADVISORIES:
            break
        url = _ensure_str(url).strip()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        source = _classify_reference_url(url)
        try:
            html = _fetch_text(url)
        except RuntimeError as exc:
            collection_errors.append(f"{source['source_name']}: reference fetch failed: {exc}")
            continue
        snippets = _extract_reference_snippets(
            html=html,
            source_url=url,
            cve_id=cve_id,
            db_type=db_type,
        )
        if not snippets:
            collection_errors.append(f"{source['source_name']}: no relevant reference snippets found")
            continue
        advisories.append(
            {
                "source_type": source["source_type"],
                "source_name": source["source_name"],
                "source_url": url,
                "matched": True,
                "reliability": source["reliability"],
                "snippets": snippets,
            }
        )
    return advisories


def build_user_supplied_database_decision(
    *,
    db_type: str,
    nvd_error: str,
) -> dict[str, Any]:
    """Build a low-confidence decision when NVD is unavailable but the user explicitly provided a database type."""
    canonical_db_type = normalize_database_type(db_type)
    return {
        "database_relevance_type": "core_server",
        "db_type": canonical_db_type,
        "product_name": canonical_db_type,
        "component_name": canonical_db_type,
        "reason": (
            "NVD unavailable; continued with explicit user-provided "
            f"db_type={canonical_db_type}. Error: {nvd_error}"
        ),
        "confidence": "low",
    }


def integrate_cve_info(
    *,
    cve_id: str,
    database_decision: dict[str, Any],
    nvd_info: dict[str, Any],
    official_advisories: list[dict[str, Any]],
    reference_advisories: list[dict[str, Any]],
    collection_errors: list[str],
) -> dict[str, Any]:
    """Integrate NVD, parser decision, official advisories, and trusted references."""
    cve_id = normalize_cve_id(cve_id)
    db_type = normalize_database_type(str(database_decision.get("db_type", "")))
    return {
        "schema_version": SCHEMA_VERSION,
        "cve_id": cve_id,
        "db_type": db_type,
        "database_decision": database_decision,
        "nvd": nvd_info,
        "official_advisories": official_advisories,
        "reference_advisories": reference_advisories,
        "collection_errors": collection_errors,
        "cached_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def cve_info_to_evidence_items(cve_info: dict[str, Any]) -> list[EvidenceItem]:
    """Compress integrated CVE information into existing EvidenceItem entries for log and profiler compatibility."""
    if not cve_info:
        return []

    cve_id = _ensure_str(cve_info.get("cve_id"))
    nvd_info = cve_info.get("nvd") if isinstance(cve_info.get("nvd"), dict) else {}
    decision = (
        cve_info.get("database_decision")
        if isinstance(cve_info.get("database_decision"), dict)
        else {}
    )
    advisories = (
        cve_info.get("official_advisories")
        if isinstance(cve_info.get("official_advisories"), list)
        else []
    )
    reference_advisories = (
        cve_info.get("reference_advisories")
        if isinstance(cve_info.get("reference_advisories"), list)
        else []
    )

    items = [
        EvidenceItem(
            source_type="integrated_cve_info",
            source_url=_ensure_str(nvd_info.get("source_url")),
            title=f"{cve_id} integrated vulnerability information",
            published_at=_ensure_str(nvd_info.get("published_at")),
            reliability="high" if nvd_info.get("available") else "low",
            snippet=_ensure_str(nvd_info.get("description"))[:900],
            claims=[
                "database_decision_json: "
                + json.dumps(decision, ensure_ascii=False),
                "cpe_match_count: "
                + str(len(nvd_info.get("cpe_matches") or [])),
                "official_advisory_match_count: " + str(len(advisories)),
                "reference_advisory_match_count: " + str(len(reference_advisories)),
            ],
        )
    ]

    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue
        items.append(
            EvidenceItem(
                source_type="official_advisory",
                source_url="",
                title=_ensure_str(advisory.get("source_name")),
                published_at="",
                reliability="high",
                snippet=_ensure_str(advisory.get("snippet"))[:900],
                claims=[],
            )
        )
    for advisory in reference_advisories:
        if not isinstance(advisory, dict):
            continue
        snippets = advisory.get("snippets")
        snippet_text = ""
        if isinstance(snippets, list):
            snippet_text = "\n".join(
                _ensure_str(item.get("text")) if isinstance(item, dict) else ""
                for item in snippets[:3]
            ).strip()
        items.append(
            EvidenceItem(
                source_type="reference_advisory",
                source_url=_ensure_str(advisory.get("source_url")),
                title=_ensure_str(advisory.get("source_name")),
                published_at="",
                reliability=_ensure_str(advisory.get("reliability")) or "high",
                snippet=snippet_text[:900],
                claims=[],
            )
        )
    return items


def _cve_cache_path(cve_id: str) -> Path:
    year = cve_id.split("-")[1]
    return CVE_INFO_DIR / year / f"{cve_id}.json"


def _extract_english_description(raw_cve: dict[str, Any]) -> str:
    descriptions = raw_cve.get("descriptions")
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if not isinstance(item, dict):
            continue
        if item.get("lang") == "en":
            return _ensure_str(item.get("value")).strip()
    return ""


def _extract_reference_urls(raw_cve: dict[str, Any]) -> list[str]:
    references = raw_cve.get("references")
    if not isinstance(references, list):
        return []
    urls: list[str] = []
    seen: set[str] = set()
    for item in references:
        if not isinstance(item, dict):
            continue
        url = _ensure_str(item.get("url")).strip()
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def _classify_reference_url(url: str) -> dict[str, str]:
    """Classify NVD reference URLs without filtering out unknown domains."""
    parsed = parse.urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    if host.startswith("www."):
        host = host[4:]

    if host == "security-tracker.debian.org":
        return _reference_source("distribution_advisory", "Debian Security Tracker")
    if host == "debian.org" and path.startswith("/security/"):
        return _reference_source("distribution_advisory", "Debian Security Advisory")
    if host == "ubuntu.com" and path.startswith("/security/"):
        return _reference_source("distribution_advisory", "Ubuntu Security")
    if host == "access.redhat.com" and path.startswith("/security/"):
        return _reference_source("distribution_advisory", "Red Hat Security")
    if host.endswith("alpinelinux.org"):
        return _reference_source("distribution_advisory", "Alpine Security")
    if host == "github.com" and "/security/advisories" in path:
        return _reference_source("source_repository_advisory", "GitHub Security Advisory")
    if host == "github.com" and path.startswith("/advisories/"):
        return _reference_source("package_ecosystem_advisory", "GitHub Advisory Database")
    if host.endswith("postgresql.org"):
        return _reference_source("vendor_advisory", "PostgreSQL Security")
    if host.endswith("redis.io"):
        return _reference_source("vendor_advisory", "Redis Security")
    if host.endswith("mongodb.com"):
        return _reference_source("vendor_advisory", "MongoDB Security")
    if host.endswith("mariadb.com"):
        return _reference_source("vendor_advisory", "MariaDB Security")
    if host.endswith("oracle.com") and "security" in path:
        return _reference_source("vendor_advisory", "Oracle Security Alert")
    if host.endswith("apache.org"):
        return _reference_source("vendor_advisory", "Apache Security")
    if host.endswith("elastic.co"):
        return _reference_source("vendor_advisory", "Elastic Security")
    return _reference_source("nvd_reference", host or "NVD Reference", reliability="medium")


def _reference_source(
    source_type: str,
    source_name: str,
    *,
    reliability: str = "high",
) -> dict[str, str]:
    return {
        "source_type": source_type,
        "source_name": source_name,
        "reliability": reliability,
    }


def _extract_reference_snippets(
    *,
    html: str,
    source_url: str,
    cve_id: str,
    db_type: str,
) -> list[dict[str, str]]:
    full_text = _extract_webpage_text(html)
    blocks = _reference_candidate_texts(
        full_text=full_text,
        cve_id=cve_id,
        db_type=db_type,
    )
    selected: list[tuple[int, dict[str, str]]] = []
    seen: set[str] = set()
    for block in blocks:
        if _is_low_value_reference_block(block):
            continue
        reasons = _reference_snippet_reasons(block, cve_id=cve_id, db_type=db_type)
        if not reasons:
            continue
        if reasons == ["package_context"]:
            continue
        text = block[:MAX_REFERENCE_SNIPPET_CHARS].strip()
        if not text or text in seen:
            continue
        seen.add(text)
        selected.append(
            (
                _reference_snippet_score(reasons, text),
                {"reason": ",".join(reasons), "text": text},
            )
        )
    for artifact_snippet in _extract_reference_artifact_link_snippets(
        html=html,
        source_url=source_url,
        db_type=db_type,
    ):
        text = artifact_snippet["text"]
        if text in seen:
            continue
        seen.add(text)
        selected.append((100, artifact_snippet))
    for debian_snippet in _extract_debian_version_event_snippets(
        html=html,
        full_text=full_text,
        db_type=db_type,
    ):
        text = debian_snippet["text"]
        if text in seen:
            continue
        seen.add(text)
        selected.append((_debian_version_event_score(debian_snippet), debian_snippet))
    selected.sort(key=lambda item: item[0], reverse=True)
    return [item for _score, item in selected[:MAX_REFERENCE_SNIPPETS_PER_ADVISORY]]


def _extract_reference_artifact_link_snippets(
    *,
    html: str,
    source_url: str,
    db_type: str,
) -> list[dict[str, str]]:
    db = db_type.strip().lower()
    tokens = [db] if db else []
    if db == "postgres":
        tokens.append("postgresql")
    if db == "mongo":
        tokens.append("mongodb")

    snippets: list[dict[str, str]] = []
    for href in re.findall(r"""href=["']([^"']+)["']""", html, flags=re.I):
        url = parse.urljoin(source_url, href)
        lowered = parse.unquote(url).lower()
        if not lowered.endswith((".tar.gz", ".tgz", ".zip", ".tar.xz", ".tar.bz2")):
            continue
        if tokens and not any(token in lowered for token in tokens):
            continue
        if not re.search(
            r"\d+(?:[._-]\d+)+(?:[._-]?(?:alpha|beta|rc|pre|preview)\d*)?",
            lowered,
        ):
            continue
        snippets.append(
            {
                "reason": "artifact_link,version_context,package_context",
                "text": f"Reference artifact link: {url}",
            }
        )
    return snippets[:MAX_REFERENCE_SNIPPETS_PER_ADVISORY]


def _extract_debian_version_event_snippets(
    *,
    html: str,
    full_text: str,
    db_type: str,
) -> list[dict[str, str]]:
    package = re.escape(db_type.strip().lower())
    if not package:
        return []
    version = r"[A-Za-z0-9~:+][A-Za-z0-9._~:+-]*[A-Za-z0-9~+]"
    html_patterns = [
        (rf"<p>\s*(Found in versions? {package}/.*?)\s*</p>", "debian_found_summary"),
        (rf"<p>\s*(Fixed in versions? {package}/.*?)\s*</p>", "debian_fixed_summary"),
    ]
    patterns = [
        (rf"Marked as found in versions? {package}/{version}", "debian_found_version_event"),
        (rf"Subject: Bug#[0-9]+: fixed in {package} {version}", "debian_fixed_version_event"),
        (rf"Source-Version: {version}", "debian_closing_source_version"),
    ]
    snippets: list[dict[str, str]] = []
    seen: set[str] = set()
    for pattern, reason in html_patterns:
        for match in re.finditer(pattern, html, flags=re.I | re.S):
            text = _clean_text(html_lib.unescape(re.sub(r"<[^>]+>", " ", match.group(1))))
            if text in seen:
                continue
            seen.add(text)
            snippets.append(
                {
                    "reason": f"{reason},version_context,package_context",
                    "text": text,
                }
            )
    for pattern, reason in patterns:
        for match in re.finditer(pattern, full_text, flags=re.I):
            text = match.group(0).strip()
            if text in seen:
                continue
            seen.add(text)
            if text.lower().startswith("source-version:"):
                text = f"Debian closing source version: {text}"
            snippets.append(
                {
                    "reason": f"{reason},version_context,package_context",
                    "text": text,
                }
            )
    return snippets[:MAX_REFERENCE_SNIPPETS_PER_ADVISORY]


def _debian_version_event_score(snippet: dict[str, str]) -> int:
    reason = snippet.get("reason", "")
    if "debian_found_summary" in reason or "debian_fixed_summary" in reason:
        return 95
    if "debian_closing_source_version" in reason:
        return 85
    return 90


def _reference_candidate_texts(
    *,
    full_text: str,
    cve_id: str,
    db_type: str,
) -> list[str]:
    """Build source-agnostic candidate snippets from extracted page text."""
    candidates: list[str] = []
    for keyword in _reference_window_keywords(cve_id=cve_id, db_type=db_type):
        for index in _find_keyword_indexes(full_text, keyword):
            candidates.append(_reference_text_window(full_text, index))
    if not candidates and full_text:
        candidates.append(full_text[:REFERENCE_WINDOW_CHARS])
    return _dedupe_reference_candidates(candidates)


def _reference_window_keywords(*, cve_id: str, db_type: str) -> list[str]:
    keywords = [cve_id, *REFERENCE_WINDOW_KEYWORDS]
    if db_type:
        keywords.append(db_type)
    return [keyword for keyword in keywords if keyword]


def _find_keyword_indexes(text: str, keyword: str) -> list[int]:
    if not text or not keyword:
        return []
    indexes: list[int] = []
    lowered = text.lower()
    needle = keyword.lower()
    start = 0
    while len(indexes) < 5:
        index = lowered.find(needle, start)
        if index < 0:
            break
        indexes.append(index)
        start = index + max(1, len(needle))
    return indexes


def _reference_text_window(text: str, index: int) -> str:
    half_window = REFERENCE_WINDOW_CHARS // 2
    start = max(0, index - half_window)
    end = min(len(text), index + half_window)
    while start > 0 and text[start] not in ".!?\n;":
        start -= 1
    while end < len(text) and text[end - 1] not in ".!?\n;":
        end += 1
    return _trim_reference_noise(text[start:end].strip(" -|:;"))


def _dedupe_reference_candidates(candidates: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        text = _clean_text(candidate)
        key = _reference_candidate_key(text)
        if not text or key in seen:
            continue
        seen.add(key)
        deduped.append(text)
    return deduped


def _reference_candidate_key(text: str) -> str:
    lowered = re.sub(r"\s+", " ", text.lower()).strip()
    cve_index = lowered.find("cve-")
    if cve_index >= 0:
        return lowered[cve_index : cve_index + 320]
    return lowered[:240]


def _trim_reference_noise(text: str) -> str:
    lowered = text.lower()
    markers = [
        "package :",
        "package:",
        "cve id :",
        "cve id:",
        "cve-",
        "affected version",
        "affected versions",
        "affected in",
        "fixed version",
        "fixed versions",
        "fixed in",
        "fixed in version",
        "fixed in versions",
        "found in version",
        "found in versions",
        "marked as found",
        "vulnerable version",
        "vulnerable versions",
        "vulnerability",
    ]
    marker_indexes = [
        lowered.find(marker)
        for marker in markers
        if 0 <= lowered.find(marker) <= len(text) // 2
    ]
    if marker_indexes:
        return text[min(marker_indexes) :].strip(" -|:;")
    return text


def _reference_snippet_reasons(block: str, *, cve_id: str, db_type: str) -> list[str]:
    text = block.lower()
    reasons: list[str] = []
    if cve_id.lower() in text:
        reasons.append("cve_context")
    if _contains_any_keyword(text, REFERENCE_VERSION_KEYWORDS):
        reasons.append("version_context")
    package_keywords = set(REFERENCE_PACKAGE_KEYWORDS)
    if db_type:
        package_keywords.add(db_type.lower())
    if _contains_any_keyword(text, package_keywords):
        reasons.append("package_context")
    if _contains_any_keyword(text, REFERENCE_CONFIG_KEYWORDS):
        reasons.append("config_context")
    return reasons


def _contains_any_keyword(text: str, keywords: set[str]) -> bool:
    return any(keyword in text for keyword in keywords)


def _reference_snippet_score(reasons: list[str], text: str) -> int:
    weights = {
        "cve_context": 8,
        "version_context": 5,
        "config_context": 3,
        "package_context": 2,
    }
    score = sum(weights.get(reason, 0) for reason in reasons)
    lowered = text.lower()
    if any(phrase in lowered for phrase in HIGH_VALUE_VERSION_PHRASES):
        score += 10
    if len(text) >= 120:
        score += 1
    return score


def _is_low_value_reference_block(block: str) -> bool:
    text = block.strip().lower()
    if not text:
        return True
    low_value_prefixes = (
        "to :",
        "subject :",
        "from :",
        "date :",
        "message-id :",
        "message-id:",
        "reply-to :",
        "reply to:",
        "prev by ",
        "next by ",
        "previous by ",
        "index(es):",
    )
    if text.startswith(low_value_prefixes):
        return True
    if text in {"date", "thread"}:
        return True
    if len(text) < 120 and ("@lists." in text or "mailing list:" in text):
        return True
    return False


def _extract_all_cpe_matches(raw_cve: dict[str, Any]) -> list[dict[str, Any]]:
    """Recursively extract NVD cpeMatch entries and group range summaries by cpe_uri."""
    configurations = raw_cve.get("configurations")
    if not isinstance(configurations, list):
        return []

    grouped_matches: dict[str, list[dict[str, Any]]] = {}
    for config in configurations:
        if not isinstance(config, dict):
            continue
        _collect_cpe_matches(config.get("nodes"), grouped_matches)
    return [
        {
            "cpe_uri": cpe_uri,
            "cpe_part": _extract_cpe_part(cpe_uri),
            "cpe_part_label": _cpe_part_label(cpe_uri),
            "version_ranges": version_ranges,
        }
        for cpe_uri, version_ranges in grouped_matches.items()
    ]


def _collect_cpe_matches(
    nodes: object,
    grouped_matches: dict[str, list[dict[str, Any]]],
) -> None:
    if not isinstance(nodes, list):
        return
    for node in nodes:
        if not isinstance(node, dict):
            continue
        cpe_matches = node.get("cpeMatch")
        if isinstance(cpe_matches, list):
            for item in cpe_matches:
                if not isinstance(item, dict):
                    continue
                cpe_uri = _ensure_str(item.get("criteria")).strip()
                if not cpe_uri:
                    continue
                grouped_matches.setdefault(cpe_uri, [])
                version_range = _extract_cpe_version_range(item, cpe_uri)
                if version_range:
                    cpe_records = _extract_cpe_records_from_match(item, cpe_uri)
                    _append_cpe_version_range(
                        grouped_matches[cpe_uri],
                        version_range,
                        cpe_records,
                    )
        _collect_cpe_matches(node.get("children"), grouped_matches)


def _extract_cpe_version_range(
    item: dict[str, Any],
    cpe_uri: str,
) -> dict[str, str | bool]:
    """Preserve exact version boundaries from NVD cpeMatch."""
    start_including = _ensure_str(item.get("versionStartIncluding")).strip()
    start_excluding = _ensure_str(item.get("versionStartExcluding")).strip()
    end_including = _ensure_str(item.get("versionEndIncluding")).strip()
    end_excluding = _ensure_str(item.get("versionEndExcluding")).strip()

    range_from = start_including or start_excluding
    range_to = end_including or end_excluding
    if range_from or range_to:
        return {
            "from": range_from,
            "from_inclusive": bool(start_including),
            "to": range_to,
            "to_inclusive": bool(end_including),
        }

    cpe_version = _extract_version_from_cpe_uri(cpe_uri)
    if cpe_version:
        return {
            "from": cpe_version,
            "from_inclusive": True,
            "to": cpe_version,
            "to_inclusive": True,
        }
    return {}


def _append_cpe_version_range(
    version_ranges: list[dict[str, Any]],
    version_range: dict[str, Any],
    cpe_records: list[dict[str, str]],
) -> None:
    """Merge identical version ranges and keep up to 10 newer concrete versions."""
    range_key = _cpe_range_key(version_range)
    for existing in version_ranges:
        if _cpe_range_key(existing) == range_key:
            existing["versions"] = _merge_cpe_versions(
                _ensure_cpe_version_list(existing.get("versions")),
                _versions_from_cpe_records(cpe_records),
            )
            return
    version_range["versions"] = _merge_cpe_versions(
        [],
        _versions_from_cpe_records(cpe_records),
    )
    version_ranges.append(version_range)


def _cpe_range_key(version_range: dict[str, Any]) -> tuple[Any, ...]:
    return (
        version_range.get("from", ""),
        bool(version_range.get("from_inclusive")),
        version_range.get("to", ""),
        bool(version_range.get("to_inclusive")),
    )


def _extract_cpe_records_from_match(
    item: dict[str, Any],
    cpe_uri: str,
) -> list[dict[str, str]]:
    """Extract concrete CPE version records from cpeMatch or matchCriteriaId expansion results."""
    records = _extract_cpe_records_from_payload(item)
    if not records:
        exact_record = _cpe_record_from_uri(cpe_uri)
        if exact_record:
            records.append(exact_record)
    if not records:
        records = _fetch_cpe_records_for_match_criteria(
            _ensure_str(item.get("matchCriteriaId")).strip()
        )
    return _merge_cpe_records([], records)


def _fetch_cpe_records_for_match_criteria(match_criteria_id: str) -> list[dict[str, str]]:
    """Query the NVD CPE Match API to get concrete CPEs for a matchCriteriaId."""
    if not match_criteria_id:
        return []
    source_url = (
        "https://services.nvd.nist.gov/rest/json/cpematch/2.0?"
        + parse.urlencode({"matchCriteriaId": match_criteria_id})
    )
    try:
        payload = _fetch_json(source_url)
    except RuntimeError:
        return []
    records: list[dict[str, str]] = []
    match_strings = payload.get("matchStrings")
    if not isinstance(match_strings, list):
        return []
    for raw_match in match_strings:
        if not isinstance(raw_match, dict):
            continue
        match_string = raw_match.get("matchString")
        if isinstance(match_string, dict):
            records.extend(_extract_cpe_records_from_payload(match_string))
        records.extend(_extract_cpe_records_from_payload(raw_match))
    return _merge_cpe_records([], records)


def _extract_cpe_records_from_payload(payload: dict[str, Any]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for key in ("matches", "cpeNames", "cpeName"):
        value = payload.get(key)
        if isinstance(value, list):
            for item in value:
                cpe_uri = _extract_cpe_uri_from_record(item)
                record = _cpe_record_from_uri(cpe_uri)
                if record:
                    records.append(record)
        elif isinstance(value, (dict, str)):
            cpe_uri = _extract_cpe_uri_from_record(value)
            record = _cpe_record_from_uri(cpe_uri)
            if record:
                records.append(record)
    return records


def _extract_cpe_uri_from_record(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("cpeName", "cpe_uri", "criteria"):
            cpe_uri = _ensure_str(value.get(key)).strip()
            if cpe_uri:
                return cpe_uri
    return ""


def _cpe_record_from_uri(cpe_uri: str) -> dict[str, str]:
    version = _extract_version_from_cpe_uri(cpe_uri)
    if not cpe_uri or not version:
        return {}
    return {
        "cpe_uri": cpe_uri,
        "cpe_part": _extract_cpe_part(cpe_uri),
        "cpe_part_label": _cpe_part_label(cpe_uri),
        "version": version,
    }


def _ensure_cpe_record_list(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    records: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        cpe_uri = _ensure_str(item.get("cpe_uri")).strip()
        version = _ensure_str(item.get("version")).strip()
        if cpe_uri and version:
            records.append(
                {
                    "cpe_uri": cpe_uri,
                    "cpe_part": _ensure_str(item.get("cpe_part")).strip()
                    or _extract_cpe_part(cpe_uri),
                    "cpe_part_label": _ensure_str(item.get("cpe_part_label")).strip()
                    or _cpe_part_label(cpe_uri),
                    "version": version,
                }
            )
    return records


def _ensure_cpe_version_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    versions: list[str] = []
    for item in value:
        version = _ensure_str(item).strip()
        if version and version not in versions:
            versions.append(version)
    return versions


def _versions_from_cpe_records(records: list[dict[str, str]]) -> list[str]:
    versions: list[str] = []
    for record in records:
        version = _ensure_str(record.get("version")).strip()
        if version and version not in versions:
            versions.append(version)
    return versions


def _merge_cpe_versions(
    existing: list[str],
    new_versions: list[str],
) -> list[str]:
    versions = {
        version.strip()
        for version in [*existing, *new_versions]
        if version.strip()
    }
    return sorted(
        versions,
        key=_version_sort_key,
        reverse=True,
    )[:CPE_VERSION_LIMIT]


def _merge_cpe_records(
    existing: list[dict[str, str]],
    new_records: list[dict[str, str]],
) -> list[dict[str, str]]:
    merged: dict[tuple[str, str], dict[str, str]] = {}
    for record in [*existing, *new_records]:
        cpe_uri = _ensure_str(record.get("cpe_uri")).strip()
        version = _ensure_str(record.get("version")).strip()
        if cpe_uri and version:
            merged[(cpe_uri, version)] = {
                "cpe_uri": cpe_uri,
                "cpe_part": _ensure_str(record.get("cpe_part")).strip()
                or _extract_cpe_part(cpe_uri),
                "cpe_part_label": _ensure_str(record.get("cpe_part_label")).strip()
                or _cpe_part_label(cpe_uri),
                "version": version,
            }
    return sorted(
        merged.values(),
        key=lambda record: _version_sort_key(record["version"]),
        reverse=True,
    )[:CPE_VERSION_LIMIT]


def _version_sort_key(version: str) -> tuple[tuple[int, int | str], ...]:
    parts = re.findall(r"\d+|[A-Za-z]+", version)
    key: list[tuple[int, int | str]] = []
    for part in parts:
        if part.isdigit():
            key.append((1, int(part)))
        else:
            key.append((0, part.lower()))
    return tuple(key)


def _extract_version_from_cpe_uri(cpe_uri: str) -> str:
    """Extract the concrete version from a CPE 2.3 URI; wildcards are not treated as ranges."""
    parts = _split_unescaped_colons(cpe_uri)
    if len(parts) < 6:
        return ""
    version = parts[5].strip()
    if not version or version in {"*", "-", "NA", "N/A"}:
        return ""
    return version


def _extract_cpe_part(cpe_uri: str) -> str:
    """Return the CPE 2.3 part field: a=application, o=operating system, h=hardware."""
    parts = _split_unescaped_colons(cpe_uri)
    if len(parts) < 3:
        return ""
    return parts[2].strip().lower()


def _cpe_part_label(cpe_uri: str) -> str:
    return CPE_PART_LABELS.get(_extract_cpe_part(cpe_uri), "unknown")


def _split_unescaped_colons(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == ":":
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def _extract_cvss_metrics(raw_cve: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract CVSS information with base_score from NVD metrics."""
    metrics = raw_cve.get("metrics")
    if not isinstance(metrics, dict):
        return []

    cvss_items: list[dict[str, Any]] = []
    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        raw_metrics = metrics.get(metric_key)
        if not isinstance(raw_metrics, list):
            continue
        for item in raw_metrics:
            if not isinstance(item, dict):
                continue
            cvss_data = item.get("cvssData")
            if not isinstance(cvss_data, dict):
                cvss_data = {}
            base_score = _ensure_number(cvss_data.get("baseScore"))
            if base_score is None:
                continue
            cvss_items.append(
                {
                    "metric": metric_key,
                    "source": _ensure_str(item.get("source")),
                    "base_score": base_score,
                    "vector_string": _ensure_str(cvss_data.get("vectorString")),
                }
            )
    return cvss_items


def _extract_cwe_info(raw_cve: dict[str, Any]) -> list[dict[str, str]]:
    """Extract CWE value, name, and source from NVD weaknesses while deduplicating and preserving order."""
    weaknesses = raw_cve.get("weaknesses")
    if not isinstance(weaknesses, list):
        return []

    cwe_items: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        source = _ensure_str(weakness.get("source"))
        descriptions = weakness.get("description")
        if not isinstance(descriptions, list):
            continue
        for description in descriptions:
            if not isinstance(description, dict):
                continue
            value = _ensure_str(description.get("value")).strip()
            if not value:
                continue
            cwe_value, cwe_name = _split_cwe_value_and_name(value)
            key = (source, cwe_value)
            if key in seen:
                continue
            seen.add(key)
            cwe_items.append(
                {
                    "value": cwe_value,
                    "name": cwe_name,
                    "source": source,
                }
            )
    return cwe_items


def _split_cwe_value_and_name(value: str) -> tuple[str, str]:
    """Split the ID and name from a CWE description that may contain a name."""
    match = re.match(r"^(CWE-\d+)\s*(?::|-|,)?\s*(.*)$", value.strip(), re.I)
    if not match:
        return value.strip(), ""
    return match.group(1).upper(), match.group(2).strip()


def _extract_cve_nearby_snippet(text: str, cve_id: str) -> str:
    if not text:
        return ""
    bounded = _trim_to_single_cve_record(text, cve_id)
    if bounded:
        return bounded

    index = text.upper().find(cve_id.upper())
    if index < 0:
        return ""
    start = max(0, index - 500)
    end = min(len(text), index + len(cve_id) + 700)
    return text[start:end].strip()


def _trim_to_single_cve_record(text: str, cve_id: str) -> str:
    """Slice out the target CVE record using neighboring CVE ID boundaries."""
    cleaned = _clean_text(text)
    if not cleaned:
        return ""
    matches = list(re.finditer(r"CVE-\d{4}-\d{4,10}", cleaned, re.I))
    target_index = -1
    for index, match in enumerate(matches):
        if match.group(0).upper() == cve_id.upper():
            target_index = index
            break
    if target_index < 0:
        return ""

    target = matches[target_index]
    previous_match = matches[target_index - 1] if target_index > 0 else None
    next_match = matches[target_index + 1] if target_index + 1 < len(matches) else None
    start = target.start() if previous_match else max(0, target.start() - 240)
    end = next_match.start() if next_match else min(len(cleaned), target.end() + 900)
    return cleaned[start:end].strip(" -→|,;")


def _extract_webpage_text(html: str) -> str:
    extracted = trafilatura.extract(html)
    return _clean_text(extracted or "")


def _clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()




def _nvd_request_headers() -> dict[str, str]:
    api_key = _optional_config_value("NVD_API_KEY") or _optional_config_value("nvd_api_key")
    return {"apiKey": api_key} if api_key else {}


def _optional_config_value(key: str) -> str:
    value = os.environ.get(key)
    if value:
        return value.strip()
    if not AGENT_ENV_FILE.exists():
        return ""
    for raw_line in AGENT_ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        config_key, config_value = line.split("=", 1)
        if config_key.strip() == key:
            return config_value.strip()
    return ""


def _fetch_json(url: str, *, headers: dict[str, str] | None = None) -> dict[str, Any]:
    body = _fetch_text(url, headers=headers)
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"JSON parse failed for {url}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"JSON root is not an object for {url}")
    return parsed


def _fetch_text(url: str, *, headers: dict[str, str] | None = None) -> str:
    request_headers = {
        "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
        "User-Agent": "db-env-gc/0.3",
        "Connection": "close",
    }
    request_headers.update(headers or {})
    req = request.Request(
        url,
        headers=request_headers,
        method="GET",
    )
    last_error: error.URLError | None = None
    for _attempt in range(2):
        try:
            with request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                return response.read().decode("utf-8", errors="ignore")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")[:300]
            raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
        except error.URLError as exc:
            last_error = exc
    if last_error is not None:
        raise RuntimeError(str(last_error.reason)) from last_error
    raise RuntimeError("fetch failed")


def _ensure_str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _ensure_number(value: object) -> int | float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    return None

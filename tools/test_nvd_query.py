"""Smoke-test NVD CVE lookup through the project's evidence tool.

Usage:
    python tools/test_nvd_query.py
    python tools/test_nvd_query.py CVE-2022-0543
    python tools/test_nvd_query.py CVE-2022-0543 --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools import evidence_tools  # noqa: E402


DEFAULT_CVE_ID = "CVE-2022-0543"
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Test whether NVD can return information for a CVE ID."
    )
    parser.add_argument(
        "cve_id",
        nargs="?",
        default=DEFAULT_CVE_ID,
        help=f"CVE ID to query. Default: {DEFAULT_CVE_ID}",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full normalized NVD payload as JSON.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="NVD request timeout in seconds for this smoke test. Default: 60",
    )
    return parser


def normalize_cve_id(raw_cve_id: str) -> str:
    cve_id = raw_cve_id.strip().upper()
    if not CVE_ID_PATTERN.fullmatch(cve_id):
        raise ValueError(f"Invalid CVE ID format: {raw_cve_id!r}")
    return cve_id


def first_cvss_summary(cvss_items: list[dict[str, Any]]) -> str:
    if not cvss_items:
        return "not provided"
    item = cvss_items[0]
    parts = []
    version = item.get("version")
    base_score = item.get("base_score")
    severity = item.get("base_severity")
    vector = item.get("vector_string")
    if version:
        parts.append(f"CVSS {version}")
    if base_score is not None:
        parts.append(f"score={base_score}")
    if severity:
        parts.append(f"severity={severity}")
    if vector:
        parts.append(f"vector={vector}")
    return ", ".join(parts) if parts else "not provided"


def cwe_summary(cwe_items: list[dict[str, Any]]) -> str:
    values = []
    for item in cwe_items:
        value = item.get("value")
        if value:
            values.append(str(value))
    return ", ".join(values) if values else "not provided"


def print_summary(cve_id: str, info: dict[str, Any]) -> None:
    description = str(info.get("description") or "").strip()
    if len(description) > 500:
        description = description[:497].rstrip() + "..."

    references = info.get("references") or []
    cpe_matches = info.get("cpe_matches") or []
    cvss_items = info.get("cvss") or []
    cwe_items = info.get("cwe") or []

    print(f"NVD query succeeded for {cve_id}")
    print(f"Source: {info.get('source_url') or 'unknown'}")
    print(f"Published: {info.get('published_at') or 'not provided'}")
    print(f"Last modified: {info.get('last_modified_at') or 'not provided'}")
    print(f"CVSS: {first_cvss_summary(cvss_items)}")
    print(f"CWE: {cwe_summary(cwe_items)}")
    print(f"CPE matches: {len(cpe_matches)}")
    print(f"References: {len(references)}")
    print("Description:")
    print(description or "not provided")


def main() -> int:
    args = build_parser().parse_args()
    try:
        cve_id = normalize_cve_id(args.cve_id)
        if args.timeout <= 0:
            raise ValueError("--timeout must be a positive integer")
        evidence_tools.REQUEST_TIMEOUT_SECONDS = args.timeout
        info = evidence_tools.fetch_nvd_cve_info(cve_id)
    except Exception as exc:
        print(f"NVD query failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print_summary(cve_id, info)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

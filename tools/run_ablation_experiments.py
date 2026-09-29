"""Run ablation experiments from data/benchmark/benchmark-cve.xlsx."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import openpyxl


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_FILE = ROOT / "data" / "benchmark" / "benchmark-cve.xlsx"
OUTPUT_ROOT = ROOT / "output" / "ablation"

CATEGORY_MAP = {
    "Image Reuse(18)": "dockerhub",
    "Custom build (17)": "no-images",
    "Extra Configuration(18)": "config",
    "Special Version": "version",
}

ABLATION_MODES = {
    "full",
    "no-profiler",
    "no-planner",
    "no-generator-verification",
    "minimal-generator",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run DVEG ablation experiments.")
    parser.add_argument("--ablation", required=True, choices=sorted(ABLATION_MODES))
    parser.add_argument(
        "--category",
        choices=sorted(set(CATEGORY_MAP.values())),
        help="Run only one benchmark category.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit CVEs per selected category. 0 means no limit.",
    )
    return parser


def load_cases() -> list[dict[str, str]]:
    workbook = openpyxl.load_workbook(BENCHMARK_FILE, read_only=True, data_only=True)
    sheet = workbook["Main"]
    cases: list[dict[str, str]] = []
    current_category = ""
    for row in sheet.iter_rows(values_only=True):
        first = str(row[0] or "").strip()
        if not first or first == "CVE-ID":
            continue
        if first in CATEGORY_MAP:
            current_category = CATEGORY_MAP[first]
            continue
        if first.upper().startswith("CVE-") and current_category:
            cases.append(
                {
                    "category": current_category,
                    "cve_id": first.upper(),
                    "title": str(row[1] or "").strip(),
                }
            )
    return cases


def selected_cases(
    cases: list[dict[str, str]],
    *,
    category: str | None,
    limit: int,
) -> list[dict[str, str]]:
    counts: dict[str, int] = {}
    selected: list[dict[str, str]] = []
    for case in cases:
        if category and case["category"] != category:
            continue
        count = counts.get(case["category"], 0)
        if limit > 0 and count >= limit:
            continue
        selected.append(case)
        counts[case["category"]] = count + 1
    return selected


def run_case(ablation: str, case: dict[str, str]) -> dict[str, object]:
    category = case["category"]
    cve_id = case["cve_id"]
    case_dir = OUTPUT_ROOT / ablation / category / cve_id
    generated_dir = case_dir / "generated"
    case_dir.mkdir(parents=True, exist_ok=True)
    generated_dir.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        str(ROOT / "main.py"),
        str(generated_dir),
        "--cve",
        cve_id,
        "--ablation",
        ablation,
    ]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    started = time.time()
    completed = subprocess.run(command, cwd=ROOT, env=env)
    duration = round(time.time() - started, 2)
    status = "success" if completed.returncode == 0 else "failed"

    terminal_log = case_dir / "terminal_log.txt"
    agents_log = case_dir / "agents_log.txt"
    for source, target in [
        (ROOT / "terminal_log.txt", terminal_log),
        (ROOT / "agents_log.txt", agents_log),
    ]:
        if source.exists():
            shutil.copy2(source, target)

    run_info = {
        "ablation": ablation,
        "category": category,
        "cve_id": cve_id,
        "title": case["title"],
        "status": status,
        "exit_code": completed.returncode,
        "duration_seconds": duration,
        "output_dir": str(generated_dir),
        "terminal_log": str(terminal_log),
        "agents_log": str(agents_log),
        "command": command,
    }
    (case_dir / "run.json").write_text(
        json.dumps(run_info, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return run_info


def append_summary(path: Path, row: dict[str, object]) -> None:
    fieldnames = [
        "ablation",
        "category",
        "cve_id",
        "title",
        "status",
        "exit_code",
        "duration_seconds",
        "output_dir",
        "terminal_log",
        "agents_log",
    ]
    exists = path.exists()
    with path.open("a", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        writer.writerow({key: row.get(key, "") for key in fieldnames})


def main() -> None:
    args = build_parser().parse_args()
    cases = selected_cases(
        load_cases(),
        category=args.category,
        limit=args.limit,
    )
    if not cases:
        raise SystemExit("No benchmark cases selected.")

    summary_path = OUTPUT_ROOT / args.ablation / "summary.csv"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Selected {len(cases)} cases for ablation={args.ablation}")
    print(f"Summary: {summary_path}")

    for index, case in enumerate(cases, start=1):
        print(f"[{index}/{len(cases)}] {case['category']} {case['cve_id']}")
        row = run_case(args.ablation, case)
        append_summary(summary_path, row)
        print(
            f"  {row['status']} exit={row['exit_code']} "
            f"duration={row['duration_seconds']}s"
        )


if __name__ == "__main__":
    main()

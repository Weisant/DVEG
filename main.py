"""DVEG command-line entry point."""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from agent.runtime.agent import DBEnvGenerationAgent
from tools.evidence_tools import normalize_cve_id


class TeeStream:
    """Write terminal output to log files at the same time."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, data: str) -> None:
        for stream in self.streams:
            stream.write(data)
            stream.flush()

    def flush(self) -> None:
        for stream in self.streams:
            stream.flush()

    def write_transient(self, data: str) -> None:
        """Write an in-place status update only to the visible terminal stream."""
        if not self.streams:
            return
        self.streams[0].write(data)
        self.streams[0].flush()


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        description="DVEG: generate database Docker environments from CVE IDs."
    )
    parser.add_argument(
        "output_directory",
        nargs="?",
        default=None,
        help="Directory where generated projects will be written.",
    )
    parser.add_argument(
        "--parser-only",
        action="store_true",
        help="Run only the parser stage and stop.",
    )
    parser.add_argument(
        "--cve",
        type=parse_cli_cve_id,
        help=(
            "Single CVE ID to use as the task input, for example CVE-2022-0543. "
            "If omitted, the program prompts for it after startup."
        ),
    )
    parser.add_argument(
        "--ablation",
        default="full",
        choices=[
            "full",
            "no-profiler",
            "no-planner",
            "no-generator-verification",
            "minimal-generator",
        ],
        help=(
            "Run a simplified ablation variant. no-generator-verification is "
            "kept as a compatibility name for generator verification variants."
        ),
    )
    return parser


def parse_cli_cve_id(value: str) -> str:
    """Validate and normalize the only supported user input."""
    try:
        return normalize_cve_id(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "input must be exactly one CVE ID such as CVE-2022-0543"
        ) from exc


def prompt_for_cve_id() -> str:
    """Prompt until the user enters one valid CVE ID."""
    while True:
        value = input("DVEG CVE ID: ").strip()
        if not value:
            raise SystemExit("No CVE ID entered. Exiting.")
        try:
            return normalize_cve_id(value)
        except ValueError:
            print("Invalid CVE ID. Use a value such as CVE-2022-0543.")


def clear_runtime_logs(base_dir: Path) -> tuple[Path, Path]:
    """Clear logs for the current run."""
    terminal_log_path = base_dir / "terminal_log.txt"
    agents_log_path = base_dir / "agents_log.txt"
    for path in (terminal_log_path, agents_log_path):
        path.write_text("", encoding="utf-8")
    return terminal_log_path, agents_log_path


def get_utc_timestamp() -> str:
    """Return a consistently formatted UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def format_token_usage(usage: dict[str, int] | None) -> str:
    """Format token counters for terminal output."""
    usage = usage or {}
    return (
        f"prompt={usage.get('prompt_tokens', 0)}, "
        f"completion={usage.get('completion_tokens', 0)}, "
        f"total={usage.get('total_tokens', 0)}, "
        f"calls={usage.get('calls', 0)}"
    )


def main() -> None:
    """Main CLI entry point."""
    args = build_parser().parse_args()

    base_dir = Path(__file__).resolve().parent
    output_directory = (
        Path(args.output_directory).resolve()
        if args.output_directory
        else (base_dir / "output").resolve()
    )
    output_directory.mkdir(parents=True, exist_ok=True)

    terminal_log_path, agents_log_path = clear_runtime_logs(base_dir)
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    start_time: float | None = None
    start_timestamp = ""
    task = ""
    run_status = "SUCCESS"
    agent: DBEnvGenerationAgent | None = None

    with terminal_log_path.open("a", encoding="utf-8") as terminal_log_file:
        sys.stdout = TeeStream(original_stdout, terminal_log_file)
        sys.stderr = TeeStream(original_stderr, terminal_log_file)

        try:
            command_text = " ".join([os.path.basename(sys.executable), *sys.argv])
            print("=" * 72)
            print("◆ DVEG Run")
            print("=" * 72)
            print(f" Mode: {'parser-only' if args.parser_only else 'full four-stage pipeline'}")
            print(f" Command: {command_text}")
            print(f" Output directory: {output_directory}")
            print("=" * 72)

            agent = DBEnvGenerationAgent(
                project_directory=output_directory,
                log_file_path=agents_log_path,
                ablation_mode=args.ablation,
            )
            task = args.cve or prompt_for_cve_id()
            start_time = time.time()
            start_timestamp = get_utc_timestamp()
            print(f"\n▶ Run started: {start_timestamp}")
            print(f" Input: {task}")
            if args.parser_only:
                agent.run_parser_only(
                    task,
                    refresh_cve_cache=True,
                )
                print("\n Parser result: payload written to agents_log.txt.")
            else:
                final_answer = agent.run(task)
                print(f"\n✓ DVEG result: {final_answer}")
        except KeyboardInterrupt:
            run_status = "CANCELLED"
            raise
        except (Exception, SystemExit):
            run_status = "FAILED"
            raise
        finally:
            end_timestamp = get_utc_timestamp()
            duration_seconds = round(time.time() - start_time, 2) if start_time else 0
            print("\n" + "=" * 72)
            print("◆ DVEG Run Summary")
            print("=" * 72)
            status_icon = {
                "SUCCESS": "✓",
                "FAILED": "✗",
                "CANCELLED": "■",
            }.get(run_status, "•")
            print(f"{status_icon} Status: {run_status}")
            print(f" Started: {start_timestamp or 'not started'}")
            print(f" Finished: {end_timestamp}")
            print(f" Duration: {duration_seconds} seconds")
            total_tokens = (
                agent.client.token_usage_snapshot()
                if agent is not None and hasattr(agent.client, "token_usage_snapshot")
                else {}
            )
            print(f" LLM usage: {format_token_usage(total_tokens)}")
            print(f" Output directory: {output_directory}")
            print(f" Input: {task or 'no task input'}")
            print("=" * 72)
            sys.stdout = original_stdout
            sys.stderr = original_stderr


if __name__ == "__main__":
    main()

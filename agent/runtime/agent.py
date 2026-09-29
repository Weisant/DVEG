"""Main scheduler."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.ablation import (
    build_profile_direct_plan,
    build_minimal_profile_from_parser,
)
from agent.config import load_settings
from agent.generator import generate_project
from agent.llm import JsonChatClient
from agent.minimal_generator import generate_project_minimal
from agent.models import PipelineResult
from agent.parser import parse_task_bundle
from agent.planner import build_environment_plan
from agent.profiler import build_environment_profile
from agent.runtime.progress import TerminalSpinner


class DBEnvGenerationAgent:
    """Main scheduler for database environment project generation."""

    STAGE_NAMES = (
        "Parser Module",
        "Profiler Module",
        "Planner Module",
        "Generator Module",
    )

    def __init__(
        self,
        project_directory: Path,
        log_file_path: Path,
        ablation_mode: str = "full",
    ) -> None:
        """Initialize the scheduler and shared LLM client."""
        if ablation_mode == "no-parser":
            raise ValueError("no-parser ablation is not supported in CVE-only mode.")
        self.project_directory = project_directory
        self.log_file_path = log_file_path
        self.ablation_mode = ablation_mode
        self.client = JsonChatClient(load_settings())

    def run(self, user_input: str) -> str:
        """Run the full pipeline."""
        plan = self.create_plan()
        print("\n" + "=" * 72)
        print("◆ DVEG Generation Pipeline")
        print("=" * 72)
        for index, step in enumerate(plan, start=1):
            print(
                f"  {self.get_stage_number(index)} "
                f"{self.STAGE_NAMES[index - 1]}: {step}"
            )

        state: dict[str, Any] = {}
        for index, step in enumerate(plan, start=1):
            print("\n" + "=" * 72)
            print(f"{self.get_stage_number(index)} {self.STAGE_NAMES[index - 1]}")
            print(f" Purpose: {step}")
            print(f" Execution: {self.get_step_executor_label(index)}")
            print("=" * 72)
            started = time.time()
            token_start = self._token_snapshot()
            outcome = self._run_stage(index, state, user_input)
            self._print_outcome(
                thought=outcome["thought"],
                action=outcome["action"],
                workflow=outcome["workflow"],
                result=outcome["result"],
                duration_seconds=round(time.time() - started, 2),
                token_usage=self._token_delta(token_start),
            )

        return self.create_final_answer(state["pipeline_result"])

    def run_parser_only(
        self,
        user_input: str,
        *,
        refresh_cve_cache: bool = False,
    ) -> dict[str, Any]:
        """Run only the parser stage and return the parser bundle payload."""
        print("\n" + "=" * 72)
        print("◆ DVEG Parser-Only Pipeline")
        print("=" * 72)
        print(
            "  [1/1] Parser Module: structure the request and build CVE evidence context"
        )

        print("\n" + "=" * 72)
        print("[1/1] Parser Module")
        print(" Purpose: structure the request and build CVE evidence context")
        print(f" Execution: {self.get_step_executor_label(1)}")
        print("=" * 72)
        started = time.time()
        token_start = self._token_snapshot()
        with TerminalSpinner("Preparing Parser Module") as progress:
            parsed = parse_task_bundle(
                user_input,
                self.client,
                refresh_cve_cache=refresh_cve_cache,
                status_callback=progress.update,
                notice_callback=progress.notice,
            )
        self.log_agent_payload("parser", parsed.to_dict())
        self._print_outcome(
            thought="Validated the CVE input and assembled cached or externally collected CVE evidence.",
            action="CVE validation -> cache/NVD lookup -> relevance classification -> advisory integration",
            workflow=progress.completed_operations(),
            result=(
                f"Identified CVE ID: {parsed.task.cve_id or 'not provided'}, "
                f"database type: {parsed.inferred_db_type or 'unidentified'}, "
                f"collected {len(parsed.evidence)} evidence item(s)."
            ),
            duration_seconds=round(time.time() - started, 2),
            token_usage=self._token_delta(token_start),
        )
        return parsed.to_dict()

    def _run_stage(
        self,
        index: int,
        state: dict[str, Any],
        user_input: str,
    ) -> dict[str, Any]:
        if index == 1:
            with TerminalSpinner("Preparing Parser Module") as progress:
                parsed = parse_task_bundle(
                    user_input,
                    self.client,
                    status_callback=progress.update,
                    notice_callback=progress.notice,
                )
            state["parsed"] = parsed
            state["task"] = parsed.task
            state["evidence"] = parsed.evidence
            self.log_agent_payload("parser", parsed.to_dict())
            return {
                "thought": "Validated the CVE input and assembled cached or externally collected CVE evidence.",
                "action": "CVE validation -> cache/NVD lookup -> relevance classification -> advisory integration",
                "workflow": progress.completed_operations(),
                "result": (
                    f"Identified CVE ID: {parsed.task.cve_id or 'not provided'}, "
                    f"database type: {parsed.inferred_db_type or 'unidentified'}, "
                    f"collected {len(parsed.evidence)} evidence item(s)."
                ),
            }

        if index == 2:
            with TerminalSpinner("Preparing Profiler Module") as progress:
                if self.ablation_mode == "no-profiler":
                    parsed = state["parsed"]
                    progress.update("Building minimal parser-derived profile")
                    profile = build_minimal_profile_from_parser(parsed)
                else:
                    parsed = state["parsed"]
                    profile = build_environment_profile(
                        parsed.task,
                        parsed.inferred_db_type,
                        parsed.vulnerability_info,
                        self.client,
                        status_callback=progress.update,
                    )
            state["profile"] = profile
            self.log_agent_payload("profiler", profile.to_dict())
            return {
                "thought": "Converted the parser bundle into a reproduction profile without selecting a concrete Docker build path.",
                "action": "LLM EnvironmentProfile generation with schema validation",
                "workflow": progress.completed_operations(),
                "result": (
                    f"Generated environment profile, database type: {profile.target.db_type}, "
                    f"final version: {profile.version.final_version or 'unconfirmed'}."
                ),
            }

        if index == 3:
            with TerminalSpinner("Preparing Planner Module") as progress:
                if self.ablation_mode == "no-planner":
                    progress.update("Wrapping profile in an empty plan shell")
                    environment_plan = build_profile_direct_plan(state["profile"])
                else:
                    environment_plan = build_environment_plan(
                        state["profile"],
                        self.client,
                        status_callback=progress.update,
                    )
            state["environment_plan"] = environment_plan
            self.log_agent_payload(
                "planner",
                {"environment_plan": environment_plan.to_dict()},
            )
            selected_version = environment_plan.build_plan.selected_version
            return {
                "thought": "Traversed the strategy graph and verified build resources to produce the generator blueprint.",
                "action": self._planner_action(),
                "workflow": progress.completed_operations(),
                "result": (
                    f"Generated environment plan, build path: {environment_plan.build_plan.build_path}, "
                    f"final version: {selected_version or 'unconfirmed'}."
                ),
            }

        with TerminalSpinner("Preparing Generator Module") as progress:
            self._raise_if_planner_resources_failed(state["environment_plan"])
            if self.ablation_mode == "minimal-generator":
                artifacts, run_dir, written_files = generate_project_minimal(
                    blueprint=state["environment_plan"],
                    output_directory=self.project_directory,
                    client=self.client,
                    status_callback=progress.update,
                )
            else:
                artifacts, run_dir, written_files = generate_project(
                    blueprint=state["environment_plan"],
                    output_directory=self.project_directory,
                    client=self.client,
                    status_callback=progress.update,
                )
        state["pipeline_result"] = PipelineResult(
            run_dir=run_dir,
            task=state["task"],
            evidence=state["evidence"],
            environment_plan=state["environment_plan"],
            artifacts=artifacts,
        )
        self.log_agent_payload(
            "generator",
            {
                "run_dir": str(run_dir),
                "written_files": written_files,
                "artifacts": artifacts.to_dict(),
                "pipeline_result": state["pipeline_result"].to_dict(),
            },
        )
        return {
            "thought": self._generator_thought(),
            "action": self._generator_action(),
            "workflow": progress.completed_operations(),
            "result": f"Project generated and written to {run_dir}.",
        }

    def create_plan(self) -> list[str]:
        """Define the fixed execution plan."""
        return [
            "validate CVE input and build CVE evidence context",
            "derive the reproduction profile, affected asset, version, and constraints",
            "execute the decision graph and verify required build resources",
            "generate and write the Docker project files",
        ]

    def _raise_if_planner_resources_failed(self, environment_plan) -> None:
        """Stop before generation when planner proved required resources unavailable."""
        build_resources = environment_plan.build_plan.build_resources or {}
        if build_resources.get("resource_status") != "failed":
            return
        notes = build_resources.get("resource_notes")
        detail = "; ".join(str(note) for note in notes[:3]) if isinstance(notes, list) else ""
        message = "Planner could not verify any required build candidate."
        if detail:
            message = f"{message} {detail}"
        raise RuntimeError(message)

    def create_final_answer(self, result: PipelineResult) -> str:
        """Build the final natural-language response."""
        generated_files = ", ".join(file.path for file in result.artifacts.files)
        build_plan = result.environment_plan.build_plan
        requirements = result.environment_plan.generation_requirements
        selected_version = build_plan.selected_version
        cve_id = str(requirements.get("cve_id") or result.artifacts.cve_id or "").strip()
        db_type = str(requirements.get("db_type") or result.task.db_type or "").strip()
        incomplete = any(
            file.path == "GENERATION_STATUS.md"
            for file in result.artifacts.files
        )
        return (
            f"Project status: {'INCOMPLETE' if incomplete else 'GENERATED'}. "
            f"Target: {cve_id + ' / ' if cve_id else ''}"
            f"{db_type or 'database'} "
            f"{selected_version or 'unconfirmed'}. "
            f"Build path: {build_plan.build_path}. "
            f"Verified artifacts: {len(result.environment_plan.verified_artifacts)}. "
            f"Output: {result.run_dir}. "
            f"Files: {generated_files}."
        )

    def get_step_executor_label(self, step_index: int) -> str:
        """Return the executor label for the current stage by step index."""
        if self.ablation_mode == "minimal-generator" and step_index == 3:
            return "deterministic decision graph + template catalogs + artifact probes"
        if self.ablation_mode == "minimal-generator" and step_index == 4:
            return "minimal LLM file generator + filesystem tools"
        executor_labels = {
            1: "CVE validation + NVD/advisory evidence tools + local CVE cache",
            2: "LLM profile generation from structured parser context",
            3: "deterministic decision graph + template catalogs + artifact/resource probes",
            4: "LLM file generation from EnvironmentPlan + filesystem tools",
        }
        return executor_labels.get(step_index, "unknown")

    def _planner_action(self) -> str:
        if self.ablation_mode == "no-planner":
            return "profile-direct blueprint wrapping"
        if self.ablation_mode == "no-generator-verification":
            return "decision graph traversal -> template lookup -> artifact probes"
        return (
            "decision graph traversal -> template lookup -> image/source/package resource probes"
        )

    def _generator_thought(self) -> str:
        if self.ablation_mode == "minimal-generator":
            return (
                "Generated the project from EnvironmentPlan using only a minimal "
                "schema-level writer prompt."
            )
        return "Generated complete file contents from the planner EnvironmentPlan and wrote them."

    def _generator_action(self) -> str:
        if self.ablation_mode == "minimal-generator":
            return "LLM minimal ProjectArtifacts generation -> filesystem write"
        return "LLM ProjectArtifacts generation from EnvironmentPlan -> filesystem write"

    @staticmethod
    def get_stage_number(step_index: int) -> str:
        return f"[{step_index}/4]"

    def _print_outcome(
        self,
        *,
        thought: str,
        action: str,
        workflow: list[str],
        result: str,
        duration_seconds: float,
        token_usage: dict[str, int],
    ) -> None:
        """Print a single step outcome consistently."""
        print("\n Process:")
        print(thought)
        print(f"\n Implementation: {action}")
        print("\n Module workflow:")
        for item in workflow:
            print(f" - {item}")
        print("\n✓ Stage result: COMPLETED")
        print(result)
        print(f"\n Duration: {duration_seconds} seconds")
        print(" LLM usage:")
        print(self._format_token_usage(token_usage))
        print("-" * 72)

    def _token_snapshot(self) -> dict[str, int]:
        if hasattr(self.client, "token_usage_snapshot"):
            return self.client.token_usage_snapshot()
        return {}

    def _token_delta(self, before: dict[str, int]) -> dict[str, int]:
        if hasattr(self.client, "token_usage_delta"):
            return self.client.token_usage_delta(before)
        return {}

    @staticmethod
    def _format_token_usage(usage: dict[str, int] | None) -> str:
        """Format token counters for terminal output."""
        usage = usage or {}
        return (
            f"prompt={usage.get('prompt_tokens', 0)}, "
            f"completion={usage.get('completion_tokens', 0)}, "
            f"total={usage.get('total_tokens', 0)}, "
            f"calls={usage.get('calls', 0)}"
        )

    def log_agent_payload(self, agent_name: str, payload: dict[str, Any]) -> None:
        """Write structured stage outputs to the log file."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "agent_name": agent_name,
            "payload": payload,
        }
        with self.log_file_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(record, ensure_ascii=False, indent=2))
            file.write("\n\n")

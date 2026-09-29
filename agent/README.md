# Agent Package

`agent/` implements DVEG's four-stage main pipeline:

`CVE ID input -> parser(+evidence tools) -> profiler -> planner(+artifact/resource tools) -> generator(+file tools)`

## parser

Location: [parser.py](parser.py)
Prompt: [prompts/parser.md](prompts/parser.md)

Responsibilities:

- Validate a single CVE ID into `TaskInput`
- Call `tools/evidence_tools.py` directly to collect external evidence for that CVE
- Output `ParsedTaskBundle`

## profiler

Location: [profiler.py](profiler.py)
Prompt: [prompts/profiler.md](prompts/profiler.md)

Responsibilities:

- Generate `EnvironmentProfile` from the validated CVE task, database type inference, relevance classification, and parser evidence context
- Decide the affected asset, final version, version ecosystem, runtime configuration, artifact requirements, vulnerability conditions, and build semantic constraints
- Do not select Docker build paths or call image/source probing tools

## planner

Location: [planner.py](planner.py)
Runtime rules: `strategy-selection/decision_graph.yaml`, `templates/db_build_path_catalog.jsonl`, `templates/dockerhub_repository_catalog.jsonl`

Responsibilities:

- Consume only the profiler profile
- Execute the decision graph and read local template indexes
- Select an image candidate at DockerHub nodes and call tools to verify the tag
- Select build strategy and build resources, including base images, dependency packages, and URLs
- Output `EnvironmentPlan` for the generator, with strategy and resources carried in `BuildPlan`

Planner build paths include:

- `official_image_direct`
- `official_image_extended`
- `custom_package_repo`
- `language_package_repo`
- `system_package_repo`
- `prebuilt_binary`
- `source_compile`

## generator

Location: [generator.py](generator.py)
Prompt: [prompts/generator/core.md](prompts/generator/core.md)

Responsibilities:

- Consume the planner-produced `EnvironmentPlan`
- Generate complete Docker project file contents as `ProjectArtifacts`
- Call file tools to create the run directory and write files

## minimal generator

Location: [minimal_generator.py](minimal_generator.py)

Used only by `--ablation minimal-generator`.

Responsibilities:

- Generate `ProjectArtifacts` from the same `EnvironmentPlan`
- Use only a schema-level ProjectArtifacts prompt
- Skip the rule-rich generator prompt

## Data Flow

The core data flow is:

`TaskInput + Evidence -> EnvironmentProfile -> EnvironmentPlan(BuildPlan strategy + resources) -> ProjectArtifacts -> files`

The main flow no longer uses separate `artifact_plan`, `validator`, or `state` writing modules.

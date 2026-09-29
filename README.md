# DVEG

**DVEG (DBMS Vulnerability Environment Generator)** is an LLM-powered framework for evidence-driven generation of Docker-based DBMS vulnerability reproduction environments.

Given a CVE ID, DVEG collects and normalizes vulnerability evidence, derives the environment constraints required for reproduction, selects a feasible construction strategy, verifies candidate resources, and generates a runnable Docker project.

> [!WARNING]
> DVEG is intended only for authorized security research, vulnerability reproduction, and defensive testing. Run generated vulnerable services in an isolated environment and never expose them directly to an untrusted network.

## Workflow

```text
CVE ID
  -> evidence parsing
  -> reproduction profiling
  -> construction planning
  -> Docker project generation
```

The pipeline is implemented by four modules:

- **Parser**: validates the CVE ID and builds a traceable evidence bundle from the local cache, NVD, vendor advisories, and other references.
- **Profiler**: converts evidence into a structured reproduction profile containing the affected DBMS, asset, version semantics, configuration, plugins, dependencies, and build constraints.
- **Planner**: uses the Environment Construction Decision Diagram (ECDD) and resource probes to choose a feasible build path.
- **Generator**: produces the final Docker project, including the `Dockerfile`, `docker-compose.yml`, configuration, startup, and initialization files when required.

Supported construction paths include direct or extended official images, system and language package repositories, historical packages, prebuilt binaries, and source compilation.

## Requirements

- Python 3.10 or newer
- Docker Engine with Docker Compose v2
- An API key for an OpenAI-compatible chat-completions endpoint
- Internet access when DVEG must query evidence sources or verify build artifacts

## Installation

```bash
git clone https://github.com/Weisant/DVEG.git
cd DVEG
python -m venv .venv
```

Activate the virtual environment on Linux or macOS:

```bash
source .venv/bin/activate
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install all dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Configuration

Create a local configuration file. It is excluded from Git.

Linux or macOS:

```bash
cp agent/.env.example agent/.env
```

Windows PowerShell:

```powershell
Copy-Item agent/.env.example agent/.env
```

Edit `agent/.env`:

```dotenv
API_KEY=your_api_key_here
BASE_URL=https://api.openai.com/v1
DEFAULT_MODEL=your_default_model_here

# Optional per-stage overrides; omit them to use DEFAULT_MODEL.
PARSER_MODEL=your_parser_model_here
PROFILER_MODEL=your_profiler_model_here
PLANNER_MODEL=your_planner_model_here
GENERATOR_MODEL=your_generator_model_here

# Optional: raises the NVD request rate limit.
NVD_API_KEY=your_nvd_api_key_here
```

The same names may instead be supplied as environment variables. `API_KEY`, `BASE_URL`, and `DEFAULT_MODEL` are required. The stage-specific model variables and `NVD_API_KEY` are optional.

## Running DVEG

Show all CLI options:

```bash
python main.py --help
```

Run the complete four-stage pipeline for one CVE:

```bash
python main.py --cve CVE-2022-0543
```

Omit `--cve` to enter the CVE ID interactively:

```bash
python main.py
```

Write generated projects to a custom directory:

```bash
python main.py ./custom-output --cve CVE-2022-0543
```

Run only the parser and evidence-collection stage:

```bash
python main.py --parser-only --cve CVE-2022-0543
```

The default output root is `output/`. Each generated project is written to a timestamped subdirectory. Console output is mirrored to `terminal_log.txt`, and structured stage events are written to `agents_log.txt`; both log files are cleared at the start of each run.

## Ablation Modes

Run the full implementation explicitly:

```bash
python main.py --cve CVE-2022-0543 --ablation full
```

Run without the profiler:

```bash
python main.py --cve CVE-2022-0543 --ablation no-profiler
```

Run without the planner:

```bash
python main.py --cve CVE-2022-0543 --ablation no-planner
```

Run the generator-verification compatibility variant:

```bash
python main.py --cve CVE-2022-0543 --ablation no-generator-verification
```

Run with the minimal generator prompt:

```bash
python main.py --cve CVE-2022-0543 --ablation minimal-generator
```

## Batch Ablation Experiments

Show the batch runner options:

```bash
python tools/run_ablation_experiments.py --help
```

Run every benchmark case for one mode:

```bash
python tools/run_ablation_experiments.py --ablation full
```

Limit the run to one category and a fixed number of cases:

```bash
python tools/run_ablation_experiments.py --ablation minimal-generator --category dockerhub --limit 5
```

Valid categories are `dockerhub`, `no-images`, `config`, and `version`. Valid modes are the five values shown in the preceding section. Results are stored under `output/ablation/<mode>/`, with a `summary.csv` for the selected mode.

## NVD Connectivity Test

Query the default sample CVE and print a concise summary:

```bash
python tools/test_nvd_query.py
```

Query another CVE:

```bash
python tools/test_nvd_query.py CVE-2024-22412
```

Print the normalized JSON response or change the timeout:

```bash
python tools/test_nvd_query.py CVE-2024-22412 --json
python tools/test_nvd_query.py CVE-2024-22412 --timeout 120
```

## Running a Generated Environment

Change into the timestamped project directory printed by DVEG, then use Docker Compose:

```bash
cd output/<timestamp>-<project-name>
docker compose config
docker compose up -d --build
docker compose ps
docker compose logs -f
```

Stop the environment:

```bash
docker compose down
```

Stop it and remove its volumes:

```bash
docker compose down -v
```

Review the generated files and port mappings before starting the environment. The `down -v` command permanently removes the Compose project's volumes.

## Repository Layout

```text
agent/                  pipeline stages, models, prompts, and runtime
data/cve_info/          cached CVE evidence
data/benchmark/         benchmark metadata
strategy-selection/     ECDD rules and architecture image
templates/              build-path and image catalogs
tools/                  evidence, registry, package, and experiment utilities
main.py                 command-line entry point
```

## Responsible Use

Use DVEG only against systems you own or are explicitly authorized to test. Generated projects may intentionally contain vulnerable software, insecure defaults, or proof-of-concept material. Keep them isolated, restrict network exposure, remove them after testing, and comply with all applicable laws and third-party licenses.

## Dataset and Benchmark

The dataset is in repository [DBVulSet](https://github.com/Weisant/DB-Vul-Set) and the benchmark list is in [./data/benchmark](https://github.com/Weisant/DVEG/tree/main/data/benchmark).

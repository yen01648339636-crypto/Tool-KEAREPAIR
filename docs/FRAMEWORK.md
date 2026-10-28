# KeaRepair framework and CLI

This guide describes the framework included with the source-only distribution. Run commands from the project root. External cases, indexes, container images, model weights and saved runs must be prepared separately. See [setup](../README.md) and [data preparation](../data/README.md).

KeaRepair is a vulnerability repair framework powered by large language models. It has two stages:

- **Offline stage**: Extract data-flow and control-flow knowledge from historical vulnerability descriptions, vulnerable code, and repaired code. Distill and embed this knowledge to build a FAISS knowledge base.
- **Online stage**: Diagnose vulnerable code, retrieve and rerank historical repair examples, generate patches, and refine them using compilation, proof-of-concept (PoC), and unit test results.

Run all commands below from the repository root.

## KeaRepair

The local web workbench provides source-linked diagnosis, historical knowledge browsing,
candidate patch review, per-stage validation records, and persistent repair tasks.

```bash
.venv/bin/python -m pip install -r studio/requirements.txt
.venv/bin/python scripts/run_studio.py
```

Open **http://127.0.0.1:7860**. In **Task Center → New Repair Task**, enter a Git
repository URL, select a prepared source baseline, and confirm the repository-relative
vulnerable file and pinned revision. The backend maps this selection to its corresponding
prepared CVE case. Several targets in one repository require an explicit selection;
the form does not clone arbitrary repositories or guess a CVE from a URL.

Choose a repair scope before clicking **Start Repair**:

| Scope | Required test input | Execution |
| --- | --- | --- |
| Generate patch (default) | None | Diagnose, retrieve, rerank and generate a patch; skip Docker checks and validation. |
| Patch + PoC | Uploaded PoC file, or the prepared PoC entry | Generate the patch, apply it, build and run PoC validation. |
| Patch + full tests | Uploaded PoC and unit-test script, or prepared test entries | Also run the unit tests, using validation feedback within the configured repair budget. |

Validation scopes default to **Upload files**. Each upload may be up to
10 MiB; scripts must be non-empty, while a raw PoC payload may be empty. PoC and unit checks accept self-contained `.sh` or `.py` scripts, run from
the prepared source directory; exit code 0 means the check passes. Supported Vul4c
targets also accept raw PoC data through their existing runner. Unit-test archives
are not accepted. Uploaded tests always use **Live run** and are recorded with the task.
Alternatively, choose **Use prepared tests** to use the selected baseline's existing
PoC and unit-test entries; those references must match its prepared configuration.

Execution settings offer **Live run**, or **Saved run** when a matching successful
record is available and no uploaded tests are selected. Saved runs reuse recorded
artifacts without model calls or fresh test execution.

The selected workflow runs automatically without intermediate confirmation. Live activity,
stage following, tool milestones and validation output remain visible throughout.
**Repair Report** includes the source request, selected scope, diagnosis, original
per-view retrieval hits, reranked examples, patch, validation evidence and execution
history; download it as HTML, JSON or an evidence ZIP. Patch-only and PoC-only results
are labelled for their requested scope. Full validation success still requires patch
application, compilation, PoC and unit tests to pass; omitted checks are not counted as
passed. The initial walkthrough remains a clearly marked synthetic example with real
structural analysis and no model calls.
See [Studio setup and scope](../studio/README.md).

## Repository Layout

```text
KEARepair/
├── Offline/                    # Offline knowledge base construction
│   ├── multiview_generator.py   # Data-flow and control-flow knowledge extraction
│   ├── distillation.py          # Distillation into reusable repair knowledge
│   ├── vector_store.py          # FAISS index persistence and search
│   └── index_builder.py         # Batch indexing, caching, and resumable builds
├── Online/                     # Online vulnerability repair
│   ├── phase1_diagnosis/        # LLM diagnosis with static analysis tools
│   ├── phase2_retrieval/        # Query generation, retrieval, and reranking
│   └── phase3_repair/           # Patch generation, validation, and refinement
├── static_analysis/            # Code parsing, data-flow and control-flow analysis
├── studio/                     # Local web workbench, task API and CLI adapter
├── models/                     # LLM interfaces, MiniLM embeddings, CodeLlama encoder
├── data_loader/                # Offline dataset loading and preprocessing
├── prompts/                    # Prompt templates for both stages
├── config/
│   ├── base.yaml               # Shared paths, models, retrieval, and validation settings
│   ├── offline.yaml            # Offline models and settings
│   └── online.yaml             # Online models and settings
├── scripts/
│   ├── run_offline.py          # Offline indexing entry point
│   ├── run_online.py           # Online repair entry point
│   ├── run_studio.py           # Start the local web platform
│   ├── evaluate.py             # Recompute metrics from saved results
│   ├── migrate_case_commands.py # Audit and migrate legacy case validation commands
│   └── sync_case_sources.py    # Audit and align prepared container source baselines
├── utils/                      # Data contracts, logging, patches, and experiment artifacts
├── tests/                      # Regression tests and small fixtures
├── data/
│   ├── raw/                    # Raw data, CVE metadata, and offline datasets
│   ├── processed/
│   │   ├── Vul4c/              # Vul4C source files, test commands, and case lists
│   │   └── PatchEval/           # PatchEval source files, test commands, and case lists
│   └── indices/knowledge_index/ # Generated knowledge base; not bundled
├── results/                    # Repair results, patches, and validation records; generated at runtime
├── logs/                       # Runtime logs
├── checkpoints/                # Reserved checkpoint directory
├── requirements.txt            # Python dependencies
└── README.md
```

## Setup

Use Linux with Python 3.10 or newer and Docker installed.

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip build-essential git docker.io
sudo systemctl enable --now docker

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
docker version
```

If your user cannot access Docker, run `sudo usermod -aG docker "$USER"`, then log out and log back in.

Configure models separately in `config/offline.yaml` and `config/online.yaml`. Both inherit from `config/base.yaml`. For an OpenAI-compatible gateway, update `models.llm` in each stage configuration, for example:

```yaml
models:
  llm:
    provider: openai
    model_name: "your-model-id"
    base_url: "https://your-gateway/v1"
    temperature_policy: omit
    token_limit_parameter: max_tokens
```

Set the model ID, gateway URL, and sampling parameters for your service. If the model requires `max_completion_tokens`, use that value for `token_limit_parameter`.

Create a `.env` file in the repository root with the key for your provider. The scripts load it automatically:

```dotenv
OPENAI_API_KEY=your_api_key
# ANTHROPIC_API_KEY=your_api_key
# GOOGLE_API_KEY=your_api_key
```

The providers `openai`, `anthropic`, and `gemini` read `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and `GOOGLE_API_KEY`, respectively. Stage configurations contain placeholders. Set the actual provider, model ID and optional compatible gateway before making model requests; keep `api_key: null` so the credential comes from the environment. Here `openai` also supports services implementing that protocol.

MiniLM is downloaded on first use. Online reranking also downloads and loads CodeLlama-7B. To use existing local weights, set `models.code_encoder.model_name` to the model directory. For GPU execution, set `experiment.device` to `cuda` and choose a suitable `models.code_encoder.dtype`, such as `float16`.

## Offline Stage: Build the Knowledge Base

Prepare an offline dataset, such as `data/raw/Offline-dataset.csv`. CSV, JSON arrays, and JSONL are supported. Each record must include:

| Field | Content |
| --- | --- |
| `cve_description` | Vulnerability description |
| `buggy_code` | Vulnerable code |
| `fixed_code` or `patch` | Repaired code, or a single-file unified diff that matches the vulnerable code |

Optional fields include `cve_id`, `project`, `language`, and `sample_id`. You must prepare the offline dataset yourself. Convert raw benchmark data into this record format before building the index.

```bash
python scripts/run_offline.py \
  --config config/offline.yaml \
  --data-path data/raw/Offline-dataset.csv \
  --output-dir data/indices/knowledge_v2 \
  --batch-size 32
```

The main files in the completed output directory are:

```text
knowledge_v2/
├── index_data_flow.faiss       # Data-flow index
├── index_control_flow.faiss    # Control-flow index
├── metadata.pkl               # Vulnerable/repaired code and knowledge for both views
├── manifest.json              # Build configuration and identity
└── build_report.json          # Build status and failure records
```

No generated index is bundled. The commands below expect an index at `data/indices/knowledge_index`. To use the knowledge base built by the preceding command, set `--indices-dir data/indices/knowledge_v2`; when starting Studio, pass the same `--indices-dir` value.

## Online Stage: End-to-End Repair

Each case directory must contain source code and a `test_cmds.json` file specifying the Docker image, target source path, and compilation and test commands. Prepare external cases under `data/processed/Vul4c` and `data/processed/PatchEval`; these datasets are not bundled.

Ensure that `online.phase3_repair.validation.execution_mode` in `config/base.yaml` is set to `docker`, the current default. The online pipeline runs diagnosis, retrieval, reranking, patch generation, compilation, and tests, then iterates using failure feedback.

Before model initialization, Docker cases must pass a source-baseline check. The
declared `source_file` selects the repair target. Both the compilation/PoC and
unit-test preparation commands must produce identical target bytes, matching the
source sent to the agents. Source, preparation commands and the immutable Docker
image ID are bound together; the validator checks that image ID again before
executing a candidate. Changed or unknown inputs are inspected afresh, and a
mismatch stops the case before any model request.

Audit and align all prepared cases after installing their images:

```bash
.venv/bin/python scripts/sync_case_sources.py --apply --workers 4
```

Use `--dataset Vul4c`, `--dataset PatchEval`, or `--case CVE-2017-6830` to restrict
the scope. Without `--apply`, the command only reports differences. Each run saves
original and container sources plus a report under `results/source_baseline_audit/`.
An aligned case receives `source_baseline.json`; unchanged source, recipe and image
identities can reuse this evidence without cloning the repository at every stage.
Successful interactive preflights also save their receipts. Later stages can reuse
the prior stage's receipt after checking the current source, commands and image ID.
Different PoC/unit sources or failed preparation block alignment rather than
overwriting a case. Start a **new repair task** after alignment: previously saved
diagnosis reports and patches belong to their original source snapshot.
To continue a completed or interrupted audit without repeating verified checkouts,
add `--reuse-verified`. This still checks source, command and current image identities;
unknown or changed cases are inspected in containers. Large source checkouts use a
600-second timeout per preparation step, configurable with `--timeout`.

Four legacy ngiflib cases prepare their Latin-1 comments as UTF-8 before source
installation in both container paths. The converter rejects legacy bytes outside
C comments, preserving code and string literals. This preparation is recorded in
`test_cmds.json` and included in the source-baseline recipe hash.

### Vul4C

Pull the Vul4C image:

```bash
docker pull vul4c/vul4c:4.0
```

Run end-to-end repair using the prepared single-file case list:

```bash
python scripts/run_online.py \
  --config config/online.yaml \
  --vul-files-dir data/processed/Vul4c \
  --case-list-file data/processed/Vul4c/vul4c_singlefile_cases.txt \
  --indices-dir data/indices/knowledge_index \
  --output-dir results/vul4c
```

The online entry point currently selects one source file per case, so this command uses the single-file case list.

To validate an existing candidate after downloading its image, reuse the saved
source, patch and validation commands without calling the model again:

```bash
.venv/bin/python scripts/validate_saved_patch.py --case-dir results/studio/runs/<task-id>/engine/cases/<CVE-ID> --candidate-id <number>
```

Choose a candidate with a nonempty `effective.patch`. The command runs the native
patch application, compilation, PoC and unit-test checks, then verifies the saved
hashes and container source receipts. Each invocation writes an independent record
under `results/validation_replay/`; `revalidation.json` contains the final status,
and `cases/<CVE-ID>/attempts/<number>/` contains the stage logs and receipts.
Exit code 0 means all four stages passed, 1 means validation did not pass, and 2
means the command could not complete. This command preserves the original repair
history; the existing Studio task continues to display its original results.

### PatchEval

Each PatchEval case has its own image. To pull the image for one case:

```bash
docker pull ghcr.io/anonymous2578-data/cve-2022-31506:latest
```

To pull all images required by the case list, read the image names directly from each case's `test_cmds.json`:

```bash
python - <<'PY'
import json
import subprocess
from pathlib import Path

root = Path("data/processed/PatchEval")
lines = (root / "patcheval_140_with_image.txt").read_text().splitlines()
case_ids = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
images = {
    json.loads((root / case_id / "test_cmds.json").read_text())["docker_image"]
    for case_id in case_ids
}
for image in sorted(images):
    subprocess.run(["docker", "pull", image], check=True)
PY
```

Run end-to-end repair using the same case list:

```bash
python scripts/run_online.py \
  --config config/online.yaml \
  --vul-files-dir data/processed/PatchEval \
  --case-list-file data/processed/PatchEval/patcheval_140_with_image.txt \
  --indices-dir data/indices/knowledge_index \
  --output-dir results/patcheval
```

### Run a Single Case First

For example, use the PatchEval image pulled above:

```bash
python scripts/run_online.py \
  --config config/online.yaml \
  --vul-files-dir data/processed/PatchEval/CVE-2022-31506 \
  --indices-dir data/indices/knowledge_index \
  --output-dir results/patcheval_single
```

You can also add `--limit 1` to a batch command to run only the first case in the list.

## Results and Resuming Runs

Each run saves `summary.json` under `--output-dir`. Each case has a `cases/<case_id>/` directory containing `result.json`, patches, and validation logs under `attempts/`. A repair is successful only when patch application, compilation, PoC tests, and unit tests all pass.

Recompute results for both experiments:

```bash
python scripts/evaluate.py --experiment-dir results/vul4c
python scripts/evaluate.py --experiment-dir results/patcheval
```

After an interruption, rerun the same command to resume. Add `--retry-failed` to retry failed online cases. Use a new output directory after changing models, data, configuration, or code.

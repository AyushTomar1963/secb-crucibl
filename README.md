# secbench-strict

**A stricter evaluation harness for LLM agents on [SEC-bench](https://github.com/SEC-bench/SEC-bench) vulnerability patching** — sandboxed so the agent can't look the answer up, two-stage so *localisation* and *repair* are scored separately, and with the oracle's blind spots made visible.

![tests](https://img.shields.io/badge/unit_tests-16%20passing-brightgreen) ![status](https://img.shields.io/badge/agent_runs-not_yet_run-orange)

## What this is

- Built a tree-sitter **localisation scorer** that maps a gold fix diff onto enclosing function spans in C/C++ and scores an agent's predicted file / symbol / line range against it (file-hit, symbol-hit, line-hit, best line-IoU).
- Built a **leakage-resistant sandbox design**: agent loop on the host, tools via `docker exec` into a `--network none` container, git history scrubbed with the base-commit hash preserved, API key never inside the container.
- Built a **deterministic failure taxonomy** (TOOL_LOOP, NO_PATCH, APPLY_FAIL, BUILD_BREAK, HANG, LOC_MISS, SAME_CRASH, SHIFTED_CRASH, PASS variants) and a four-arm ablation design (`stock` → `single_sb` → `two_stage` → `two_stage_orc`).
- Read the upstream evaluator source rather than assuming (see §2) and found its oracle has **no test step**, so "regression break" is not measurable as specified.

## Results (measured)

Everything below is computed from the public SEC-bench dataset alone — **no Docker and no model were used**. Reproduce with `python -m secb_strict.h3_baseline eval`. Raw per-instance output: [`results/h3_crash_frame_eval.json`](results/h3_crash_frame_eval.json).

### Free localisation already sits in the patch prompt (H3 baseline)

SEC-bench's patch prompt embeds the full sanitizer report. How well does the **top in-repo crash frame** — zero agent skill — point at what the gold patch edits? (`eval` split, n=300; 278 have a usable frame; 95% Wilson CIs.)

| Signal | Hits | Rate | 95% CI |
|---|---|---|---|
| Top crash frame is in a **file** the gold patch edits | 147 / 278 | **52.9%** | 47.0–58.7% |
| …in the **function** named by a gold hunk header (lower bound*) | 87 / 278 | 31.3% | 26.1–37.0% |
| …on a **line** inside a gold hunk's pre-image (incl. ±3 context lines) | 50 / 278 | 18.0% | 13.9–22.9% |
| **Any** in-repo frame in the stack is in a gold-patch file | 252 / 278 | **90.6%** | 86.6–93.5% |

\*Function hit uses git's hunk-header context, not tree-sitter spans, so it under-counts relative to `ast_verifier`.

Split breakdown (the `eval` split is exactly `cve` ∪ `oss`, 200 + 100, no overlap): CVE file-hit 57.5% (107/186), OSS 43.5% (40/92).

**Reading it:** in ~9 of 10 instances a gold-patch file is already named somewhere in the crash stack handed to the agent, and the single top frame gets the right file about half the time. Any Stage-A localiser has to beat these numbers to show real skill — and file-level localisation on stock SEC-bench is largely free.

### Other measured facts
- **Bug found and fixed:** `crash_frame_baseline` required frames under `work_dir`, but most CVE-split reports were captured on the reporter's machine (e.g. `/home/<user>/.../njs_f65981b/src/…`). It returned *no frame for 197 of 200 CVE instances* — silently disabling the mandatory baseline. Fixed with a suffix-matching fallback (used for 183 instances) that also skips sanitizer-runtime frames (`asan_interceptors`, `compiler-rt`, `libsanitizer`; an audit found 10 such wrong picks before the filter). Regression test added.
- Split sizes confirmed from the dataset: `eval` 300, `cve` 200, `oss` 100.
- Unit tests: **16 pass**.

### Not yet run (be honest about it)
H1 (leakage), H2 (localisation vs. repair), H4 (oracle false-passes) and the agent-vs-baseline half of H3 need Docker images and a live model. The authoring machine had neither a Docker daemon nor an API key, so `sandbox.py`, `preflight.py` and the smolagents glue in `dual_runner.py` remain **unexercised**. No pass-rate numbers exist yet.

## Impact
- Gives SEC-bench users a **baseline any claimed localisation skill must beat**: a zero-skill heuristic already reaches ~53% file-hit and ~91% "file somewhere in the stack".
- Exposes and fixes a silent failure mode in crash-frame parsing across heterogeneous report formats, so baselines don't quietly vanish on 2/3 of the dataset.
- Provides a ready harness to run the four-arm ablation once Docker and a model are available; claims stay falsifiable (each hypothesis below lists what would refute it).

## 1. Hypotheses (each can come out false)

| # | Claim | Falsified if |
|---|-------|--------------|
| H1 | Stock SEC-bench patch scores are inflated by leakage (git history, network, advisories). | Stock-arm trajectories almost never touch `git log/show`, `curl`, `pip download`, or the web, and `stock` vs `single_sb` pass rates are statistically indistinguishable. A null here is a finding, not a failure. |
| H2 | Localisation is a major share of failures, separable from repair. | `two_stage_orc` (gold location handed over) pass rate ≈ `two_stage`. |
| H3 | Crash-frame localisation (free, from the sanitizer report already in the prompt) rivals the agent's Stage A. | Stage A beats the top-in-repo-frame baseline on gold-function hit rate. |
| H4 | The stock oracle (apply → compile → no sanitizer) passes some non-fixes. | `PASS_ALT_SITE` / `PASS_DELETION_HEAVY` runs all survive differential review against the gold-patched binary. |

## 2. What SEC-bench actually does (read from source, not assumed)

| Fact | Where | Consequence for this project |
|---|---|---|
| Patch eval = `git apply` → `secb build` → `timeout 10 secb repro`. **No test step.** | `evaluator/templates/eval_patch_script.j2` | "Regression break" is not measurable as specified. See `analyze_failures.py`. |
| Success modes strict / medium / generous (exit code vs. dataset `exit_code`, no sanitizer report). | `eval_instances.interpret_patch_results` | Report **strict and medium**. |
| Patch prompt embeds `bug_description` + full `sanitizer_report`. | `smolagents/prompts/patch.j2` | The crash stack is free localisation → crash-frame baseline is mandatory. |
| `secb-run` runs the agent **inside** the container, pip-installs smolagents there, passes the API key via env, default `network_mode="host"`. | `smolagents/cli.py`, `config.example.toml` | A bare `--network none` kills the agent and the key is readable by it → agent loop on host, tools via `docker exec`. |
| Eval images are micro-repos only when the Dockerfile has an adjacent `git clone`/`git checkout` pair (regex). | `build_eval_instances.clean_git_repo_commits` | Likely already minimal; **audit each image**, don't assume. |
| Patch collector: `git diff --cached <base_commit> '*.c' '*.h' …`; validation: `git reset --hard <base_commit>`. | `smolagents/cli.py`, `build_eval_instances.validate_image` | An orphan commit changes the hash and breaks both → scrub keeps the hash. |
| Image validation already checks exploit crashes pre-patch and gold patch is clean. | `build_eval_instances.validate_image` | `preflight.py` re-checks under *your* runtime + flakiness. |
| Dataset has gold `patch`, `sanitizer_report`, `exit_code`; no tests field. | HF dataset card | Gate 1 is feasible; Gate 2 can't use tests. Verify split sizes yourself: `load_dataset("SEC-bench/SEC-bench", split=...)` (the card was ambiguous about 200/300 counts). |

## 3. Setup

```bash
git clone --recurse-submodules https://github.com/SEC-bench/SEC-bench   # upstream, for secb.evaluator.*
pip install -e ".[dev,agent]"
export PYTHONPATH=$PWD:$PWD/SEC-bench            # `secb` (upstream) + `secb_strict` (this repo)
export ANTHROPIC_API_KEY=...                      # host only; never enters a container
PYTHONPATH=$PWD:$PWD/SEC-bench pytest -q
# Windows PowerShell: $env:PYTHONPATH = "$PWD;$PWD\SEC-bench"; pytest -q   (";" separator, not ":")
python -m secb_strict.h3_baseline eval   # reproduces the measured results above (needs network for HF dataset only)

# 1. choose instances; drop untrustworthy images BEFORE any agent runs
python -m secb_strict.preflight --split cve --ids <25 ids> --repeats 3
# 2. run arms (stock via upstream `smolagent secb-run`; others via secb_strict.dual_runner)
# 3. score with upstream eval_instances (--mode all), then:
python -m secb_strict.analyze_failures --records <records.jsonl>
```

Docker needs >200 GB free (upstream recommendation). The authoring environment had
no Docker daemon, so `sandbox.py`, `preflight.py` and the smolagents glue in
`dual_runner.py` are **unexercised**; the pure logic (AST mapping, scoring,
prompts/JSON, orchestration, classification) is tested.

### Layout
```
secb_strict/        (named `secb_strict`, not `secb/strict`: upstream's package is `secb`)
  sandbox.py        git audit + hash-preserving scrub + network-none container, host-side exec
  preflight.py      red/green/flake/no-network control; drops bad images
  h3_baseline.py    dataset-only crash-frame baseline (measured results)
  ast_verifier.py   gold diff -> function spans; Stage-A scoring; crash-frame baseline
  dual_runner.py    arms: single_sb | two_stage | two_stage_orc
  analyze_failures.py  deterministic taxonomy
configs/            claude_codeagent.toml, claude_toolcalling.toml
results/            metrics_comparison.csv (header only), failure_case_studies.md (template)
tests/
```

## 4. Method

**Arms** (isolate one change at a time): `stock` → `single_sb` (+sandbox) → `two_stage` (+protocol) → `two_stage_orc` (gold location given).

**Gate 1 — localisation (a metric, not an AND-gate).** Gold diff → enclosing function
nodes in the base commit via tree-sitter; pure-addition hunks anchor at the insertion
point; multi-function gold is a set. Report file/symbol/line-hit and best line-IoU,
next to the crash-frame baseline. Valid alternative fix sites exist, so Gate 1 never
vetoes a pass on its own.

**Gate 2 — red/green.** Upstream's oracle, reported in strict and medium modes, plus
`PASS_ALT_SITE` / `PASS_DELETION_HEAVY` flags and a differential review (gold-patched vs.
agent-patched binary on benign inputs) for flagged passes.

**Failure taxonomy** (see `analyze_failures.py` docstring): TOOL_LOOP, NO_PATCH,
APPLY_FAIL, BUILD_BREAK, HANG, LOC_MISS, SAME_CRASH (= patch-shaped edit),
SHIFTED_CRASH, and the PASS variants.

**Statistics.** n≈25 gives wide intervals (≈±19 pp at p=0.5). Use ≥3 seeds, paired
tests across arms (McNemar on per-instance outcomes), and present this as a case study,
not a leaderboard claim.

## 5. Results
See the measured H3-baseline results at the top; agent arms are not yet run. → `results/metrics_comparison.csv`

## 6. Findings
_Pending. Write only what the data supports; H1 may well come out null._

## Known limitations
- Gate 1 file matching is path-suffix based (`same_file`), so a bare-basename prediction can match a deeper gold path.
- Collector only keeps C/C++ paths (mirrors upstream): fixes in other file types are dropped, and gold edits outside any function (globals/macros) are reported as `unmapped`.
- Macro-heavy C can yield tree-sitter ERROR nodes; spans carry `parse_error`.
- No project test suites in the images; differential review is the substitute.

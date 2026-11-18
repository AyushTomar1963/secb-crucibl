# secbench-strict

A stricter evaluation of LLM agents on SEC-bench vulnerability patching:
sandboxed so the agent can't look the answer up, two-stage so localisation and
repair are measured separately, and with the oracle's blind spots made visible.

> Status: scaffold. Unit tests pass (15). **Nothing has been run against real
> images or a live model yet** — no numbers below are measured.

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
_No runs yet._ → `results/metrics_comparison.csv`

## 6. Findings
_Pending. Write only what the data supports; H1 may well come out null._

## Known limitations
- Collector only keeps C/C++ paths (mirrors upstream): fixes in other file types are dropped, and gold edits outside any function (globals/macros) are reported as `unmapped`.
- Macro-heavy C can yield tree-sitter ERROR nodes; spans carry `parse_error`.
- No project test suites in the images; differential review is the substitute.

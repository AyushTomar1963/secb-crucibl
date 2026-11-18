"""Deterministic failure taxonomy for patch runs (no LLM judge).

Why these buckets differ from "Localisation Miss / Patch-Shaped Edit /
Regression Break / Tool Loop":

  SEC-bench's patch evaluator runs exactly: git apply -> compile -> repro (see
  evaluator/templates/eval_patch_script.j2). There is NO functional test step,
  so "regression break" and "passes unit tests, fails PoC" are not observable.
  Upstream's own labels are NP / IP / CE / FF(+UNKNOWN). We refine them using
  only signals that exist: the eval log, the sanitizer report before/after, the
  trajectory, and the AST map of gold vs. predicted edit sites.

Priority order (first match wins) for FAILED runs:
  TOOL_LOOP       no patch AND (step cap hit OR the same command repeated in a loop)
  NO_PATCH        no patch otherwise                                  (upstream NP)
  APPLY_FAIL      `FAIL_STEP: Git apply`                              (upstream IP)
  BUILD_BREAK     `FAIL_STEP: Compile`  <- computable stand-in for "regression break"  (CE)
  HANG            repro timed out (patch introduced a hang)
  LOC_MISS        crash persists AND edited functions disjoint from gold functions
  SAME_CRASH      crash persists, edit hit the gold function(s) -> "patch-shaped edit"
  SHIFTED_CRASH   a *different* sanitizer signature appears (new bug / moved crash)
  UNKNOWN
Passing runs are split so false passes are visible instead of silently counted:
  PASS            edit overlaps gold function(s)
  PASS_ALT_SITE   passes but edits only functions the gold patch did not touch
                  (valid alternative fix OR symptom suppression -- needs review)
  PASS_DELETION_HEAVY  passes, but removes far more than it adds (suppression smell)
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Optional

from secb_strict.ast_verifier import changed_old_lines, crash_signature, gold_spans


@dataclass
class EvalRecord:
    instance_id: str
    success: bool
    patch: str
    reason: str = ""            # step_reason from upstream interpret_patch_results
    logs: str = ""              # container log of the eval run
    base_sanitizer_report: str = ""
    work_dir: str = ""
    commands: list[str] = field(default_factory=list)
    max_steps_hit: bool = False
    gold_patch: str = ""


def _norm_cmd(c: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"\d+", "N", c.strip()))[:200]


def detect_tool_loop(commands: list[str], max_steps_hit: bool,
                     consecutive: int = 4, total: int = 8) -> bool:
    """Same normalised command >= `consecutive` times in a row, or >= `total` times overall."""
    if max_steps_hit:
        return True
    norm = [_norm_cmd(c) for c in commands]
    run = 1
    for a, b in zip(norm, norm[1:]):
        run = run + 1 if a == b else 1
        if run >= consecutive:
            return True
    return any(n >= total for n in Counter(norm).values())


def _edit_stats(patch: str) -> tuple[int, int]:
    add = sum(1 for l in patch.splitlines() if l.startswith("+") and not l.startswith("+++"))
    rem = sum(1 for l in patch.splitlines() if l.startswith("-") and not l.startswith("---"))
    return add, rem


def classify(rec: EvalRecord, read_base_file: Optional[Callable[[str], Optional[str]]] = None) -> str:
    patch = (rec.patch or "").strip()

    gold_fns = pred_fns = None
    if read_base_file is not None and rec.gold_patch and patch:
        g, _ = gold_spans(rec.gold_patch, read_base_file)
        p, _ = gold_spans(patch, read_base_file)
        gold_fns = {(s.file, s.symbol) for s in g}
        pred_fns = {(s.file, s.symbol) for s in p}

    if rec.success:
        if gold_fns is not None and pred_fns and gold_fns.isdisjoint(pred_fns):
            return "PASS_ALT_SITE"
        add, rem = _edit_stats(patch)
        if rem >= 10 and rem > 3 * max(add, 1):
            return "PASS_DELETION_HEAVY"
        return "PASS"

    if not patch:
        return "TOOL_LOOP" if detect_tool_loop(rec.commands, rec.max_steps_hit) else "NO_PATCH"
    if "FAIL_STEP: Git apply" in rec.reason or "FAIL_STEP: Git apply" in rec.logs:
        return "APPLY_FAIL"
    if "FAIL_STEP: Compile" in rec.reason or "FAIL_STEP: Compile" in rec.logs:
        return "BUILD_BREAK"
    if "timed out" in rec.reason or "Run PoC exit code: 124" in rec.logs or "Run PoC exit code: 137" in rec.logs:
        return "HANG"

    # crash persists: same or different sanitizer signature?
    from secb.evaluator.utils import extract_sanitizer_report  # upstream detector

    after = extract_sanitizer_report(rec.logs)
    if after is None:
        return "UNKNOWN"
    same = crash_signature(after, rec.work_dir) == crash_signature(rec.base_sanitizer_report, rec.work_dir)
    if not same:
        return "SHIFTED_CRASH"
    if gold_fns is not None and pred_fns is not None and gold_fns.isdisjoint(pred_fns):
        return "LOC_MISS"
    return "SAME_CRASH"


def main() -> None:
    ap = argparse.ArgumentParser(description="Tag failures; read JSONL of EvalRecord fields.")
    ap.add_argument("--records", required=True)
    ap.add_argument("--out", default="results/failure_counts.csv")
    args = ap.parse_args()
    counts: Counter = Counter()
    with open(args.records) as f:
        for line in f:
            counts[classify(EvalRecord(**json.loads(line)))] += 1   # no base-file reader => no LOC_MISS/ALT_SITE
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["bucket", "n"]); w.writerows(sorted(counts.items()))
    print(dict(counts))


if __name__ == "__main__":
    main()

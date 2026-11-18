"""H3 crash-frame baseline, computed from the dataset alone (no Docker, no model).

For each instance: does the top in-repo frame of the sanitizer report (the free
localisation already in the patch prompt) land in a file / function that the gold
patch edits?

Approximations (no base-commit sources are checked out here):
  * file hit   : exact, crash-frame file in gold-patch file set.
  * symbol hit : crash-frame function name equals the function named in a gold hunk
                 header (git's `@@ ... @@ <funcname>` context). Hunk-header context is
                 a heuristic (it names the nearest preceding function-like line), so
                 this under-counts vs. the tree-sitter span mapping in ast_verifier.
  * line hit   : crash-frame line lies within a gold hunk's pre-image range
                 (includes 3 lines of diff context on each side).
  * any_frame_file : ANY in-repo frame in the stack is in a gold file (upper bound).
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter

from datasets import load_dataset

from secb_strict.ast_verifier import (
    _bare,
    _norm_file,
    _strip_prefix,
    crash_frame_baseline,
    sanitizer_frames,
    same_file,
    _SYSTEM_PREFIXES,
    _RUNTIME_RE,
)

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@ ?(.*)$")
_FUNC = re.compile(r"([A-Za-z_~][\w:~]*)\s*\(")


def gold_hunks(diff: str) -> dict[str, list[tuple[int, int, str]]]:
    out: dict[str, list] = {}
    cur = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            p = _strip_prefix(line[4:])
            cur = None if p == "/dev/null" else p
            if cur:
                out.setdefault(cur, [])
        elif cur and (m := _HUNK.match(line)):
            start = int(m.group(1))
            ln = int(m.group(2)) if m.group(2) is not None else 1
            fm = _FUNC.findall(m.group(3) or "")
            out[cur].append((start, start + max(ln, 1) - 1, _bare(fm[-1]) if fm else ""))
    return out


def evaluate(split: str = "eval") -> dict:
    ds = load_dataset("SEC-bench/SEC-bench", split=split)
    c = Counter()
    rows = []
    for r in ds:
        c["n"] += 1
        wd = r["work_dir"] or ""
        gold = gold_hunks(r["patch"] or "")
        gold_files = {_norm_file(f) for f in gold}
        base = crash_frame_baseline(r["sanitizer_report"] or "", wd)
        row = {"instance_id": r["instance_id"], "n_gold_files": len(gold_files)}
        if not base:
            c["no_crash_frame"] += 1
            rows.append({**row, "baseline": None})
            continue
        c["with_crash_frame"] += 1
        fhit = any(same_file(base["file"], g) for g in gold_files)
        shit = lhit = False
        for gf, hunks in gold.items():
            if not same_file(_norm_file(gf), base["file"]):
                continue
            for s, e, sym in hunks:
                if sym and sym == _bare(base["symbol"]):
                    shit = True
                if s <= base["start_line"] <= e:
                    lhit = True
        anyf = any(
            not f["file"].startswith(_SYSTEM_PREFIXES)
            and not _RUNTIME_RE.search(f["file"])
            and any(same_file(_norm_file(f["file"], wd), g) for g in gold_files)
            for f in sanitizer_frames(r["sanitizer_report"], wd)
        )
        c["file_hit"] += fhit
        c["symbol_hit"] += shit
        c["line_hit"] += lhit
        c["any_frame_file_hit"] += anyf
        c["multi_file_gold"] += len(gold_files) > 1
        rows.append({**row, "baseline": base, "file_hit": fhit, "symbol_hit": shit,
                     "line_hit": lhit, "any_frame_file_hit": anyf})
    return {"split": split, "counts": dict(c), "rows": rows}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if not n:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (c - h, c + h)


if __name__ == "__main__":
    split = sys.argv[1] if len(sys.argv) > 1 else "eval"
    res = evaluate(split)
    json.dump(res, open(f"results/h3_crash_frame_{split}.json", "w"), indent=1)
    c = res["counts"]
    c["fallback_path_used"] = sum(1 for r in res["rows"] if (r.get("baseline") or {}).get("raw_path"))
    n = c["with_crash_frame"] or 1
    print(json.dumps(c, indent=1))
    for k in ("file_hit", "symbol_hit", "line_hit", "any_frame_file_hit"):
        lo, hi = wilson(c.get(k, 0), n)
        print(f"{k}: {c.get(k,0)}/{n} = {c.get(k,0)/n:.1%}  (95% CI {lo:.1%}-{hi:.1%})")

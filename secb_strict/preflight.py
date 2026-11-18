"""Preflight red/green control: run BEFORE any agent touches an instance.

SEC-bench already validates each image once at build time (exploit crashes on
the base commit; gold patch builds and repro is clean). That does not cover
*your* configuration. This re-checks every image under the hardened runtime
(`--network none`, scrubbed git) and drops anything that is not trustworthy:

  RED    empty patch  -> `secb build` ok, `secb repro` shows a sanitizer report
                         (a stub `repro()` that exits 0 would make every patch "pass")
  GREEN  gold patch   -> apply, build ok, `secb repro` clean (exit 0, no report)
  FLAKE  repeat each phase N times; any disagreement => drop
  NET    everything above must work with the network disabled (submodule update,
         build scripts that fetch things, etc. fail here, not in your results)

Usage (on a Docker host with the eval images pulled):
    python -m secb_strict.preflight --split cve --ids a b c --repeats 3 \
        --out results/preflight.jsonl
"""

from __future__ import annotations

import argparse
import json
import shlex
from pathlib import Path

from secb_strict.ast_verifier import crash_signature
from secb_strict.sandbox import SandboxedContainer

IMAGE_PREFIX = "hwiwonlee/secb.eval.x86_64"


def _sanitizer_report(text: str):
    # Reuse upstream's detector so "crash" means exactly what the stock evaluator means.
    from secb.evaluator.utils import extract_sanitizer_report  # SEC-bench must be installed

    return extract_sanitizer_report(text)


def _run_phase(box: SandboxedContainer, gold_patch: str | None, row: dict) -> dict:
    wd = shlex.quote(row["work_dir"])
    # Same reset the upstream validate_image() does; no `git clean -x` (could delete build state).
    box.exec(f"cd {wd} && git reset --hard -q {row['base_commit']}", timeout=300)
    res: dict = {"applied": None}
    if gold_patch is not None:
        box.exec(f"mkdir -p /testcase && cat > /testcase/model_patch.diff <<'EOF_PATCH'\n{gold_patch}\nEOF_PATCH")
        code, out = box.exec(f"cd {wd} && secb patch", timeout=120)
        res["applied"] = code == 0
        if code != 0:
            return {**res, "build": None, "crash": None, "tail": out[-400:]}
    code, out = box.exec(f"cd {wd} && secb build", timeout=1800)
    res["build"] = code == 0
    if code != 0:
        return {**res, "crash": None, "tail": out[-400:]}
    code, out = box.exec(f"cd {wd} && timeout 10 secb repro", timeout=60)
    rep = _sanitizer_report(out)
    res.update(repro_exit=code, crash=rep is not None,
               sig=repr(crash_signature(rep or "", row["work_dir"])), timeout=code in (124, 137))
    return res


def preflight_instance(row: dict, repeats: int = 3) -> dict:
    image = f"{IMAGE_PREFIX}.{row['instance_id']}:patch"
    out = {"instance_id": row["instance_id"], "red": [], "green": [], "ok": False, "reasons": []}
    with SandboxedContainer(image, row["work_dir"], row["base_commit"]) as box:
        audit = box.audit_git()
        out["git_audit"] = audit.to_dict()
        if not audit.base_commit_present:
            out["reasons"].append("base_commit missing from .git (collector/validation would break)")
        if audit.leaks_history:
            box.scrub_git()
            out["git_audit_after_scrub"] = box.audit_git().to_dict()
        for _ in range(repeats):
            out["red"].append(_run_phase(box, None, row))
            out["green"].append(_run_phase(box, row["patch"], row))

    red_ok = all(p.get("build") and p.get("crash") for p in out["red"])
    green_ok = all(p.get("applied") and p.get("build") and p.get("crash") is False and not p.get("timeout")
                   for p in out["green"])
    red_stable = len({p.get("sig") for p in out["red"]}) == 1
    if not red_ok: out["reasons"].append("RED failed: base does not build+crash reliably (stub repro / network dependency?)")
    if not green_ok: out["reasons"].append("GREEN failed: gold patch does not yield a clean, stable run")
    if not red_stable: out["reasons"].append("FLAKE: crash signature differs across repeats")
    out["ok"] = not out["reasons"]
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="cve", choices=["eval", "cve", "oss"])
    ap.add_argument("--ids", nargs="+", required=True)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--out", default="results/preflight.jsonl")
    args = ap.parse_args()

    from datasets import load_dataset

    ds = {r["instance_id"]: r for r in load_dataset("SEC-bench/SEC-bench", split=args.split)}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "a") as f:
        for iid in args.ids:
            res = preflight_instance(ds[iid], args.repeats)
            f.write(json.dumps(res) + "\n"); f.flush()
            print(("PASS " if res["ok"] else "DROP ") + iid, *res["reasons"], sep="\n   ")


if __name__ == "__main__":
    main()

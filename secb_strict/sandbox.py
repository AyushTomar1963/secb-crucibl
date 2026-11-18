"""Sandbox hardening for SEC-bench eval images.

What the stock harness does (verified in SEC-bench/SEC-bench and its smolagents
fork), and why a bare `--network none` is not enough:

  * `secb-run` starts the container with network_mode="host" (config default),
    pip-installs smolagents INSIDE it, copies /app/runner.py in, and passes the
    LLM API key through the container environment. The LLM call therefore
    happens from inside the container, and the agent can read the key.
  * Eval images are already "micro-repos" for adjacent `git clone`/`git checkout`
    pairs (build_eval_instances.clean_git_repo_commits), but that is a regex;
    instances that don't match it keep whatever the original Dockerfile did.
  * The patch collector runs `git diff --cached <base_commit> '*.c' '*.h' ...`
    and image validation runs `git reset --hard <base_commit>`. Both need the
    ORIGINAL commit hash, so an orphan single-commit repo (new hash) breaks
    them. We keep the hash.

So this module (1) AUDITS each image's git state, (2) optionally scrubs what
is still reachable WITHOUT changing HEAD's hash, and (3) runs the container with
`network_mode="none"` while the agent loop runs on the HOST and executes tools
through `docker exec` (the key never enters the container).
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Optional

# Same pathspec the stock collector uses; edits to other file types are dropped
# there too, so we mirror it (and report it as a known limitation in the README).
SRC_PATHSPEC = ["*.c", "*.cpp", "*.h", "*.hpp", "*.cc", "*.hh"]


@dataclass
class GitAudit:
    work_dir: str
    commits_reachable: int = -1
    refs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    remotes: list[str] = field(default_factory=list)
    is_shallow: bool = False
    fetch_head: str = ""
    reflog_entries: int = -1
    submodules: bool = False
    base_commit_present: bool = False
    base_is_head: bool = False

    @property
    def leaks_history(self) -> bool:
        """True if an agent could `git log`/`git diff` its way to future code."""
        return (
            self.commits_reachable > 1
            or bool(self.tags)
            or bool(self.remotes)
            or any(r.startswith("refs/remotes/") or r.startswith("refs/tags/") for r in self.refs)
        )

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["leaks_history"] = self.leaks_history
        return d


AUDIT_SCRIPT = r"""
set -u
cd {wd}
echo "COMMITS=$(git rev-list --all 2>/dev/null | wc -l)"
echo "SHALLOW=$([ -f .git/shallow ] && echo 1 || echo 0)"
echo "REFLOG=$(git reflog 2>/dev/null | wc -l)"
echo "SUBMODULES=$([ -f .gitmodules ] && echo 1 || echo 0)"
echo "BASE_PRESENT=$(git cat-file -e {base}^{{commit}} 2>/dev/null && echo 1 || echo 0)"
echo "BASE_IS_HEAD=$([ "$(git rev-parse HEAD 2>/dev/null)" = "$(git rev-parse {base}^{{commit}} 2>/dev/null)" ] && echo 1 || echo 0)"
echo "FETCH_HEAD=$(cat .git/FETCH_HEAD 2>/dev/null | head -c 300 | tr '\n' ' ')"
echo "--REFS--"; git for-each-ref --format='%(refname)' 2>/dev/null
echo "--TAGS--"; git tag 2>/dev/null
echo "--REMOTES--"; git remote -v 2>/dev/null
"""


def parse_audit(work_dir: str, out: str) -> GitAudit:
    a = GitAudit(work_dir)
    section = None
    for line in out.splitlines():
        if line.startswith("--") and line.endswith("--"):
            section = line.strip("-")
            continue
        if section is None:
            k, _, v = line.partition("=")
            if k == "COMMITS": a.commits_reachable = int(v or -1)
            elif k == "SHALLOW": a.is_shallow = v == "1"
            elif k == "REFLOG": a.reflog_entries = int(v or -1)
            elif k == "SUBMODULES": a.submodules = v == "1"
            elif k == "BASE_PRESENT": a.base_commit_present = v == "1"
            elif k == "BASE_IS_HEAD": a.base_is_head = v == "1"
            elif k == "FETCH_HEAD": a.fetch_head = v.strip()
        elif line.strip():
            {"REFS": a.refs, "TAGS": a.tags, "REMOTES": a.remotes}[section].append(line.strip())
    return a


# Scrub that PRESERVES the base-commit hash (do not use `git checkout --orphan`).
SCRUB_SCRIPT = r"""
set -eu
cd {wd}
git checkout -q --detach {base}
# drop every ref except HEAD, plus tags/remotes/stash
git for-each-ref --format='%(refname)' | xargs -r -n1 git update-ref -d
git tag -l | xargs -r git tag -d >/dev/null
git remote | xargs -r -n1 git remote remove
rm -f .git/FETCH_HEAD .git/ORIG_HEAD .git/packed-refs
git reflog expire --expire=now --all
git gc -q --prune=now --aggressive
"""


class SandboxedContainer:
    """Container with no network; the agent loop lives on the host.

    Requires `pip install docker`. Not exercised in CI here (no Docker daemon in
    the authoring environment) -- run `python -m secb_strict.preflight` on your
    Docker host before trusting it.
    """

    def __init__(self, image: str, work_dir: str, base_commit: str,
                 mem_limit: str = "8g", pids_limit: int = 2048):
        import docker  # lazy: keeps ast_verifier/analyze importable without Docker

        self.client = docker.from_env()
        self.image, self.work_dir, self.base_commit = image, work_dir, base_commit
        self.container = self.client.containers.run(
            image,
            command="sleep infinity",
            detach=True,
            network_mode="none",          # no GitHub, no advisories, no pip, no LLM API
            mem_limit=mem_limit,
            pids_limit=pids_limit,
            # Do NOT cap_drop=ALL by default: LeakSanitizer needs ptrace and the stock
            # harness keeps default caps, so dropping them changes repro behaviour
            # (a confound). Tighten only after preflight passes with it on.
            security_opt=["no-new-privileges"],
            environment={},               # NEVER pass API keys in
            working_dir=work_dir,
        )

    # -- tool execution (what the host-side agent's cmd tool calls) ------------
    def exec(self, command: str, timeout: int = 120, workdir: Optional[str] = None) -> tuple[int, str]:
        wrapped = f"timeout -k 5 {int(timeout)} bash -lc {shlex.quote(command)}"
        r = self.container.exec_run(["bash", "-c", wrapped], workdir=workdir or self.work_dir, demux=False)
        return r.exit_code, (r.output or b"").decode("utf8", "replace")

    def audit_git(self) -> GitAudit:
        _, out = self.exec(AUDIT_SCRIPT.format(wd=shlex.quote(self.work_dir), base=self.base_commit))
        return parse_audit(self.work_dir, out)

    def scrub_git(self) -> GitAudit:
        code, out = self.exec(SCRUB_SCRIPT.format(wd=shlex.quote(self.work_dir), base=self.base_commit), timeout=300)
        if code != 0:
            raise RuntimeError(f"git scrub failed: {out[-500:]}")
        return self.audit_git()

    def collect_patch(self) -> str:
        """Same extraction as the stock harness (relative to the ORIGINAL base hash)."""
        spec = " ".join(shlex.quote(p) for p in SRC_PATHSPEC)
        _, out = self.exec(
            f"cd {shlex.quote(self.work_dir)} && git config --global core.pager '' "
            f"&& git add -A && git diff --no-color --cached {self.base_commit} {spec}"
        )
        return out

    def close(self) -> None:
        try:
            self.container.remove(force=True)
        except Exception:
            pass

    def __enter__(self): return self
    def __exit__(self, *a): self.close()

"""Two-stage (Localise -> Repair) harness, with ablation arms.

The agent loop runs on the HOST. Its shell/python tool calls are executed via
`SandboxedContainer.exec` (docker exec into a network-none container), so the
LLM API key and network egress never exist inside the sandbox.

Arms (so the effects are separable -- see README "Hypotheses"):
  stock          single stage, SEC-bench's own patch.j2 prompt, stock harness
                 (run with upstream `smolagent secb-run`, NOT this module)
  single_sb      single stage, same prompt, hardened sandbox
  two_stage      Stage A (localise, JSON) -> Stage B (repair), own localisation
  two_stage_orc  Stage B receives the GOLD localisation (isolates repair skill)

Everything below the `# glue` marker is thin and untested against a live
model; the parts above it (prompts, JSON validation, arm logic) are pure and
unit-testable.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

ARMS = ("single_sb", "two_stage", "two_stage_orc")

LOC_SCHEMA_KEYS = {"file", "symbol", "start_line", "end_line"}

STAGE_A_PROMPT = """\
You are localising a memory-safety bug. The repository is in {work_dir}.

<issue_description>
{bug_description}
---
{sanitizer_report}
</issue_description>

Do NOT modify any files in this stage. Explore (find/grep/read) and decide where
the code should be FIXED -- the root cause, which may differ from the frame where
the sanitizer fired. Finish by calling final_answer with ONLY a JSON object:
{{"file": "<path relative to {work_dir}>", "symbol": "<function name>",
  "start_line": <int>, "end_line": <int>}}
where start_line..end_line is the span of the function you would edit.
"""

STAGE_B_PROMPT = """\
Repository: {work_dir}. Fix the vulnerability described below with the minimal
change to non-test C/C++ sources.

<issue_description>
{bug_description}
---
{sanitizer_report}
</issue_description>

Fix location (use this as your starting point):
{location_json}

Run `secb build` then `secb repro` in {work_dir}; success means repro shows NO
sanitizer error. Keep iterating until it does.
"""


def parse_stage_a(text: str) -> tuple[Optional[dict], str]:
    """Extract and validate the Stage-A JSON. Returns (obj|None, reason)."""
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        return None, "no_json"
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None, "bad_json"
    if not LOC_SCHEMA_KEYS <= obj.keys():
        return None, f"missing_keys:{sorted(LOC_SCHEMA_KEYS - obj.keys())}"
    try:
        obj["start_line"], obj["end_line"] = int(obj["start_line"]), int(obj["end_line"])
    except (TypeError, ValueError):
        return None, "non_int_lines"
    return obj, "ok"


@dataclass
class RunRecord:
    instance_id: str
    arm: str
    seed: int
    stage_a_raw: str = ""
    stage_a: Optional[dict] = None
    stage_a_status: str = ""
    patch: str = ""
    commands: list[str] = field(default_factory=list)  # for tool-loop detection
    steps: int = 0
    max_steps_hit: bool = False
    usage: dict = field(default_factory=dict)


def run_instance(
    row: dict,
    arm: str,
    seed: int,
    agent_run: Callable[[str, "SandboxedContainerLike"], tuple[str, list[str], int, bool]],
    box: "SandboxedContainerLike",
    gold_loc: Optional[dict] = None,
) -> RunRecord:
    """Pure orchestration. `agent_run(prompt, box) -> (final_text, commands, steps, hit_cap)`."""
    assert arm in ARMS, arm
    rec = RunRecord(row["instance_id"], arm, seed)
    fmt = dict(work_dir=row["work_dir"], bug_description=row["bug_description"],
               sanitizer_report=row["sanitizer_report"])

    if arm == "single_sb":
        from_stock = _stock_patch_prompt(row)
        _, cmds, steps, hit = agent_run(from_stock, box)
    else:
        if arm == "two_stage":
            text, cmds_a, steps_a, hit_a = agent_run(STAGE_A_PROMPT.format(**fmt), box)
            rec.stage_a_raw = text
            rec.stage_a, rec.stage_a_status = parse_stage_a(text)
            # Stage A must not edit; discard any accidental edits so Stage B starts clean.
            box.exec(f"cd {row['work_dir']} && git checkout -q -- . && git clean -fdq")
            loc = rec.stage_a or {"file": "UNKNOWN", "symbol": "UNKNOWN", "start_line": 0, "end_line": 0}
        else:  # two_stage_orc
            assert gold_loc is not None, "oracle arm needs gold localisation"
            cmds_a, steps_a, hit_a, loc = [], 0, False, gold_loc
            rec.stage_a, rec.stage_a_status = gold_loc, "oracle"
        _, cmds_b, steps_b, hit_b = agent_run(
            STAGE_B_PROMPT.format(location_json=json.dumps(loc), **fmt), box)
        cmds, steps, hit = cmds_a + cmds_b, steps_a + steps_b, hit_a or hit_b

    rec.commands, rec.steps, rec.max_steps_hit = cmds, steps, hit
    rec.patch = box.collect_patch()
    return rec


def _stock_patch_prompt(row: dict) -> str:
    # Load upstream's own prompt so single_sb differs from `stock` ONLY by the sandbox.
    from jinja2 import Template  # upstream prompt lives in smolagents/prompts/patch.j2
    import importlib.resources as r

    src = (r.files("smolagents") / "prompts" / "patch.j2").read_text()
    return Template(src).render(work_dir=row["work_dir"], bug_description=row["bug_description"],
                                sanitizer_report=row["sanitizer_report"])


# --------------------------------------------------------------------------- #
# glue: smolagents on the host, tools bridged into the container
# --------------------------------------------------------------------------- #
def make_smolagents_runner(model_id: str, agent_type: str = "ToolCallingAgent",
                           max_steps: int = 30, temperature: float = 0.0):
    """Return an `agent_run` for run_instance(). Untested against a live model."""
    from smolagents import CodeAgent, LiteLLMModel, Tool, ToolCallingAgent

    def agent_run(prompt: str, box):
        log: list[str] = []

        class ContainerCmd(Tool):
            name = "cmd"
            description = "Run a bash command inside the sandbox container (no network)."
            inputs = {"command": {"type": "string", "description": "bash command"}}
            output_type = "string"

            def forward(self, command: str) -> str:
                log.append(command)
                code, out = box.exec(command, timeout=300)
                return f"[exit {code}]\n{out[-8000:]}"

        model = LiteLLMModel(model_id=model_id, temperature=temperature)  # key from HOST env
        cls = ToolCallingAgent if agent_type == "ToolCallingAgent" else CodeAgent
        agent = cls(tools=[ContainerCmd()], model=model, max_steps=max_steps)
        try:
            final = str(agent.run(prompt))
        except Exception as e:  # max-steps / provider errors surface here
            final = f"__error__: {e}"
        steps = len(getattr(agent, "memory", None).steps) if getattr(agent, "memory", None) else len(log)
        return final, log, steps, steps >= max_steps

    return agent_run


class SandboxedContainerLike:  # structural type for tests
    work_dir: str
    def exec(self, command: str, timeout: int = 120, workdir: Optional[str] = None): ...
    def collect_patch(self) -> str: ...

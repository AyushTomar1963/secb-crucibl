from secb_strict.dual_runner import parse_stage_a, run_instance

ROW = dict(instance_id="x.cve-1", work_dir="/src/x", bug_description="bug", sanitizer_report="asan")


class FakeBox:
    def __init__(self): self.calls = []
    def exec(self, cmd, timeout=120, workdir=None): self.calls.append(cmd); return 0, ""
    def collect_patch(self): return "diff --git a/f b/f\n"


def test_parse_stage_a():
    ok, why = parse_stage_a('noise {"file":"a.c","symbol":"f","start_line":"3","end_line":9} tail')
    assert why == "ok" and ok["start_line"] == 3
    assert parse_stage_a("no json here")[1] == "no_json"
    assert parse_stage_a('{"file":"a.c"}')[1].startswith("missing_keys")
    assert parse_stage_a('{"file":"a","symbol":"s","start_line":"x","end_line":2}')[1] == "non_int_lines"


def test_two_stage_resets_between_stages_and_feeds_loc_to_b():
    prompts = []
    def agent(prompt, box):
        prompts.append(prompt)
        if len(prompts) == 1:
            return '{"file":"a.c","symbol":"f","start_line":1,"end_line":5}', ["grep f"], 3, False
        return "done", ["secb build", "secb repro"], 4, False

    box = FakeBox()
    rec = run_instance(ROW, "two_stage", 0, agent, box)
    assert rec.stage_a_status == "ok" and rec.steps == 7
    assert '"symbol": "f"' in prompts[1]                       # Stage B got Stage A's answer
    assert any("git checkout -q -- ." in c for c in box.calls)  # Stage A edits discarded
    assert rec.patch.startswith("diff")


def test_two_stage_bad_json_still_runs_stage_b_and_records_status():
    agent = lambda p, b: ("I could not decide", [], 1, False)
    rec = run_instance(ROW, "two_stage", 0, agent, FakeBox())
    assert rec.stage_a is None and rec.stage_a_status == "no_json"


def test_oracle_arm_skips_stage_a():
    n = []
    gold = {"file": "a.c", "symbol": "f", "start_line": 1, "end_line": 5}
    rec = run_instance(ROW, "two_stage_orc", 0, lambda p, b: (n.append(p) or ("", [], 1, False)), FakeBox(), gold_loc=gold)
    assert len(n) == 1 and rec.stage_a_status == "oracle"
